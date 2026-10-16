#!/usr/bin/env python3
"""Authorized, bounded POSIX Ghidra import into a fresh disposable project."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        seen = getattr(namespace, '_seen', set())
        if self.dest in seen:
            parser.error('duplicate option: ' + option_string)
        seen.add(self.dest)
        namespace._seen = seen
        setattr(namespace, self.dest, True if self.nargs == 0 else values)


def bounded(maximum):
    def parse(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError('expected a positive integer')
        if not 1 <= number <= maximum:
            raise argparse.ArgumentTypeError(f'expected integer in 1..{maximum}')
        return number
    return parse


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def launcher_path(explicit):
    candidate = explicit or os.environ.get('GHIDRA_HEADLESS')
    if not candidate:
        candidate = shutil.which('ghidra-headless') or shutil.which('analyzeHeadless')
    if not candidate and os.environ.get('GHIDRA_HOME'):
        home = Path(os.environ['GHIDRA_HOME']).expanduser().resolve()
        if not (home / 'Ghidra/application.properties').is_file():
            raise ValueError('GHIDRA_HOME is not a Ghidra installation')
        candidate = str(home / 'support/analyzeHeadless')
    if not candidate:
        raise ValueError('no official headless launcher found; configure --launcher')
    found = shutil.which(candidate)
    path = Path(found or candidate).expanduser().absolute()
    if path.suffix.lower() in ('.bat', '.cmd', '.exe'):
        raise ValueError('native Windows launchers are unsupported')
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('launcher is not an executable regular file')
    return str(path)


def require_nonreaping_wait():
    if not all(hasattr(os, name) for name in ('waitid', 'P_PID', 'WEXITED', 'WNOWAIT', 'WNOHANG')):
        raise ValueError('os.waitid with WEXITED/WNOWAIT/WNOHANG is required for safe '
                         'process-group cleanup; unsupported platform')


def wait_unreaped(pid, deadline):
    """Return True once pid has exited, False at the deadline; never reaps it.

    The unreaped (zombie) leader keeps its PID, and thus its process-group ID, from being reused.
    """
    while True:
        if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def validate_report(path, expected_digest, config):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('report absent or too large')
    report = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(report, dict):
        raise ValueError('report must be an object')
    if (type(report.get('schema_version')) is not int or report['schema_version'] != 1
            or report.get('complete') is not True
            or report.get('analysis_timed_out') is not False
            or report.get('sample_sha256', '').lower() != expected_digest
            or report.get('unmatched_selectors') != []
            or report.get('selectors') != config['selectors']
            or report.get('limits') != config['limits']):
        raise ValueError('report incomplete, timed out, unmatched, or inconsistent')
    for key in ('ghidra_version', 'program', 'language'):
        if not isinstance(report.get(key), str) or not report[key].strip():
            raise ValueError('missing program identity')
    if type(report.get('functions_truncated')) is not bool:
        raise ValueError('missing function truncation marker')
    functions = report.get('functions')
    if not isinstance(functions, list) or not 1 <= len(functions) <= config['limits']['max_functions']:
        raise ValueError('empty or excessive function report')
    addresses = set()
    for function in functions:
        if not isinstance(function, dict):
            raise ValueError('invalid function object')
        for key in ('name', 'address', 'c'):
            if not isinstance(function.get(key), str) or not function[key].strip():
                raise ValueError('missing function result')
        if function.get('status') != 'ok' or len(function['c']) > 100000:
            raise ValueError('decompilation failed or exceeded output bound')
        if function['address'] in addresses:
            raise ValueError('duplicate function result')
        addresses.add(function['address'])
        if type(function.get('xrefs_truncated')) is not bool:
            raise ValueError('missing xref truncation marker')
        xrefs = function.get('xrefs')
        if not isinstance(xrefs, list) or len(xrefs) > config['limits']['max_xrefs']:
            raise ValueError('invalid xref bound')
        for xref in xrefs:
            if not isinstance(xref, dict) or any(not isinstance(xref.get(k), str) or not xref[k]
                                                   for k in ('from_address', 'type')):
                raise ValueError('invalid xref')
            if 'caller' not in xref or (xref['caller'] is not None and not isinstance(xref['caller'], str)):
                raise ValueError('invalid caller')
    # Selected results must account for every requested name/address, not just claim a match.
    for selector in config['selectors']:
        matches = [f for f in functions if f['name'] == selector or
                   f['address'].lower().removeprefix('0x').lstrip('0') == selector.lower().removeprefix('0x').lstrip('0')]
        if len(matches) != 1:
            raise ValueError('selector not uniquely represented: ' + selector)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('input')
    parser.add_argument('--output', required=True, action=Once)
    parser.add_argument('--authorized', action=Once, nargs=0, default=False,
                        help='confirm approved input/action/output scope')
    parser.add_argument('--launcher', action=Once)
    parser.add_argument('--function', action='append', default=[])
    for flag, default, ceiling in [('max-functions', 20, 1000), ('max-xrefs', 100, 10000),
                                    ('analysis-timeout', 120, 3600), ('function-timeout', 30, 300),
                                    ('timeout', 300, 7200)]:
        parser.add_argument('--' + flag, type=bounded(ceiling), default=default, action=Once)
    args = parser.parse_args()
    try:
        if os.name != 'posix':
            raise ValueError('only POSIX launchers are supported; native Windows is unsupported')
        require_nonreaping_wait()
        if not args.authorized:
            raise ValueError('explicit input/action/output authorization required (--authorized)')
        source = Path(args.input).expanduser().absolute()
        info = source.stat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o444 or not os.access(source, os.R_OK):
            raise ValueError('input must be a readable regular file')
        source = source.resolve()
        output = Path(args.output).expanduser().absolute()
        if os.path.lexists(output):
            raise ValueError('output must be new (symlinks also rejected)')
        if not output.parent.is_dir():
            raise ValueError('output parent must already exist')
        selectors = args.function
        if (len(set(selectors)) != len(selectors) or len(selectors) > args.max_functions
                or any(not s or s.startswith('-') or len(s) > 512 or any(ord(c) < 32 for c in s) for s in selectors)):
            raise ValueError('invalid, duplicate, or excessive function selectors')
        launcher = launcher_path(args.launcher)
        resources = Path(__file__).resolve().parent
        if not (resources / 'ExportAnalysis.java').is_file():
            raise ValueError('missing bundled Java exporter')
        expected_digest = digest(source)
        limits = {key: getattr(args, key) for key in
                  ('max_functions', 'max_xrefs', 'analysis_timeout', 'function_timeout', 'timeout')}
        config = {'selectors': selectors, 'limits': limits, 'output': str(output / 'analysis.json')}
        output.mkdir(mode=0o700)
        project = output / 'project'
        project.mkdir(mode=0o700)
        config_path = output / 'request.json'
        config_path.write_text(json.dumps(config), encoding='utf-8')
        command = [launcher, str(project), 'Analysis', '-import', str(source), '-readOnly',
                   '-analysisTimeoutPerFile', str(args.analysis_timeout), '-scriptPath', str(resources),
                   '-scriptlog', str(output / 'script.log'), '-log', str(output / 'headless.log'),
                   '-postScript', 'ExportAnalysis.java', str(config_path)]
        # An inherited SIG_IGN would auto-reap the launcher, losing its status and PID/PGID ownership.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        with (output / 'console.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       shell=False, start_new_session=True)
            deadline = time.monotonic() + args.timeout
            interrupted = None
            pinned = True
            try:
                try:
                    if not wait_unreaped(process.pid, deadline):
                        interrupted = 124
                except KeyboardInterrupt:
                    interrupted = 130
                except ChildProcessError:
                    pinned = False  # reaped elsewhere: the number no longer identifies our group
                    raise ValueError('launcher was reaped externally; process group not signalled')
            finally:
                # The launcher may exit before its same-group descendants. It is still unreaped
                # here, so its PID/PGID cannot have been reused; reap exactly once afterwards and
                # never signal that number again.
                if pinned:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                code = process.wait()
            if interrupted:
                print('Analysis interrupted/timed out; process group killed; diagnostics retained.', file=sys.stderr)
                return interrupted
        if digest(source) != expected_digest:
            raise ValueError('input changed during analysis')
        if code != 0:
            raise ValueError(f'launcher failed ({code}); diagnostics retained')
        report = validate_report(output / 'analysis.json', expected_digest, config)
        truncated = report['functions_truncated'] or any(f['xrefs_truncated'] for f in report['functions'])
        print(f"Exported {len(report['functions'])} functions; scoped/bounded output; truncation={truncated}.")
        return 0
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        print('Analysis failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
