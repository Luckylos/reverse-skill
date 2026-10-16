"""Offline contract tests. Generated binaries are analyzed, never executed."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import uuid

SKILL = Path(__file__).resolve().parents[1]
SCRIPT = SKILL / 'scripts/analyze.py'
SCRATCH = Path(os.environ.get('GHIDRA_TEST_SCRATCH', str(SKILL.parents[2])))
PROC = Path('/proc')
# Above Linux PID_MAX_LIMIT (2**22): never a live process even if a mock were bypassed.
FAKE_PID = 2 ** 22 + 4242


def pidfd_exited(fd):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    return bool(poller.poll(0))


def kill_verified_child(pid_file, marker, proc=PROC):
    """SIGKILL the controlled fixture child only through a pidfd proven to carry marker.

    The pidfd pins one process. If it is live both before and after reading /proc/<pid>/cmdline,
    that PID named the pinned process throughout, so the marker belongs to it. Gone, zombie,
    reused, unreadable, or exited-during-check processes are never signalled; there is no
    numeric kill fallback. Returns True only when the owned child was signalled.
    """
    try:
        pid = int(pid_file.read_text())
        fd = os.pidfd_open(pid)
    except (OSError, ValueError):
        return False
    try:
        if pidfd_exited(fd):
            return False
        try:
            argv = (proc / str(pid) / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            return False
        if marker is None or marker.encode() not in argv or pidfd_exited(fd):
            return False
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        return True
    finally:
        os.close(fd)


def child_gone(pid_file, attempts=40):
    """Read-only /proc polling: True once the recorded child is absent or a zombie."""
    pid = int(pid_file.read_text())
    for _ in range(attempts):
        try:
            if (PROC / str(pid) / 'stat').read_text().split()[2] == 'Z':
                return True
        except FileNotFoundError:
            return True
        time.sleep(0.05)
    return False


def load_analyze():
    spec = importlib.util.spec_from_file_location('ghidra_analyze_under_test', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def fixture_report(source, config):
    return {'schema_version': 1, 'complete': True,
            'sample_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'ghidra_version': 'fixture', 'program': source.name, 'language': 'x86:LE:64:default',
            'analysis_timed_out': False, 'unmatched_selectors': [],
            'selectors': config['selectors'], 'limits': config['limits'],
            'functions_truncated': False, 'functions': [
                {'name': 'target', 'address': '00101000', 'status': 'ok', 'c': 'int target(void) { return 1; }',
                 'xrefs_truncated': False, 'xrefs': []}]}


class FakePoll:
    """select.poll stand-in replaying pidfd readiness: True means POLLIN (process exited)."""
    def __init__(self, script):
        self.script = script
        self.fd = None

    def register(self, fd, events):
        assert events & select.POLLIN
        self.fd = fd

    def poll(self, timeout=None):
        return [(self.fd, select.POLLIN)] if self.script.pop(0) else []


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        # Cleanup of controlled fixture children needs a stable pidfd identity; fail, never skip.
        self.assertTrue(PROC.joinpath('self/cmdline').is_file() and hasattr(os, 'pidfd_open')
                        and hasattr(signal, 'pidfd_send_signal') and hasattr(select, 'poll'),
                        'Linux /proc, os.pidfd_open, signal.pidfd_send_signal and select.poll required')
        os.close(os.pidfd_open(os.getpid()))
        self.marker = None
        self.temp = tempfile.TemporaryDirectory(prefix='contract ', dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sample = self.root / "sample ; ' owned.bin"
        self.sample.write_bytes(b'owned offline fixture')
        self.out = self.root / "output ; ' private"
        self.fake = self.root / 'fake launcher'
        self.fake.write_text('#!' + sys.executable + '\n' + r'''
import hashlib, json, os, pathlib, subprocess, sys, time
args = sys.argv[1:]
out = pathlib.Path(args[0]).parent
(out / 'argv.json').write_text(json.dumps(args))
mode = os.environ.get('FAKE_MODE', 'valid')
marker = os.environ['FAKE_MARKER']
if mode.startswith('early-'):
    mode = mode.removeprefix('early-')
    child = subprocess.Popen([sys.executable, '-c',
        'import os, pathlib, signal, sys, time; '
        'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
        'pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)',
        str(out / 'child.pid'), marker])
    deadline = time.monotonic() + 5
    while not (out / 'child.pid').exists():
        if child.poll() is not None or time.monotonic() >= deadline:
            child.kill()
            child.wait()
            raise RuntimeError('child did not become ready')
        time.sleep(0.01)
if mode == 'fail': sys.exit(9)
if mode == 'timeout':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)', marker])
    (out / 'child.pid').write_text(str(child.pid))
    time.sleep(60)
if mode == 'missing': sys.exit(0)
if mode == 'malformed':
    (out / 'analysis.json').write_text('{')
    sys.exit(0)
source = pathlib.Path(args[args.index('-import') + 1])
config = json.loads(pathlib.Path(args[args.index('-postScript') + 2]).read_text())
report = {'schema_version': 1, 'complete': True,
 'sample_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
 'ghidra_version': 'fixture', 'program': source.name, 'language': 'x86:LE:64:default',
 'analysis_timed_out': False, 'unmatched_selectors': [],
 'selectors': config['selectors'], 'limits': config['limits'],
 'functions_truncated': False, 'functions': [
 {'name': 'target', 'address': '00101000', 'status': 'ok', 'c': 'int target(void) { return 1; }',
 'xrefs_truncated': False, 'xrefs': [{'from_address': '00102000', 'type': 'UNCONDITIONAL_CALL', 'caller': 'main'}]}]}
if mode == 'partial': report['complete'] = False
if mode == 'empty': report['functions'] = []
if mode == 'timedout': report['analysis_timed_out'] = True
if mode == 'failed': report['functions'][0]['status'] = 'failed'
if mode == 'digest': report['sample_sha256'] = '0' * 64
if mode == 'unmatched': report['unmatched_selectors'] = ['absent']
if mode == 'badxref': report['functions'][0]['xrefs'] *= 101
if mode == 'missingcaller': del report['functions'][0]['xrefs'][0]['caller']
if mode == 'badversion': report['schema_version'] = True
if mode == 'badidentity': report['language'] = ''
if mode == 'noc': del report['functions'][0]['c']
if mode == 'oversizedc': report['functions'][0]['c'] = 'x' * 100001
if mode == 'noxrefmarker': del report['functions'][0]['xrefs_truncated']
if mode == 'mutate': source.write_bytes(b'changed')
(out / 'analysis.json').write_text(json.dumps(report))
if mode == 'validfail': sys.exit(9)
''')
        self.fake.chmod(0o700)

    def run_cli(self, *extra, mode='valid', auth=True, launcher=None, preexec_fn=None):
        env = os.environ.copy()
        env['FAKE_MODE'] = mode
        # Unique argv marker for the controlled fixture child; cleanup verifies it before signalling.
        self.marker = env['FAKE_MARKER'] = 'ghidra-fixture-child-' + uuid.uuid4().hex
        args = [sys.executable, str(SCRIPT), str(self.sample), '--output', str(self.out),
                '--launcher', str(launcher or self.fake)]
        if auth:
            args.append('--authorized')
        return subprocess.run(args + list(extra), env=env, capture_output=True, text=True, timeout=240,
                              preexec_fn=preexec_fn)

    def test_safe_argv_private_output_and_unchanged_input(self):
        before = self.sample.read_bytes()
        result = self.run_cli('--function', 'target')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sample.read_bytes(), before)
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o700)
        args = json.loads((self.out / 'argv.json').read_text())
        self.assertEqual(args[args.index('-import') + 1], str(self.sample))
        self.assertIn('-readOnly', args)
        self.assertNotIn('-process', args)
        self.assertNotIn('-overwrite', args)
        self.assertEqual(args[args.index('-scriptPath') + 1], str(SKILL / 'scripts'))
        self.assertTrue((self.out / 'console.log').exists())
        self.assertNotIn('return 1', result.stdout)

    def test_no_authorization_has_no_output(self):
        self.assertNotEqual(self.run_cli(auth=False).returncode, 0)
        self.assertFalse(self.out.exists())

    def test_invalid_inputs_limits_and_ambiguous_flags_have_no_output(self):
        cases = [('--max-functions', '0'), ('--max-functions', '1001'),
                 ('--timeout', '-1'), ('--timeout', 'nan'), ('--max-xrefs', '0'),
                 ('--analysis-timeout', '0'), ('--function-timeout', '0'),
                 ('--function=-log',), ('--function', 'target', '--function', 'target'),
                 ('--max-functions', '1', '--max-functions', '2'), ('--out', 'elsewhere'),
                 ('--authorized',)]
        for flags in cases:
            with self.subTest(flags=flags):
                self.assertNotEqual(self.run_cli(*flags).returncode, 0)
                self.assertFalse(self.out.exists())
        self.sample.unlink()
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertFalse(self.out.exists())
        self.sample.mkdir()
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertFalse(self.out.exists())
        self.sample.rmdir()
        self.sample.write_bytes(b'x')
        self.sample.chmod(0)
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_existing_output_and_dangling_symlink_are_rejected(self):
        self.out.mkdir()
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertEqual(list(self.out.iterdir()), [])
        self.out.rmdir()
        self.out.symlink_to(self.root / 'absent')
        self.assertNotEqual(self.run_cli().returncode, 0)
        self.assertTrue(self.out.is_symlink())

    def test_launcher_and_invalid_reports_fail(self):
        for mode in ['fail', 'missing', 'malformed', 'partial', 'empty', 'timedout',
                     'failed', 'digest', 'unmatched', 'badxref', 'missingcaller', 'badversion',
                     'badidentity', 'noc', 'oversizedc', 'noxrefmarker', 'mutate']:
            with self.subTest(mode=mode):
                self.out = self.root / ('out-' + mode)
                result = self.run_cli(mode=mode)
                self.assertNotEqual(result.returncode, 0, mode)
        self.out = self.root / 'bad-launcher'
        self.assertNotEqual(self.run_cli(launcher=self.root / 'missing').returncode, 0)
        self.assertFalse(self.out.exists())

    def test_selector_must_be_present_in_successful_report(self):
        result = self.run_cli('--function', 'absent')
        self.assertNotEqual(result.returncode, 0)

    def test_launcher_discovery_environment_path_and_verified_home(self):
        env = os.environ.copy()
        env.pop('GHIDRA_HEADLESS', None)
        env.pop('GHIDRA_HOME', None)
        env['FAKE_MODE'] = 'valid'
        env['FAKE_MARKER'] = 'ghidra-fixture-child-' + uuid.uuid4().hex
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'ghidra-headless').symlink_to(self.fake)
        env['PATH'] = str(bin_dir)
        home = self.root / 'Ghidra fixture home'
        (home / 'Ghidra').mkdir(parents=True)
        (home / 'Ghidra/application.properties').write_text('application.name=Ghidra\n')
        (home / 'support').mkdir()
        (home / 'support/analyzeHeadless').symlink_to(self.fake)
        for strategy in ('environment', 'path', 'home', 'invalid-home'):
            self.out = self.root / strategy
            current = env.copy()
            if strategy == 'environment':
                current['GHIDRA_HEADLESS'] = str(self.fake)
                current['PATH'] = ''
            elif strategy in ('home', 'invalid-home'):
                current['PATH'] = ''
                current['GHIDRA_HOME'] = str(home if strategy == 'home' else self.root)
            result = subprocess.run([sys.executable, str(SCRIPT), str(self.sample), '--output',
                                     str(self.out), '--authorized'], env=current,
                                    capture_output=True, text=True, timeout=10)
            with self.subTest(strategy=strategy):
                if strategy == 'invalid-home':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(self.out.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_early_launcher_exit_kills_child_process_group(self):
        for mode, expected in [('valid', 0), ('fail', 1), ('malformed', 1), ('mutate', 1)]:
            with self.subTest(mode=mode):
                self.out = self.root / ('early-' + mode)
                gone = False
                try:
                    result = self.run_cli(mode='early-' + mode)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    pid = int((self.out / 'child.pid').read_text())
                    for _ in range(40):
                        status = Path('/proc') / str(pid) / 'stat'
                        try:
                            if status.read_text().split()[2] == 'Z':
                                gone = True
                                break
                        except FileNotFoundError:
                            gone = True
                            break
                        time.sleep(0.05)
                    else:
                        self.fail('launcher descendant remains running after early ' + mode)
                finally:
                    # RED must not leak the controlled orphan when cleanup is missing; once it is
                    # confirmed gone its number is never signalled again.
                    if not gone:
                        kill_verified_child(self.out / 'child.pid', self.marker)

    def test_timeout_kills_child_process_group(self):
        gone = False
        try:
            result = self.run_cli('--timeout', '2', mode='timeout')
            self.assertEqual(result.returncode, 124, result.stderr)
            pid = int((self.out / 'child.pid').read_text())
            for _ in range(40):
                status = Path('/proc') / str(pid) / 'stat'
                if not status.exists() or status.read_text().split()[2] == 'Z':
                    gone = True
                    break
                time.sleep(0.05)
            else:
                self.fail('launcher descendant remains running')
            self.assertTrue((self.out / 'console.log').exists())
        finally:
            if not gone:
                kill_verified_child(self.out / 'child.pid', self.marker)

    def test_inherited_ignored_sigchld_keeps_launcher_identity(self):
        # SIG_IGN for SIGCHLD auto-reaps the launcher: its status is lost and its PID/PGID may be reused.
        def ignore_sigchld():
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        for mode, expected in [('valid', 0), ('validfail', 1)]:
            with self.subTest(mode=mode):
                self.out = self.root / ('ignored-sigchld-' + mode)
                gone = False
                try:
                    result = self.run_cli(mode='early-' + mode, preexec_fn=ignore_sigchld)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected:
                        self.assertIn('launcher failed (9)', result.stderr)
                    gone = child_gone(self.out / 'child.pid')
                    self.assertTrue(gone, 'launcher descendant remains running with inherited SIG_IGN')
                finally:
                    if not gone:
                        kill_verified_child(self.out / 'child.pid', self.marker)

    def test_launcher_never_reaped_before_group_kill_nor_signalled_after(self):
        analyze = load_analyze()
        expectations = {'valid': 0, 'fail': 1, 'missing': 1, 'mutate': 1, 'timeout': 124,
                        'interrupt': 130, 'observe-error': RuntimeError}
        for scenario, expected in expectations.items():
            with self.subTest(scenario=scenario):
                self.sample.write_bytes(b'owned offline fixture')
                self.out = self.root / ('order-' + scenario)
                events, kills = [], []
                exit_code = {'valid': 0, 'missing': 0, 'mutate': 0, 'fail': 9}.get(scenario, -9)
                sample = self.sample

                def observe(reaping):
                    events.append('reap' if reaping else 'observe')
                    if scenario == 'interrupt':
                        raise KeyboardInterrupt
                    if scenario == 'observe-error':
                        raise RuntimeError('observation failed')
                    return scenario != 'timeout'

                class Launcher:
                    pid = FAKE_PID
                    returncode = None

                    def wait(self, timeout=None):
                        if timeout is not None and not observe(True):
                            raise subprocess.TimeoutExpired('fake launcher', timeout)
                        if timeout is None:
                            events.append('reap')
                        self.returncode = exit_code
                        return exit_code

                    def poll(self):
                        events.append('reap')
                        self.returncode = exit_code
                        return exit_code

                def popen(command, **kwargs):
                    self.assertIs(kwargs.get('shell'), False)
                    self.assertIs(kwargs.get('start_new_session'), True)
                    events.append('spawn')
                    config_path = Path(command[command.index('-postScript') + 2])
                    config = json.loads(config_path.read_text())
                    if scenario == 'valid':
                        Path(config['output']).write_text(json.dumps(fixture_report(sample, config)))
                    if scenario == 'mutate':
                        sample.write_bytes(b'changed')
                    return Launcher()

                def waitid(idtype, pid, options):
                    self.assertEqual((idtype, pid), (os.P_PID, FAKE_PID))
                    required = os.WEXITED | os.WNOWAIT | os.WNOHANG
                    if not observe(options & required != required):
                        return None
                    return types.SimpleNamespace(si_pid=FAKE_PID, si_code=os.CLD_EXITED, si_status=exit_code)

                def waitpid(pid, options):
                    events.append('reap')
                    return pid, (exit_code & 0xff) << 8

                def killpg(pgid, sig):
                    events.append('killpg')
                    kills.append((pgid, sig))

                def set_handler(signum, handler):
                    if signum == signal.SIGCHLD:
                        events.append('sigchld-default' if handler == signal.SIG_DFL else 'sigchld-other')
                    return signal.SIG_DFL

                argv = ['analyze.py', str(self.sample), '--output', str(self.out), '--authorized',
                        '--launcher', str(self.fake), '--timeout', '1']
                stderr = io.StringIO()
                with mock.patch.object(sys, 'argv', argv), \
                        mock.patch.object(subprocess, 'Popen', popen), \
                        mock.patch.object(os, 'waitid', waitid), \
                        mock.patch.object(os, 'waitpid', waitpid), \
                        mock.patch.object(os, 'killpg', killpg), \
                        mock.patch.object(os, 'kill', side_effect=AssertionError('numeric kill')), \
                        mock.patch.object(signal, 'signal', set_handler), \
                        contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    if expected is RuntimeError:
                        with self.assertRaises(RuntimeError):
                            analyze.main()
                    else:
                        self.assertEqual(analyze.main(), expected, stderr.getvalue())
                self.assertEqual(kills, [(FAKE_PID, signal.SIGKILL)], events)
                self.assertEqual(events.count('reap'), 1, events)
                self.assertLess(events.index('killpg'), events.index('reap'), events)
                self.assertIn('sigchld-default', events)
                self.assertLess(events.index('sigchld-default'), events.index('spawn'), events)
                self.assertTrue((self.out / 'console.log').exists())

    def test_missing_nonreaping_wait_support_fails_before_output(self):
        analyze = load_analyze()
        for name in ('waitid', 'WNOWAIT', 'WNOHANG'):
            with self.subTest(name=name):
                self.out = self.root / ('unsupported-' + name)
                argv = ['analyze.py', str(self.sample), '--output', str(self.out), '--authorized',
                        '--launcher', str(self.fake)]
                stderr = io.StringIO()
                saved = getattr(os, name)
                delattr(os, name)
                try:
                    with mock.patch.object(sys, 'argv', argv), \
                            mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')), \
                            contextlib.redirect_stderr(stderr):
                        code = analyze.main()
                finally:
                    setattr(os, name, saved)
                self.assertEqual(code, 1)
                self.assertIn('waitid', stderr.getvalue())
                self.assertFalse(self.out.exists())

    def test_fixture_cleanup_signals_only_verified_owned_child_via_pidfd(self):
        marker = 'ghidra-fixture-child-' + uuid.uuid4().hex
        proc = self.root / 'fake proc'
        (proc / str(FAKE_PID)).mkdir(parents=True)
        cmdline = proc / str(FAKE_PID) / 'cmdline'
        mine = b'\0'.join([b'python3', b'-c', b'sleep', b'child.pid', marker.encode()]) + b'\0'
        other = mine.replace(marker.encode(), b'ghidra-fixture-child-' + uuid.uuid4().hex.encode())
        # name: (pid file text, pidfd_open outcome, pidfd exited per poll, cmdline bytes or None, signalled)
        cases = {
            'gone': (str(FAKE_PID), ProcessLookupError(), [], mine, False),
            'malformed-pid-file': ('12ab', 777, [], mine, False),
            'zombie': (str(FAKE_PID), 777, [True], b'', False),
            'reused-other-marker': (str(FAKE_PID), 777, [False], other, False),
            'unreadable': (str(FAKE_PID), 777, [False], None, False),
            'exited-during-check': (str(FAKE_PID), 777, [False, True], mine, False),
            'owned': (str(FAKE_PID), 777, [False, False], mine, True),
        }
        for name, (pid_text, opened, exits, content, signalled) in cases.items():
            with self.subTest(case=name):
                pid_file = self.root / 'child.pid'
                pid_file.write_text(pid_text)
                if content is None:
                    cmdline.unlink(missing_ok=True)
                else:
                    cmdline.write_bytes(content)
                polls = list(exits)
                pidfd_open = mock.Mock(side_effect=[opened])
                with mock.patch.object(os, 'pidfd_open', pidfd_open), \
                        mock.patch.object(select, 'poll', lambda: FakePoll(polls)), \
                        mock.patch.object(os, 'close') as close, \
                        mock.patch.object(os, 'kill') as kill, \
                        mock.patch.object(os, 'killpg') as killpg, \
                        mock.patch.object(signal, 'pidfd_send_signal') as send:
                    result = kill_verified_child(pid_file, marker, proc=proc)
                kill.assert_not_called()
                killpg.assert_not_called()
                self.assertIs(result, signalled)
                if signalled:
                    send.assert_called_once_with(777, signal.SIGKILL)
                else:
                    send.assert_not_called()
                if pidfd_open.called and not isinstance(opened, Exception):
                    close.assert_called_once_with(777)
                else:
                    close.assert_not_called()
                self.assertEqual(polls, [], 'unexpected pidfd liveness poll count')

    def test_real_decompilation_selection_and_xref_bounds(self):
        self.assertTrue(SCRIPT.exists(), 'wrapper not implemented')
        compiler = shutil.which('cc') or shutil.which('gcc')
        self.assertIsNotNone(compiler, 'C compiler required, not skipped')
        source = self.root / 'owned.c'
        source.write_text('__attribute__((noinline)) int target(int x) { return x * 3 + 7; }\n'
                          '__attribute__((noinline)) int caller(int x) { return target(x) + target(x+1); }\n'
                          'int main(void) { return caller(2); }\n')
        self.sample = self.root / 'owned ELF'
        subprocess.run([compiler, '-O0', '-g', '-fno-inline', '-o', str(self.sample), str(source)], check=True)
        digest = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        real = os.environ.get('GHIDRA_HEADLESS')
        self.assertTrue(real, 'real Ghidra launcher required')
        self.out = self.root / 'real output with spaces'
        home, tmp = self.root / 'java home', self.root / 'java tmp'
        cache = self.root / 'ghidra cache'
        home.mkdir(); tmp.mkdir(); cache.mkdir()
        wrapper = self.root / 'isolated real launcher'
        # JVM parses JAVA_TOOL_OPTIONS quoting itself; do not use shell quoting here.
        wrapper.write_text('#!' + sys.executable + '\nimport os, sys\n'
                           + 'os.environ["JAVA_TOOL_OPTIONS"] = ' + repr(f'-Duser.home="{home}" -Djava.io.tmpdir="{tmp}" -Dapplication.cachedir="{cache}" -Dapplication.tempdir="{tmp}"') + '\n'
                           + 'os.execv(' + repr(real) + ', [' + repr(real) + '] + sys.argv[1:])\n')
        wrapper.chmod(0o700)
        result = self.run_cli('--function', 'target', launcher=wrapper)
        self.assertEqual(result.returncode, 0, result.stderr + '\n' + (self.out / 'console.log').read_text()[-6000:])
        report = json.loads((self.out / 'analysis.json').read_text())
        self.assertEqual(report['sample_sha256'], digest)
        self.assertEqual(hashlib.sha256(self.sample.read_bytes()).hexdigest(), digest)
        self.assertEqual(len(report['functions']), 1)
        function = report['functions'][0]
        self.assertEqual(function['name'], 'target')
        self.assertIn('7', function['c'])
        self.assertEqual(function['status'], 'ok')
        self.assertLessEqual(len(function['xrefs']), 100)
        calls = [xref for xref in function['xrefs'] if xref['caller'] == 'caller']
        self.assertTrue(calls, 'known caller xref missing')
        self.assertTrue(any('CALL' in xref['type'] for xref in calls))
        address = function['address']
        self.out = self.root / 'address selection'
        result = self.run_cli('--function', address, '--max-xrefs', '1', launcher=wrapper)
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = json.loads((self.out / 'analysis.json').read_text())['functions'][0]
        self.assertEqual(selected['name'], 'target')
        self.assertEqual(len(selected['xrefs']), 1)
        self.assertTrue(selected['xrefs_truncated'])
        self.out = self.root / 'unmatched selection'
        self.assertNotEqual(self.run_cli('--function', 'not_a_real_function', launcher=wrapper).returncode, 0)
        self.assertEqual(json.loads((self.out / 'analysis.json').read_text())['unmatched_selectors'], ['not_a_real_function'])
        self.out = self.root / 'bounded functions'
        self.assertEqual(self.run_cli('--max-functions', '1', launcher=wrapper).returncode, 0)
        bounded = json.loads((self.out / 'analysis.json').read_text())
        self.assertEqual(len(bounded['functions']), 1)
        self.assertTrue(bounded['functions_truncated'])


if __name__ == '__main__':
    unittest.main()
