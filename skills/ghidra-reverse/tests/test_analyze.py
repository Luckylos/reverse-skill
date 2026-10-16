"""Offline contract tests. Generated binaries are analyzed, never executed."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SKILL = Path(__file__).resolve().parents[1]
SCRIPT = SKILL / 'scripts/analyze.py'
SCRATCH = Path(os.environ.get('GHIDRA_TEST_SCRATCH', str(SKILL.parents[2])))


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
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
if mode.startswith('early-'):
    mode = mode.removeprefix('early-')
    child = subprocess.Popen([sys.executable, '-c',
        'import os, pathlib, signal, sys, time; '
        'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
        'pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)',
        str(out / 'child.pid')])
    deadline = time.monotonic() + 5
    while not (out / 'child.pid').exists():
        if child.poll() is not None or time.monotonic() >= deadline:
            child.kill()
            child.wait()
            raise RuntimeError('child did not become ready')
        time.sleep(0.01)
if mode == 'fail': sys.exit(9)
if mode == 'timeout':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
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
''')
        self.fake.chmod(0o700)

    def run_cli(self, *extra, mode='valid', auth=True, launcher=None):
        env = os.environ.copy()
        env['FAKE_MODE'] = mode
        args = [sys.executable, str(SCRIPT), str(self.sample), '--output', str(self.out),
                '--launcher', str(launcher or self.fake)]
        if auth:
            args.append('--authorized')
        return subprocess.run(args + list(extra), env=env, capture_output=True, text=True, timeout=240)

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
                try:
                    result = self.run_cli(mode='early-' + mode)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    pid = int((self.out / 'child.pid').read_text())
                    for _ in range(40):
                        status = Path('/proc') / str(pid) / 'stat'
                        try:
                            if status.read_text().split()[2] == 'Z':
                                break
                        except FileNotFoundError:
                            break
                        time.sleep(0.05)
                    else:
                        self.fail('launcher descendant remains running after early ' + mode)
                finally:
                    # RED must not leak the controlled orphan when cleanup is missing.
                    pid_file = self.out / 'child.pid'
                    if pid_file.exists():
                        try:
                            os.kill(int(pid_file.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_timeout_kills_child_process_group(self):
        result = self.run_cli('--timeout', '2', mode='timeout')
        self.assertEqual(result.returncode, 124, result.stderr)
        pid = int((self.out / 'child.pid').read_text())
        for _ in range(40):
            status = Path('/proc') / str(pid) / 'stat'
            if not status.exists() or status.read_text().split()[2] == 'Z':
                break
            time.sleep(0.05)
        else:
            self.fail('launcher descendant remains running')
        self.assertTrue((self.out / 'console.log').exists())

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
