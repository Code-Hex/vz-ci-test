import importlib.util
from pathlib import Path
import unittest
import tempfile
import sys

spec = importlib.util.spec_from_file_location('preflight', Path(__file__).with_name('panic-source-preflight.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Preflight(unittest.TestCase):
    def test_exact_probe_list(self):
        name = 'vz_nonce_' + 'a' * 64
        line = f'   ID PROVIDER MODULE FUNCTION NAME\n  123 pid456 helper {name} entry\n'
        self.assertEqual(p.parse_probe_list(line, 456, name), 'matched')
        self.assertEqual(p.parse_probe_list(line, 457, name), 'missing')
        self.assertEqual(p.parse_probe_list(line + line, 456, name), 'ambiguous')
        self.assertEqual(p.parse_probe_list(line.replace(' entry', ' return'), 456, name), 'missing')

    def test_helper_name_and_no_untrusted_source(self):
        source = p.helper_source('a' * 64)
        self.assertIn('vz_nonce_' + 'a' * 64, source)
        self.assertIn('read(STDIN_FILENO', source)
        with self.assertRaises(ValueError): p.helper_source('a;evil')

    def test_script_actions(self):
        safe = p.probe_script('a' * 64, False)
        compile_only = p.probe_script('a' * 64, True)
        self.assertNotIn('panic()', safe)
        self.assertIn('panic()', compile_only)
        self.assertIn(':entry', safe)
        self.assertIn('READY', safe)
        self.assertIn('HIT', safe)

    def test_command_bounds_both_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code, out = p.command([sys.executable, '-c', 'import sys; print("ok"); print("private", file=sys.stderr)'], root, 'small')
            self.assertEqual((code, out), (0, b'ok\n'))
            self.assertEqual((root / 'small.stderr').read_bytes(), b'private\n')
            with self.assertRaisesRegex(ValueError, 'output_limit'):
                p.command([sys.executable, '-c', 'import sys; sys.stderr.write("x" * 100000)'], root, 'large')
            self.assertLessEqual((root / 'large.stderr').stat().st_size, p.LIMIT)

    def test_events_only_exact_once_in_order(self):
        name = 'vz_nonce_' + 'a' * 64
        hit = f'HIT pid456:helper:{name}:entry\n'.encode()
        self.assertTrue(p.events_valid(b'READY\n' + hit, 456, name))
        for data in (hit + b'READY\n', b'READY\n' + hit + hit, b'READY\n',
                     b'READY\n' + hit + b'extra\n', b'READY\n' + hit.replace(b'pid456', b'pid457'),
                     b'READY\n' + hit.replace(name.encode(), b'other')):
            self.assertFalse(p.events_valid(data, 456, name))

if __name__ == '__main__': unittest.main()
