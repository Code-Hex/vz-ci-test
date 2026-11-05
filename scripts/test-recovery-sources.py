import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import recovery_sources as sources


NAMES = ('recovery.py', 'recovery_reports.py', 'recovery_bootargs.py', 'recovery_bootplist.py',
         'recovery_nvram_panic.py', 'recovery_panic_control.py', 'panic-source-preflight.py',
         'recovery_arrival.py', 'kdp_registry.py', 'recovery_netdump_settings.py', 'recovery_sources.py',
         'recovery_netdump.py', 'kdp_udp_preflight.py', 'kdp_crashdump.py', 'recovery_netdump_capture.py')


class Sources(unittest.TestCase):
    def fixture(self, root, main_name='reboot-recovery.py'):
        root.mkdir()
        main = root / main_name
        for index, target in enumerate(NAMES):
            (main if target == 'recovery.py' else root / target).write_bytes(
                ('value = ' + repr(target + ':' + str(index)) + '\n').encode())
        return main

    def test_copy_table_is_immutable_complete_and_has_fixed_targets(self):
        main = Path('/private/checkout/reboot-recovery.py')
        table = sources.source_files(main)
        self.assertIs(type(table), tuple)
        self.assertEqual(tuple(target for target, _ in table), NAMES)
        self.assertEqual(len({target for target, _ in table}), len(NAMES))
        self.assertEqual(table[0], ('recovery.py', main))
        for entry in table:
            self.assertIs(type(entry), tuple)
            target, path = entry
            self.assertIsInstance(path, Path)
            self.assertEqual(path, main if target == 'recovery.py' else main.parent / target)
        with self.assertRaises(TypeError): table[0] = table[1]

    def test_identity_is_the_fixed_order_nul_join_of_all_copied_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = self.fixture(Path(tmp) / 'checkout')
            content = [(main if target == 'recovery.py' else main.parent / target).read_bytes() for target in NAMES]
            self.assertEqual(sources.identity(main), hashlib.sha256(b'\0'.join(content)).hexdigest())

    def test_every_copied_dependency_including_self_changes_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = self.fixture(Path(tmp) / 'checkout')
            original = sources.identity(main)
            for target, path in sources.source_files(main):
                with self.subTest(target=target):
                    content = path.read_bytes()
                    path.write_bytes(content + b'changed\n')
                    self.assertNotEqual(sources.identity(main), original)
                    path.write_bytes(content)
                    self.assertEqual(sources.identity(main), original)

    def test_checkout_and_private_main_names_have_equal_identity_after_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = self.fixture(root / 'checkout')
            private = root / 'private'
            private.mkdir()
            for target, path in sources.source_files(checkout):
                (private / target).write_bytes(path.read_bytes())
            self.assertEqual(sources.identity(checkout), sources.identity(private / 'recovery.py'))
            self.assertEqual(tuple(target for target, _ in sources.source_files(private / 'recovery.py')), NAMES)

    def test_missing_dependency_never_produces_a_partial_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = self.fixture(Path(tmp) / 'checkout')
            (main.parent / 'recovery_sources.py').unlink()
            with self.assertRaises(FileNotFoundError): sources.identity(main)

    def test_real_copied_main_imports_in_clean_child_with_the_same_identity(self):
        checkout_main = Path(__file__).with_name('reboot-recovery.py').resolve()
        expected = sources.identity(checkout_main)
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp)
            for target, source in sources.source_files(checkout_main):
                (private / target).write_bytes(source.read_bytes())
            program = ('import runpy, sys; from pathlib import Path; '
                       'main = Path(sys.argv[1]); sys.path.insert(0, str(main.parent)); '
                       'module = runpy.run_path(str(main), run_name="copied_module"); '
                       'print(module["debug_source_identity"]())')
            result = subprocess.run([sys.executable, '-c', program, str(private / 'recovery.py')],
                                    env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                                    cwd=private, capture_output=True, text=True, timeout=10, check=True)
            self.assertEqual(result.stderr, '')
            self.assertEqual(result.stdout, expected + '\n')

    def test_nul_separator_preserves_file_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = self.fixture(Path(tmp) / 'checkout')
            dependency = main.parent / 'recovery_reports.py'
            main.write_bytes(b'a'); dependency.write_bytes(b'bc')
            first = sources.identity(main)
            main.write_bytes(b'ab'); dependency.write_bytes(b'c')
            self.assertNotEqual(sources.identity(main), first)


if __name__ == '__main__':
    unittest.main()
