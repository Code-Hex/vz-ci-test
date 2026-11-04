import importlib.util
import pathlib
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('experiment', pathlib.Path(__file__).with_name('nvram-staged-sync.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class NativeResult(unittest.TestCase):
    def test_single_sync_return_is_only_public_fact(self):
        output = b'{"event":"guard","status":"passed"}\n{"event":"sync","status":"returned","ioreturn":3758097084,"durability_verified":false}\n'
        self.assertEqual(p.parse_native(output, 70), {'status': 'returned', 'exit': 70, 'ioreturn': 3758097084})
        self.assertEqual(p.parse_native(output.replace(b'3758097084', b'0'), 0), {'status': 'returned', 'exit': 0, 'ioreturn': 0})

    def test_private_backup_is_exclusive_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = pathlib.Path(folder)
            path = directory / 'backup'
            p.private_write(path, b'synthetic-secret')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError): p.private_write(path, b'overwrite')
            link = directory / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError): p.private_write(link, b'overwrite')
            self.assertEqual(path.read_bytes(), b'synthetic-secret')

    def test_checkpoint_failure_is_a_fact_not_an_exception(self):
        with tempfile.TemporaryDirectory() as folder:
            result = {}
            path = pathlib.Path(folder) / 'missing' / 'result.json'
            self.assertFalse(p.checkpoint(result, 'restore_start', lambda: path.write_text('x')))
            self.assertEqual(result, {'phase': 'restore_start', 'artifact_write_failed': True})

    def test_invalid_or_ambiguous_output_is_not_a_result(self):
        event = b'{"event":"sync","status":"returned","ioreturn":0}\n'
        for data in (event + event, b'{"event":"sync","status":"returned","ioreturn":true}', b'not-json'):
            self.assertEqual(p.parse_native(data, 0)['status'], 'invalid')
        self.assertEqual(p.parse_native(b'{"event":"sync","status":"options_unavailable"}', 69)['status'], 'options_unavailable')

if __name__ == '__main__':
    unittest.main()
