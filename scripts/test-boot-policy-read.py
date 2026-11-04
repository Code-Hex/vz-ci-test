import importlib.util
import json
import os
import pathlib
import plistlib
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('inventory', pathlib.Path(__file__).with_name('boot-policy-read.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Inventory(unittest.TestCase):
    def test_redaction_and_referenced_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            launches, helpers = root / 'launch', root / 'helpers'
            launches.mkdir(); helpers.mkdir()
            (helpers / 'agent').write_text('nvram boot-args=secret debug=0x2000')
            (launches / 'job.plist').write_bytes(plistlib.dumps({'ProgramArguments': ['/bin/sh', str(helpers / 'agent'), 'do-not-publish']}))
            result = p.inventory([launches], [helpers], time.monotonic() + 5)
            serialized = json.dumps(result)
            self.assertNotIn('do-not-publish', serialized)
            self.assertNotIn('secret', serialized)
            self.assertNotIn(tmp, serialized)
            helper = next(x for x in result['records'] if x['basename'] == 'agent')
            self.assertTrue(helper['boot_args_literal'])
            self.assertTrue(helper['nvram_literal'])
            self.assertTrue(helper['debug_literal'])
            self.assertEqual(len(helper['sha256']), 64)

    def test_invalid_plist_and_file_count_are_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            (root / 'bad.plist').write_bytes(b'not-a-plist')
            for i in range(129):
                (root / f'{i:03}').write_bytes(b'x')
            result = p.inventory([root], [], time.monotonic() + 5)
            self.assertIn('file_limit', result['incomplete'])
            self.assertLessEqual(result['files_considered'], 128)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            (root / 'bad.plist').write_bytes(b'not-a-plist')
            result = p.inventory([root], [], time.monotonic() + 5)
            self.assertIn('invalid_plist', result['incomplete'])

    def test_byte_limit_and_external_program_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            launches, outside = root / 'launches', root / 'outside'
            launches.mkdir(); outside.mkdir()
            (outside / 'do-not-read').write_text('nvram boot-args')
            (launches / 'job.plist').write_bytes(plistlib.dumps({'Program': str(outside / 'do-not-read')}))
            result = p.inventory([launches], [root / 'allowed'], time.monotonic() + 5)
            self.assertEqual(result['candidate_count'], 0)
            self.assertNotIn('do-not-read', json.dumps(result))
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            for i in range(5): (root / str(i)).write_bytes(b'x' * (1024 * 1024))
            result = p.inventory([root], [], time.monotonic() + 5)
            self.assertIn('byte_limit', result['incomplete'])
            self.assertLessEqual(result['bytes_read'], 4 * 1024 * 1024)

    def test_argument_limit_does_not_claim_complete_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            (root / 'job.plist').write_bytes(plistlib.dumps({'ProgramArguments': ['/bin/sh'] * 129}))
            result = p.inventory([root], [], time.monotonic() + 5)
            self.assertIn('argument_limit', result['incomplete'])
            self.assertFalse(result['complete'])

    def test_referenced_fifo_does_not_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            launches, helpers = root / 'launches', root / 'helpers'
            launches.mkdir(); helpers.mkdir()
            fifo = helpers / 'pipe'
            os.mkfifo(fifo)
            (launches / 'job.plist').write_bytes(plistlib.dumps({'Program': str(fifo)}))
            result = p.inventory([launches], [helpers], time.monotonic() + 2)
            self.assertIn('not_regular', result['incomplete'])

    def test_symlink_and_oversize_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            (root / 'large').write_bytes(b'x' * (1024 * 1024 + 1))
            (root / 'link').symlink_to(root / 'large')
            result = p.inventory([root], [], time.monotonic() + 5)
            self.assertIn('oversize', result['incomplete'])
            self.assertIn('symlink', result['incomplete'])
            self.assertEqual(result['records'], [])

if __name__ == '__main__':
    unittest.main()
