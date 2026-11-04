import importlib.util
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('preflight', Path(__file__).with_name('bootplist-preflight.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
G = 'AAAAAAAA-1111-1111-1111-111111111111'
S = 'BBBBBBBB-2222-2222-2222-222222222222'


class Preflight(unittest.TestCase):
    def test_group_and_system_uniqueness(self):
        info = {'APFSVolumeGroupID': G}
        groups = {'Containers': [{'VolumeGroups': [{'APFSVolumeGroupUUID': G, 'Volumes': [{'Role': 'System', 'DiskUUID': S}]}]}]}
        self.assertEqual(p.volume_ids(info, groups), (G, S))
        with self.assertRaises(ValueError): p.volume_ids(info, {'Containers': groups['Containers'] * 2})
        groups['Containers'][0]['VolumeGroups'][0]['Volumes'].append({'Role': 'System', 'DiskUUID': G})
        with self.assertRaises(ValueError): p.volume_ids(info, groups)

    def test_flags_validate_and_preserve_unrelated_values(self):
        raw = plistlib.dumps({'Kernel Flags': '-v', 'secret': 'do-not-print'})
        staged = p.stage_content(raw)
        self.assertEqual(plistlib.loads(staged)['Kernel Flags'], '-v debug=0x2000')
        self.assertEqual(plistlib.loads(staged)['secret'], 'do-not-print')
        with self.assertRaises(ValueError): p.stage_content(plistlib.dumps({'Kernel Flags': 'debug=0x4'}))
        with self.assertRaises(ValueError): p.stage_content(plistlib.dumps({'Kernel Flags': []}))

    def test_preboot_candidates_require_one_unique_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            first, second = root / 'one', root / 'two'
            first.write_bytes(b'a')
            self.assertEqual(p.select_preboot({first, first})[0], first)
            second.write_bytes(b'b')
            with self.assertRaises(ValueError): p.select_preboot({first, second})
            second.unlink(); second.symlink_to(first)
            with self.assertRaises(OSError): p.select_preboot({first, second})

    def test_slow_child_is_reaped_before_return(self):
        events = []
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.15)'])
        self.assertEqual(p.wait_for_update(child, events.append, 0.02), 'returned_zero_late')
        self.assertEqual(events, ['update_pending'])
        self.assertIsNotNone(child.poll())

    def test_error_reporting_is_filtered(self):
        self.assertEqual(p.error_fact(ValueError('secret payload')), {'error_kind': 'validation', 'reason': 'invalid'})
        self.assertEqual(p.error_fact(ValueError('flags_mismatch')), {'error_kind': 'validation', 'reason': 'flags_mismatch'})
        self.assertEqual(p.error_fact(PermissionError(13, 'secret path')), {'error_kind': 'os_error', 'errno': 13})
        self.assertEqual(p.update_error_fact(p.UpdateUncertain('nonzero', 3)), {'reason': 'nonzero', 'exit': 3})

    def test_nonzero_update_is_uncertain(self):
        child = subprocess.Popen([sys.executable, '-c', 'raise SystemExit(3)'])
        with self.assertRaises(p.UpdateUncertain): p.wait_for_update(child, lambda _phase: None, 2)
        self.assertEqual(child.returncode, 3)

    def test_metadata_only_foreign_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); path = root / 'boot.plist'
            path.write_bytes(b'original')
            before = p.snapshot(path)
            time.sleep(0.01)
            os.chmod(path, before['mode'] ^ 0o100)
            os.chmod(path, before['mode'])
            with self.assertRaises(ValueError): p.write_if_expected(path, before, b'staged')
            self.assertEqual(path.read_bytes(), b'original')

    def test_snapshot_restores_original_timestamps_after_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); path = root / 'boot.plist'
            path.write_bytes(b'original')
            before = p.snapshot(path)
            staged = p.write_if_expected(path, before, b'staged')
            restored = p.write_if_expected(path, staged, b'original')
            self.assertTrue(p.metadata_preserved(before, restored))
            self.assertTrue(p.restore_times(path, restored, before['atime_ns'], before['mtime_ns']))
            after = path.stat()
            self.assertEqual((after.st_atime_ns, after.st_mtime_ns), (before['atime_ns'], before['mtime_ns']))

    def test_xattrs_benign_flag_group_and_inode_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'file'
            path.write_bytes(b'fixture')
            subprocess.run(['/usr/bin/xattr', '-w', 'com.example.fixture', 'value', str(path)], check=True, capture_output=True)
            os.chflags(path, stat.UF_NODUMP)
            before = p.snapshot(path)
            staged = p.write_if_expected(path, before, b'changed')
            self.assertEqual(staged['ino'], before['ino'])
            self.assertEqual(staged['gid'], before['gid'])
            self.assertEqual(staged['flags'], before['flags'])
            self.assertEqual((staged['xattr_count'], staged['xattr_sha256']), (before['xattr_count'], before['xattr_sha256']))
            subprocess.run(['/usr/bin/xattr', '-w', 'com.example.fixture', 'foreign', str(path)], check=True, capture_output=True)
            with self.assertRaises(ValueError): p.write_if_expected(path, staged, b'original')

    def test_compressed_flags_or_attribute_are_rejected(self):
        checks = {'uid_root': True, 'mode_0644': True, 'nlink_one': True, 'write_blocking_flags_absent': True,
                  'compression_absent': True, 'xattrs_bounded': True, 'acl_empty': True, 'identity_stable': True}
        self.assertTrue(p.metadata_allowed({'checks': checks, 'observed': {'gid': 20, 'flags': 1}}))
        self.assertFalse(p.metadata_allowed({'checks': {**checks, 'compression_absent': False}, 'observed': {'gid': 20, 'flags': 32}}))

    def test_oversize_new_content_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'file'; path.write_bytes(b'original')
            before = p.snapshot(path)
            with self.assertRaises(ValueError): p.write_if_expected(path, before, b'x' * (1024 * 1024 + 1))
            self.assertEqual(path.read_bytes(), b'original')

    def test_partial_write_is_uncertain_and_never_self_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'file'; path.write_bytes(b'original')
            before = p.snapshot(path)
            def partial(fd, data, offset):
                os.pwrite(fd, data[:1], offset)
                raise OSError('simulated partial write')
            with self.assertRaises(p.WriteUncertain): p.write_if_expected(path, before, b'changed', writer=partial)
            self.assertNotEqual(path.read_bytes(), b'original')

    def test_no_symlink_or_foreign_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); path = root / 'boot.plist'
            old = b'original'; path.write_bytes(old); before = p.snapshot(path)
            staged = p.write_if_expected(path, before, b'staged')
            path.write_bytes(b'foreign')
            with self.assertRaises(ValueError): p.write_if_expected(path, staged, old)
            self.assertEqual(path.read_bytes(), b'foreign')
            (root / 'link').symlink_to(path)
            with self.assertRaises(OSError): p.snapshot(root / 'link')

if __name__ == '__main__': unittest.main()
