import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest

import recovery_bootplist as core


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


class Transaction(unittest.TestCase):
    def fixture(self, root):
        original = plistlib.dumps({'Kernel Flags': '-v', 'other': 'not-public'})
        data, preboot, directory = root / 'data', root / 'preboot', root / 'private'
        directory.mkdir(); data.write_bytes(original); preboot.write_bytes(original)
        marker = {'binding': '123/1/' + 'a' * 40, 'nonce': 'b' * 64, 'baseline': 'AAAAAAAA-1111-1111-1111-111111111111', 'source_identity': 'c' * 64}
        return data, preboot, directory, original, marker

    def test_two_files_staged_then_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            fact = core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            self.assertEqual(fact, {'data': 'staged', 'preboot': 'staged', 'metadata_preserved': True})
            self.assertEqual(core.flags(data.read_bytes(), allow_debug=True), '-v debug=0x2000')
            result = core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', 0x2000, save, sync)
            self.assertEqual(result['bootplist_file_states'], {'data': 'staged', 'preboot': 'staged'})
            self.assertTrue(result['bootplist_restored'])
            self.assertEqual(result['active_bootargs_status'], 'observed_debug')
            self.assertEqual(data.read_bytes(), original); self.assertEqual(preboot.read_bytes(), original)
            self.assertNotIn('not-public', json.dumps(result))
            again = core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', None, save, sync)
            self.assertEqual(again, result)

    def test_other_debug_mask_is_observed_no_debug(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            result = core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', 1, save, sync)
            self.assertEqual((result['active_debug_mask'], result['active_bootargs_status']), (1, 'observed_no_debug'))

    def test_unavailable_is_distinct_from_no_debug(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            result = core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', None, save, sync, active_status='unavailable')
            self.assertEqual(result['active_bootargs_status'], 'unavailable')

    def test_foreign_change_before_stage_complete_is_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            def writer(path, expected, content):
                current = core.write_if_expected(path, expected, content)
                if path == preboot: data.write_bytes(b'foreign')
                return current
            with self.assertRaises(core.WriteUncertain):
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(), writer=writer, boot_uuid=lambda: marker['baseline'])
            self.assertFalse((directory / 'bootplist-stage-complete.json').exists())
            self.assertEqual(data.read_bytes(), b'foreign')

    def test_foreign_state_is_recorded_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            preboot.write_bytes(b'foreign')
            result = core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', None, save, sync)
            self.assertEqual(result['bootplist_file_states']['preboot'], 'other')
            self.assertFalse(result['bootplist_restored'])
            self.assertEqual(result['active_bootargs_status'], 'observed_no_debug')
            self.assertEqual(preboot.read_bytes(), b'foreign')
            self.assertNotEqual(data.read_bytes(), original)

    def test_corrupt_done_record_blocks_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            (directory / 'data.stage-done.json').write_text('{')
            with self.assertRaises(core.WriteUncertain): core.rollback_files(directory, marker, data, preboot, save, sync, current_boot_uuid=marker['baseline'])
            self.assertNotEqual(data.read_bytes(), original)

    def test_empty_done_metadata_and_missing_done_do_not_authorize_finish(self):
        for mode in ('empty', 'missing'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
                done = directory / 'data.stage-done.json'
                if mode == 'empty': done.write_text(json.dumps({'marker': marker, 'meta': {}}))
                else:
                    done.unlink()
                    (directory / 'data.stage-pending.json').unlink()
                with self.assertRaises(core.WriteUncertain):
                    core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', None, save, sync)
                self.assertNotEqual(data.read_bytes(), original)

    def test_rollback_rejects_new_boot_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            staged = (data.read_bytes(), preboot.read_bytes())
            with self.assertRaisesRegex(ValueError, 'rollback_boot_mismatch'):
                core.rollback_files(directory, marker, data, preboot, save, sync, current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222')
            self.assertEqual((data.read_bytes(), preboot.read_bytes()), staged)
            self.assertNotEqual(staged[0], original)

    def test_definite_second_failure_rolls_back_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            def writer(path, expected, content):
                if path == preboot: raise ValueError('definite_rejection')
                return core.write_if_expected(path, expected, content)
            with self.assertRaises(ValueError):
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(), writer=writer, boot_uuid=lambda: marker['baseline'])
            self.assertEqual(data.read_bytes(), original)
            self.assertEqual(preboot.read_bytes(), original)

    def test_uncertain_second_write_does_not_restore_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            def writer(path, expected, content):
                if path == preboot:
                    def partial(fd, data, offset):
                        os.pwrite(fd, data[:1], offset)
                        raise OSError('partial')
                    return core.write_if_expected(path, expected, content, writer=partial)
                return core.write_if_expected(path, expected, content)
            with self.assertRaises(core.WriteUncertain):
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(), writer=writer, boot_uuid=lambda: marker['baseline'])
            self.assertNotEqual(data.read_bytes(), original)
            with self.assertRaises(core.WriteUncertain): core.rollback_files(directory, marker, data, preboot, save, sync, current_boot_uuid=marker['baseline'])

    def test_pending_without_done_blocks_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            (directory / 'data.stage-done.json').unlink()
            with self.assertRaises(core.WriteUncertain): core.rollback_files(directory, marker, data, preboot, save, sync, current_boot_uuid=marker['baseline'])
            self.assertNotEqual(data.read_bytes(), original)

if __name__ == '__main__': unittest.main()
