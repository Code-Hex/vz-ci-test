import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

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
    def netdump_settings(self):
        from recovery_netdump_settings import NetdumpSettings
        return NetdumpSettings('8.8.8.8', '192.168.64.1', 10248, 'vz1234567890abcd')

    def test_netdump_rejects_untyped_settings(self):
        original = plistlib.dumps({'Kernel Flags': '-v'})
        for settings in ({}, False, '203.0.113.7'):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                core.stage_content(original, 0x22040, netdump_settings=settings)

    def test_netdump_derivation_preserves_format_and_other_fields(self):
        settings = self.netdump_settings()
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            for original_flags in ('', '-v alpha=1 alpha=1'):
                with self.subTest(fmt=fmt, original_flags=original_flags):
                    original = plistlib.dumps({'Kernel Flags': original_flags, 'other': 'preserved'}, fmt=fmt)
                    staged = core.stage_content(original, 0x22040, netdump_settings=settings)
                    self.assertEqual(staged.startswith(b'bplist00'), fmt == plistlib.FMT_BINARY)
                    expected = (original_flags + ' ' if original_flags else '') + (
                        'debug=0x22040 _panicd_ip=8.8.8.8 _router_ip=192.168.64.1 '
                        'panicd_port=10248 _panicd_corename=vz1234567890abcd')
                    self.assertEqual(plistlib.loads(staged), {'Kernel Flags': expected, 'other': 'preserved'})

    def test_netdump_settings_and_mask_are_exclusive(self):
        original = plistlib.dumps({'Kernel Flags': '-v'})
        settings = self.netdump_settings()
        for mask, value, nvram in ((0x22040, None, None), (0x2000, settings, None),
                                   (0x102000, settings, None), (0x22040, settings, 0),
                                   (True, settings, None), ('0x22040', settings, None)):
            with self.subTest(mask=mask, settings=value, nvram=nvram), self.assertRaises(ValueError):
                core.stage_content(original, mask, netdump_settings=value, nvram_paniclog=nvram)

    def test_existing_netdump_flags_never_stage(self):
        settings = self.netdump_settings()
        for key in ('_panicd_ip', '_router_ip', 'panicd_port', '_panicd_corename'):
            for flag in (key + '=old', '-' + key + '=old', '--' + key, key + ' =old',
                         key + '=old ' + key + '=other'):
                with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmp:
                    data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
                    original = plistlib.dumps({'Kernel Flags': flag})
                    data.write_bytes(original); preboot.write_bytes(original)
                    with self.assertRaises(ValueError):
                        core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                         debug_mask=0x22040, netdump_settings=settings)
                    self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))
                    self.assertEqual(list(directory.iterdir()), [])

    def test_netdump_two_files_finish_and_receipt_replay(self):
        settings = self.netdump_settings()
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
                original = plistlib.dumps({'Kernel Flags': '-v', 'other': 'not-public'}, fmt=fmt)
                data.write_bytes(original); preboot.write_bytes(original)
                for path in (data, preboot): os.utime(path, ns=(1_700_000_000_000_000_000, 1_700_000_001_000_000_000))
                before = {path: core.snapshot(path) for path in (data, preboot)}
                fact = core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                        debug_mask=0x22040, netdump_settings=settings)
                self.assertEqual(fact, {'data': 'staged', 'preboot': 'staged', 'metadata_preserved': True})
                manifest = json.loads((directory / 'bootplist-manifest.json').read_text())
                self.assertEqual(manifest['netdump_settings'], settings.record())
                result = core.finish_files(directory, marker, data, preboot,
                                           'BBBBBBBB-2222-2222-2222-222222222222', 0x22040, save, sync)
                self.assertTrue(result['bootplist_restored'])
                self.assertEqual(result['active_bootargs_status'], 'observed_debug')
                for path in (data, preboot):
                    self.assertEqual(path.read_bytes(), original)
                    after = core.snapshot(path)
                    for key in ('dev', 'ino', 'uid', 'gid', 'mode', 'flags', 'mtime_ns', 'xattr_count', 'xattr_sha256'):
                        self.assertEqual(after[key], before[path][key])
                self.assertNotIn('8.8.8.8', json.dumps(result))
                self.assertEqual(core.finish_files(directory, marker, data, preboot,
                                                   'BBBBBBBB-2222-2222-2222-222222222222', None, save, sync), result)

    def test_netdump_manifest_tampering_cannot_authorize_restore(self):
        settings = self.netdump_settings()
        for mutation in ('missing', 'none', 'extra', 'missing_key', 'wrong_type', 'port_bool', 'receiver', 'router', 'port', 'corename', 'legacy_mask', 'nvram'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                 debug_mask=0x22040, netdump_settings=settings)
                before = data.read_bytes(), preboot.read_bytes()
                path = directory / 'bootplist-manifest.json'
                manifest = json.loads(path.read_text())
                if mutation == 'missing': del manifest['netdump_settings']
                elif mutation == 'none': manifest['netdump_settings'] = None
                elif mutation == 'extra': manifest['netdump_settings']['extra'] = 'unowned'
                elif mutation == 'missing_key': del manifest['netdump_settings']['port']
                elif mutation == 'wrong_type': manifest['netdump_settings'] = []
                elif mutation == 'port_bool': manifest['netdump_settings']['port'] = True
                elif mutation == 'legacy_mask': manifest['debug_mask'] = 0x2000
                elif mutation == 'nvram': manifest['nvram_paniclog'] = 0
                else:
                    key, value = {'receiver': ('receiver_ipv4', '1.1.1.1'), 'router': ('router_ipv4', '192.168.64.2'),
                                  'port': ('port', 10249), 'corename': ('corename', 'vzother')}[mutation]
                    manifest['netdump_settings'][key] = value
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    core.finish_files(directory, marker, data, preboot,
                                      'BBBBBBBB-2222-2222-2222-222222222222', 0x22040, save, sync)
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), before)
                self.assertFalse((directory / 'bootplist-observation.json').exists())

    def test_netdump_definite_second_failure_rolls_back_and_uncertain_does_not(self):
        settings = self.netdump_settings()
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
                def writer(path, expected, content):
                    if path == preboot:
                        if uncertain: raise core.WriteUncertain()
                        raise ValueError('definite_rejection')
                    return core.write_if_expected(path, expected, content)
                with self.assertRaises(core.WriteUncertain if uncertain else ValueError):
                    core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(), writer=writer,
                                     boot_uuid=lambda: marker['baseline'], debug_mask=0x22040, netdump_settings=settings)
                self.assertEqual(preboot.read_bytes(), original)
                self.assertEqual(data.read_bytes() == original, not uncertain)
                self.assertFalse((directory / 'bootplist-stage-complete.json').exists())

    def test_netdump_finish_checks_active_owned_tokens_without_blocking_restore(self):
        settings = self.netdump_settings()
        valid = '-v debug=0x22040 ' + ' '.join(settings.tokens())
        for active, status in ((valid, 'observed_debug'),
                               (valid.replace('debug=0x22040', 'debug=0x2000'), 'observed_no_debug'),
                               (valid.replace(' _panicd_ip=8.8.8.8', ''), 'invalid'),
                               (valid.replace('_router_ip=192.168.64.1', '_router_ip=192.168.64.2'), 'invalid'),
                               (valid + ' panicd_port=10248', 'invalid'),
                               (valid.replace('panicd_port=', '--panicd_port='), 'invalid')):
            with self.subTest(active=active), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                 debug_mask=0x22040, netdump_settings=settings)
                with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                     patch.object(core.boot.MacPlatform, 'active', return_value=active.encode()):
                    result = core.finish(directory, marker, save, sync,
                                         current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222')
                self.assertTrue(result['bootplist_restored'])
                self.assertEqual(result['active_bootargs_status'], status)
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))
                if status == 'invalid': self.assertIsNone(result['active_debug_mask'])

    def test_nvram_off_derivation_adds_only_fixed_token(self):
        original = plistlib.dumps({'Kernel Flags': '-v', 'other': 'preserved'}, fmt=plistlib.FMT_BINARY)
        default = core.stage_content(original, 0x102000)
        self.assertEqual(core.stage_content(original, 0x102000, nvram_paniclog=None), default)
        staged = core.stage_content(original, 0x102000, nvram_paniclog=0)
        self.assertTrue(staged.startswith(b'bplist00'))
        self.assertEqual(plistlib.loads(staged), {'Kernel Flags': '-v debug=0x102000 nvram_paniclog=0', 'other': 'preserved'})
        empty = plistlib.dumps({'Kernel Flags': ''})
        self.assertEqual(core.flags(core.stage_content(empty, 0x102000, nvram_paniclog=0), allow_debug=True),
                         'debug=0x102000 nvram_paniclog=0')

    def test_nvram_off_rejects_overrides_and_invalid_modes(self):
        for token in ('nvram_paniclog=1', 'nvram_paniclog=0', '-nvram_paniclog=1',
                      '--nvram_paniclog', 'nvram_paniclog =0', 'nvram_paniclog=bad\t-v'):
            with self.subTest(token=token):
                original = plistlib.dumps({'Kernel Flags': token})
                with self.assertRaises(ValueError):
                    core.stage_content(original, 0x102000, nvram_paniclog=0)
        original = plistlib.dumps({'Kernel Flags': 'nvram_paniclog=1'})
        self.assertEqual(core.flags(core.stage_content(original, 0x102000), allow_debug=True),
                         'nvram_paniclog=1 debug=0x102000')
        for mode in (False, True, '0', 1, -1, []):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                core.stage_content(plistlib.dumps({'Kernel Flags': '-v'}), 0x102000, nvram_paniclog=mode)
        with self.assertRaises(ValueError):
            core.stage_content(plistlib.dumps({'Kernel Flags': '-v'}), 0x2000, nvram_paniclog=0)

    def test_nvram_off_restores_both_original_files_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            os.utime(data, ns=(1_700_000_000_000_000_000, 1_700_000_001_000_000_000))
            os.utime(preboot, ns=(1_700_000_002_000_000_000, 1_700_000_003_000_000_000))
            before = {path: core.snapshot(path) for path in (data, preboot)}
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                             debug_mask=0x102000, nvram_paniclog=0)
            self.assertEqual(json.loads((directory / 'bootplist-manifest.json').read_text())['nvram_paniclog'], 0)
            for path in (data, preboot):
                self.assertEqual(core.flags(path.read_bytes(), allow_debug=True), '-v debug=0x102000 nvram_paniclog=0')
            result = core.finish_files(directory, marker, data, preboot,
                                       'BBBBBBBB-2222-2222-2222-222222222222', 0x102000, save, sync)
            self.assertTrue(result['bootplist_restored'])
            for path in (data, preboot):
                self.assertEqual(path.read_bytes(), original)
                after = core.snapshot(path)
                for key in ('uid', 'gid', 'mode', 'flags', 'mtime_ns', 'xattr_count', 'xattr_sha256'):
                    self.assertEqual(after[key], before[path][key])
            self.assertEqual(result['bootplist_restore'], {name: {'bytes': True, 'metadata': True, 'timestamps': True}
                                                           for name in ('data', 'preboot')})

    def test_nvram_off_manifest_tampering_does_not_write(self):
        for mode in (None, False, True, '0', 1, 'missing', 'extra'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, _original, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                 debug_mask=0x102000, nvram_paniclog=0)
                before = data.read_bytes(), preboot.read_bytes()
                path = directory / 'bootplist-manifest.json'
                manifest = json.loads(path.read_text())
                if mode == 'missing': del manifest['nvram_paniclog']
                elif mode == 'extra': manifest['extra'] = 'unowned'
                else: manifest['nvram_paniclog'] = mode
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    core.finish_files(directory, marker, data, preboot,
                                      'BBBBBBBB-2222-2222-2222-222222222222', 0x102000, save, sync)
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), before)

    def test_invalid_nvram_mode_or_existing_policy_never_stages(self):
        for mode, original_flags in ((False, '-v'), ('0', '-v'), (0, '-v --nvram_paniclog=1')):
            with self.subTest(mode=mode, original_flags=original_flags), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, _original, marker = self.fixture(Path(tmp).resolve())
                original = plistlib.dumps({'Kernel Flags': original_flags})
                data.write_bytes(original); preboot.write_bytes(original)
                with self.assertRaises(ValueError):
                    core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                     debug_mask=0x102000, nvram_paniclog=mode)
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))
                self.assertEqual(list(directory.iterdir()), [])

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
            self.assertIsNone(json.loads((directory / 'bootplist-manifest.json').read_text())['nvram_paniclog'])
            self.assertIsNone(json.loads((directory / 'bootplist-manifest.json').read_text())['netdump_settings'])
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

    def test_followup_mask_is_saved_and_verified_before_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(), debug_mask=0x102000)
            self.assertEqual(core.flags(data.read_bytes(), allow_debug=True), '-v debug=0x102000')
            result = core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', 0x102000, save, sync)
            self.assertEqual(result['active_bootargs_status'], 'observed_debug')
            self.assertTrue(result['bootplist_restored'])
            self.assertEqual(data.read_bytes(), original)
            self.assertEqual(preboot.read_bytes(), original)

    def test_mask_change_in_manifest_prevents_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, _original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(), debug_mask=0x102000)
            before = data.read_bytes(), preboot.read_bytes()
            path = directory / 'bootplist-manifest.json'
            manifest = json.loads(path.read_text()); manifest['debug_mask'] = 0x2000
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                core.finish_files(directory, marker, data, preboot, 'BBBBBBBB-2222-2222-2222-222222222222', 0x102000, save, sync)
            self.assertEqual((data.read_bytes(), preboot.read_bytes()), before)

    def test_unsupported_mask_does_not_modify_files(self):
        for mask in (True, None, '0x102000', 1):
            with self.subTest(mask=mask), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
                with self.assertRaises(ValueError):
                    core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(), debug_mask=mask)
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))
                self.assertFalse((directory / 'bootplist-manifest.json').exists())

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
