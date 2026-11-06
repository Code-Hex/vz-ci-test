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
    def test_bootmarker_derivation_and_old_manifest_variant(self):
        nonce='b'*64; original=plistlib.dumps({'Kernel Flags':'-v','other':'retained'})
        staged=core.stage_content(original,0x102000,boot_marker_nonce=nonce)
        self.assertEqual(plistlib.loads(staged),{'Kernel Flags':'-v debug=0x102000 vz_ci_nonce='+nonce,'other':'retained'})
        for value in (True,'B'*64,'b'*63,'b'*65):
            with self.subTest(value=value),self.assertRaises(ValueError): core.stage_content(original,0x102000,boot_marker_nonce=value)
        for flags in ('vz_ci_nonce=old','-vz_ci_nonce=old','--vz_ci_nonce','vz_ci_nonce =old'):
            with self.subTest(flags=flags),self.assertRaises(ValueError):
                core.stage_content(plistlib.dumps({'Kernel Flags':flags}),0x102000,boot_marker_nonce=nonce)
        with self.assertRaises(ValueError): core.stage_content(original,0x2000,boot_marker_nonce=nonce)
        with self.assertRaises(ValueError): core.stage_content(original,0x102000,boot_marker_nonce=nonce,nvram_paniclog=0)
        with tempfile.TemporaryDirectory() as tmp:
            data,preboot,directory,_,marker=self.fixture(Path(tmp).resolve())
            core.stage_files(directory,marker,data,preboot,save,sync,owner_uid=os.geteuid())
            self.assertNotIn('boot_marker_nonce',json.loads((directory/'bootplist-manifest.json').read_text()))

    def test_bootmarker_single_capture_restores_bytes_metadata_and_replays_without_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            data,preboot,directory,original,marker=self.fixture(Path(tmp).resolve());calls=[]
            before={p:core.snapshot(p) for p in (data,preboot)}
            baseline=core.boot.boot_argument_profile('-v')
            core.stage_files(directory,marker,data,preboot,save,sync,owner_uid=os.geteuid(),debug_mask=0x102000,boot_marker_nonce=marker['nonce'])
            self.assertEqual(json.loads((directory/'bootplist-manifest.json').read_text())['boot_marker_nonce'],marker['nonce'])
            raw=('-v debug=0x102000 vz_ci_nonce='+marker['nonce']+'\n').encode();actual=core.boot.capture
            def read(argv,limit,timeout):
                if argv!=['/usr/sbin/sysctl','-n','kern.bootargs']: return actual(argv,limit,timeout)
                self.assertEqual((argv,limit,timeout),(['/usr/sbin/sysctl','-n','kern.bootargs'],1025,8))
                self.assertEqual(core.flags(data.read_bytes(),allow_debug=True),raw[:-1].decode())
                calls.append(1)
                import sys
                return actual([sys.executable,'-c','import sys;sys.stdout.buffer.write('+repr(raw)+')'],limit,timeout)
            with patch.object(core,'_production_paths',return_value=(data,preboot)),patch.object(core.boot,'capture',read):
                first=core.finish(directory,marker,save,sync,current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',baseline_boot_argument_profile=baseline)
            self.assertTrue(first['bootplist_restored']);self.assertTrue(core.boot.bootmarker_proven(first['boot_marker_control'],marker['nonce'],baseline))
            for path in (data,preboot):
                self.assertEqual(path.read_bytes(),original)
                after=core.snapshot(path)
                for key in ('dev','ino','uid','gid','mode','flags','mtime_ns','xattr_count','xattr_sha256'):
                    self.assertEqual(after[key],before[path][key])
            with patch.object(core,'_production_paths',return_value=(data,preboot)),patch.object(core.boot,'capture',lambda argv,*a,**k: actual(argv,*a,**k) if argv!=['/usr/sbin/sysctl','-n','kern.bootargs'] else self.fail('repeat read')):
                self.assertEqual(core.finish(directory,marker,save,sync,current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',baseline_boot_argument_profile=baseline),first)
            self.assertEqual(calls,[1])

    def test_bootmarker_negative_and_capture_storage_failure_still_restore_and_never_recapture(self):
        for case in ('invalid','io','started_save','final_save','started_sync','final_sync'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                data,preboot,directory,original,marker=self.fixture(Path(tmp).resolve());calls=[];actual=core.boot.capture
                baseline=core.boot.boot_argument_profile('-v')
                core.stage_files(directory,marker,data,preboot,save,sync,owner_uid=os.geteuid(),debug_mask=0x102000,boot_marker_nonce=marker['nonce'])
                def read(argv,*args,**kwargs):
                    if argv!=['/usr/sbin/sysctl','-n','kern.bootargs']: return actual(argv,*args,**kwargs)
                    calls.append(1)
                    if case=='io': raise OSError('synthetic getter failure')
                    return b'-v debug=0x102000\n' if case=='invalid' else ('-v debug=0x102000 vz_ci_nonce='+marker['nonce']+'\n').encode()
                failures=[]
                def flush(path):
                    target='boot-marker-started.json' if case=='started_sync' else 'boot-marker-observation.json'
                    if case in ('started_sync','final_sync') and not failures and (path/target).exists():
                        failures.append(True); raise OSError('synthetic journal fsync failure')
                    sync(path)
                def store(path,raw):
                    if path.name=={'started_save':'boot-marker-started.json','final_save':'boot-marker-observation.json'}.get(case):
                        raise OSError('synthetic journal failure')
                    save(path,raw)
                with patch.object(core,'_production_paths',return_value=(data,preboot)),patch.object(core.boot,'capture',read):
                    first=core.finish(directory,marker,store,flush,current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',baseline_boot_argument_profile=baseline)
                self.assertTrue(first['bootplist_restored']);self.assertEqual((data.read_bytes(),preboot.read_bytes()),(original,original))
                expected={'invalid':'invalid','io':'unavailable','started_save':'uncertain','final_save':'uncertain','started_sync':'uncertain','final_sync':'uncertain'}[case]
                self.assertEqual(first['boot_marker_control'],{'status':expected})
                with patch.object(core,'_production_paths',return_value=(data,preboot)),patch.object(core.boot,'capture',lambda argv,*a,**k: actual(argv,*a,**k) if argv!=['/usr/sbin/sysctl','-n','kern.bootargs'] else self.fail('repeat read')):
                    again=core.finish(directory,marker,save,sync,current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',baseline_boot_argument_profile=baseline)
                self.assertEqual(again['boot_marker_control'],first['boot_marker_control'])
                self.assertEqual(len(calls),0 if case in ('started_save','started_sync') else 1)

    def test_bootmarker_manifest_and_scope_tampering_fail_closed(self):
        for mutation in ('nonce','none','extra','scope'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                data,preboot,directory,_,marker=self.fixture(Path(tmp).resolve())
                core.stage_files(directory,marker,data,preboot,save,sync,owner_uid=os.geteuid(),debug_mask=0x102000,boot_marker_nonce=marker['nonce'])
                path=directory/'bootplist-manifest.json';manifest=json.loads(path.read_text())
                if mutation=='nonce': manifest['boot_marker_nonce']='e'*64
                elif mutation=='none': manifest['boot_marker_nonce']=None
                elif mutation=='extra': manifest['extra']='private'
                else: manifest['marker']['nonce']='d'*64
                path.write_text(json.dumps(manifest));before=data.read_bytes(),preboot.read_bytes()
                with self.assertRaises(ValueError):
                    core.finish_files(directory,marker,data,preboot,'BBBBBBBB-2222-2222-2222-222222222222',0x102000,save,sync)
                self.assertEqual((data.read_bytes(),preboot.read_bytes()),before)

    def test_bootmarker_cached_facts_are_strict_and_never_recaptured(self):
        for mutation in ('extra','count_bool','scope','started_only','restored_without_new_journals','baseline'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                data,preboot,directory,_,marker=self.fixture(Path(tmp).resolve());baseline=core.boot.boot_argument_profile('-v');actual=core.boot.capture
                core.stage_files(directory,marker,data,preboot,save,sync,owner_uid=os.geteuid(),debug_mask=0x102000,boot_marker_nonce=marker['nonce'])
                raw=('-v debug=0x102000 vz_ci_nonce='+marker['nonce']+'\n').encode()
                def read(argv,*a,**k): return raw if argv==['/usr/sbin/sysctl','-n','kern.bootargs'] else actual(argv,*a,**k)
                with patch.object(core,'_production_paths',return_value=(data,preboot)),patch.object(core.boot,'capture',read):
                    first=core.finish(directory,marker,save,sync,current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',baseline_boot_argument_profile=baseline)
                self.assertEqual(first['boot_marker_control']['status'],'observed')
                path=directory/'boot-marker-observation.json';cache=json.loads(path.read_text())
                if mutation=='extra': cache['private']='unowned'
                elif mutation=='count_bool': cache['control']['active_byte_count']=True
                elif mutation=='scope': cache['scope']['current_boot_uuid']='CCCCCCCC-3333-3333-3333-333333333333'
                elif mutation=='baseline': baseline=core.boot.boot_argument_profile('-v other=1')
                if mutation in ('started_only','restored_without_new_journals'):
                    path.unlink()
                    if mutation=='restored_without_new_journals': (directory/'boot-marker-started.json').unlink()
                else: path.write_text(json.dumps(cache))
                def no_read(argv,*a,**k):
                    if argv==['/usr/sbin/sysctl','-n','kern.bootargs']: self.fail('bad cache caused recapture')
                    return actual(argv,*a,**k)
                with patch.object(core,'_production_paths',return_value=(data,preboot)),patch.object(core.boot,'capture',no_read):
                    again=core.finish(directory,marker,save,sync,current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',baseline_boot_argument_profile=baseline)
                self.assertTrue(again['bootplist_restored'])
                self.assertEqual(again['boot_marker_control'],{'status':'uncertain' if mutation in ('started_only','restored_without_new_journals') else 'invalid'})

    def test_bootmarker_non_b2_scope_never_captures_or_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            data,preboot,directory,_,marker=self.fixture(Path(tmp).resolve())
            core.stage_files(directory,marker,data,preboot,save,sync,owner_uid=os.geteuid(),debug_mask=0x102000,boot_marker_nonce=marker['nonce'])
            staged=data.read_bytes(),preboot.read_bytes()
            for current in (marker['baseline'],'invalid',True):
                with self.subTest(current=current),patch.object(core,'_production_paths',return_value=(data,preboot)), \
                     patch.object(core.boot,'capture',side_effect=AssertionError('non B2 capture')):
                    with self.assertRaises(ValueError):
                        core.finish(directory,marker,save,sync,current_boot_uuid=current,baseline_boot_argument_profile=core.boot.boot_argument_profile('-v'))
                self.assertEqual((data.read_bytes(),preboot.read_bytes()),staged)
                self.assertFalse((directory/'boot-marker-started.json').exists())

    def test_bootmarker_preexisting_debug_core_prevents_capture_but_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            data,preboot,directory,original,marker=self.fixture(Path(tmp).resolve());actual=core.boot.capture
            core.stage_files(directory,marker,data,preboot,save,sync,owner_uid=os.geteuid(),debug_mask=0x102000,boot_marker_nonce=marker['nonce'])
            save(directory/'debug-boot-core.json',b'{"status":"prior-negative-core"}')
            self.assertFalse((directory/'boot-marker-started.json').exists())
            self.assertFalse((directory/'bootplist-observation.json').exists())
            self.assertFalse((directory/'bootplist-restored.json').exists())
            def no_read(argv,*args,**kwargs):
                if argv==['/usr/sbin/sysctl','-n','kern.bootargs']: self.fail('saved core caused raw recapture')
                return actual(argv,*args,**kwargs)
            with patch.object(core,'_production_paths',return_value=(data,preboot)),patch.object(core.boot,'capture',no_read):
                result=core.finish(directory,marker,save,sync,current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                   baseline_boot_argument_profile=core.boot.boot_argument_profile('-v'))
            self.assertTrue(result['bootplist_restored'])
            self.assertEqual(result['boot_marker_control'],{'status':'uncertain'})
            self.assertEqual((data.read_bytes(),preboot.read_bytes()),(original,original))
            self.assertFalse((directory/'boot-marker-started.json').exists())

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

    def test_netdump_active_control_uses_one_capture_and_replays_without_reading(self):
        settings = self.netdump_settings()
        baseline = core.boot.boot_argument_profile('-v')
        active = '-v debug=0x22040 ' + ' '.join(settings.tokens())
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                             debug_mask=0x22040, netdump_settings=settings)
            captures = []
            def read_active(_platform):
                captures.append(True)
                if len(captures) != 1: raise AssertionError('active_recaptured')
                return active.encode()
            with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                 patch.object(core.boot.MacPlatform, 'active', read_active):
                result = core.finish(directory, marker, save, sync,
                                     current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                     baseline_boot_argument_profile=baseline)
                again = core.finish(directory, marker, save, sync,
                                    current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                    baseline_boot_argument_profile=baseline)
            self.assertEqual(captures, [True])
            self.assertEqual(again, result)
            self.assertTrue(result['bootplist_restored'])
            self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))
            control = result['netdump_active_control']
            self.assertEqual(control['status'], 'observed')
            self.assertEqual(control['settings_sha256'], settings.digest())
            self.assertEqual(control['remaining_profile'], {**baseline, 'debug_mask': 0x22040})
            self.assertEqual(control['full_profile']['nondebug_token_count'], baseline['nondebug_token_count'] + 4)
            self.assertEqual(control['full_profile']['debug_mask'], result['active_debug_mask'])

    def test_netdump_bad_baseline_or_capture_still_restores_both_files(self):
        settings = self.netdump_settings()
        valid = '-v debug=0x22040 ' + ' '.join(settings.tokens())
        baseline = core.boot.boot_argument_profile('-v')
        for profile, active, status in ((None, valid, 'invalid'), ({}, valid, 'invalid'),
                                        ({**baseline, 'debug_mask': 0x2000}, valid, 'invalid'),
                                        (baseline, valid + ' other=1', 'invalid'),
                                        (baseline, OSError('read_unavailable'), 'unavailable')):
            with self.subTest(profile=profile, status=status), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                 debug_mask=0x22040, netdump_settings=settings)
                def read_active(_platform):
                    if isinstance(active, Exception): raise active
                    return active.encode()
                with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                     patch.object(core.boot.MacPlatform, 'active', read_active):
                    result = core.finish(directory, marker, save, sync,
                                         current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                         baseline_boot_argument_profile=profile)
                self.assertTrue(result['bootplist_restored'])
                self.assertEqual(result['netdump_active_control'], {'status': status})
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))
                def forbidden(_platform): raise AssertionError('active_recaptured')
                with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                     patch.object(core.boot.MacPlatform, 'active', forbidden):
                    again = core.finish(directory, marker, save, sync,
                                        current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                        baseline_boot_argument_profile=profile)
                self.assertEqual(again, result)

    def test_netdump_corrupt_or_partial_capture_does_not_block_restore_or_recapture(self):
        settings = self.netdump_settings()
        for filename, content in (('bootplist-active-started.json', '{'),
                                  ('bootplist-active-capture.json', '{'),
                                  ('bootplist-active-capture.json', '{"scope":{}}')):
            with self.subTest(filename=filename, content=content), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                 debug_mask=0x22040, netdump_settings=settings)
                (directory / filename).write_text(content)
                def forbidden(_platform): raise AssertionError('active_recaptured')
                with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                     patch.object(core.boot.MacPlatform, 'active', forbidden):
                    result = core.finish(directory, marker, save, sync,
                                         current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                         baseline_boot_argument_profile=core.boot.boot_argument_profile('-v'))
                self.assertTrue(result['bootplist_restored'])
                self.assertEqual(result['netdump_active_control'], {'status': 'invalid'})
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))

    def test_netdump_capture_storage_failure_restores_and_prevents_later_recapture(self):
        settings = self.netdump_settings()
        baseline = core.boot.boot_argument_profile('-v')
        active = ('-v debug=0x22040 ' + ' '.join(settings.tokens())).encode()
        for filename in ('bootplist-active-started.json', 'bootplist-active-capture.json'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                 debug_mask=0x22040, netdump_settings=settings)
                def failing_save(path, value):
                    if path.name == filename: raise OSError('capture_storage_failed')
                    save(path, value)
                calls = []
                def read_active(_platform):
                    calls.append(True)
                    return active
                with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                     patch.object(core.boot.MacPlatform, 'active', read_active):
                    result = core.finish(directory, marker, failing_save, sync,
                                         current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                         baseline_boot_argument_profile=baseline)
                    count = len(calls)
                    again = core.finish(directory, marker, save, sync,
                                        current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                        baseline_boot_argument_profile=baseline)
                self.assertTrue(result['bootplist_restored'])
                self.assertEqual(result['netdump_active_control'], {'status': 'invalid'})
                self.assertEqual(again, result)
                self.assertEqual(len(calls), count)
                self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))

    def test_netdump_capture_replay_rejects_scope_control_and_baseline_tampering(self):
        settings = self.netdump_settings()
        baseline = core.boot.boot_argument_profile('-v')
        for mutation in ('source', 'boot', 'settings', 'baseline', 'mask', 'extra', 'control_settings', 'count_bool', 'remaining_hash', 'caller_baseline'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
                core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                                 debug_mask=0x22040, netdump_settings=settings)
                with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                     patch.object(core.boot.MacPlatform, 'active', return_value=('-v debug=0x22040 ' + ' '.join(settings.tokens())).encode()):
                    first = core.finish(directory, marker, save, sync,
                                        current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                        baseline_boot_argument_profile=baseline)
                self.assertEqual(first['netdump_active_control']['status'], 'observed')
                path = directory / 'bootplist-active-capture.json'
                value = json.loads(path.read_text())
                if mutation == 'source': value['scope']['marker']['source_identity'] = 'd' * 64
                elif mutation == 'boot': value['scope']['current_boot_uuid'] = marker['baseline']
                elif mutation == 'settings': value['scope']['settings_sha256'] = '0' * 64
                elif mutation == 'baseline': value['scope']['baseline_profile_sha256'] = '0' * 64
                elif mutation == 'mask': value['active_mask'] = 0x2000
                elif mutation == 'extra': value['raw'] = 'unowned'
                elif mutation == 'control_settings': value['control']['settings_sha256'] = '0' * 64
                elif mutation == 'count_bool': value['control']['full_profile']['nondebug_token_count'] = True
                elif mutation == 'remaining_hash': value['control']['remaining_profile']['nondebug_sha256'] = '0' * 64
                path.write_text(json.dumps(value))
                supplied = core.boot.boot_argument_profile('-v other=1') if mutation == 'caller_baseline' else baseline
                def forbidden(_platform): raise AssertionError('active_recaptured')
                with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                     patch.object(core.boot.MacPlatform, 'active', forbidden):
                    result = core.finish(directory, marker, save, sync,
                                         current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                         baseline_boot_argument_profile=supplied)
                self.assertTrue(result['bootplist_restored'])
                self.assertEqual(result['netdump_active_control'], {'status': 'invalid'})

    def test_netdump_old_mask_receipt_never_gets_a_new_capture(self):
        settings = self.netdump_settings()
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                             debug_mask=0x22040, netdump_settings=settings)
            core.finish_files(directory, marker, data, preboot,
                              'BBBBBBBB-2222-2222-2222-222222222222', 0x2000, save, sync)
            def forbidden(_platform): raise AssertionError('active_recaptured')
            with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                 patch.object(core.boot.MacPlatform, 'active', forbidden):
                result = core.finish(directory, marker, save, sync,
                                     current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                     baseline_boot_argument_profile=core.boot.boot_argument_profile('-v'))
            self.assertEqual(result['active_debug_mask'], 0x2000)
            self.assertTrue(result['bootplist_restored'])
            self.assertEqual(result['netdump_active_control'], {'status': 'invalid'})

    def test_netdump_capture_and_restored_receipt_mask_mismatch_is_negative(self):
        settings = self.netdump_settings()
        baseline = core.boot.boot_argument_profile('-v')
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, _, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid(),
                             debug_mask=0x22040, netdump_settings=settings)
            with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                 patch.object(core.boot.MacPlatform, 'active', return_value=('-v debug=0x22040 ' + ' '.join(settings.tokens())).encode()):
                first = core.finish(directory, marker, save, sync,
                                    current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                    baseline_boot_argument_profile=baseline)
            self.assertEqual(first['netdump_active_control']['status'], 'observed')
            for filename in ('bootplist-observation.json', 'bootplist-restored.json'):
                path = directory / filename
                value = json.loads(path.read_text())
                value.update(active_debug_mask=0x2000, active_bootargs_status='observed_no_debug')
                path.write_text(json.dumps(value))
            with patch.object(core, '_production_paths', return_value=(data, preboot)):
                result = core.finish(directory, marker, save, sync,
                                     current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                     baseline_boot_argument_profile=baseline)
            self.assertEqual(result['active_debug_mask'], 0x2000)
            self.assertEqual(result['netdump_active_control'], {'status': 'invalid'})

    def test_legacy_finish_ignores_new_baseline_and_adds_no_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, preboot, directory, original, marker = self.fixture(Path(tmp).resolve())
            core.stage_files(directory, marker, data, preboot, save, sync, owner_uid=os.geteuid())
            with patch.object(core, '_production_paths', return_value=(data, preboot)), \
                 patch.object(core.boot.MacPlatform, 'active', return_value=b'-v debug=0x2000'):
                result = core.finish(directory, marker, save, sync,
                                     current_boot_uuid='BBBBBBBB-2222-2222-2222-222222222222',
                                     baseline_boot_argument_profile={'invalid': 'ignored'})
            self.assertNotIn('netdump_active_control', result)
            self.assertTrue(result['bootplist_restored'])
            self.assertEqual((data.read_bytes(), preboot.read_bytes()), (original, original))

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
