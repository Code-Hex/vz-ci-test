import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bootargs", Path(__file__).with_name("recovery_bootargs.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
MARKER = {"baseline": "old", "nonce": "b" * 64, "binding": "123/1/" + "a" * 40}
CANARY = "vz-ci-persistence-probe"


class Platform:
    def __init__(self, value):
        self.value, self.events, self.fail_write = value, [], False
        self.active_value = b"preempt=10"

    def read(self):
        return self.value

    def write(self, path, owned_canary, expected_previous):
        self.events.append("write")
        self.value = b.parse_nvram(path.read_bytes())
        if self.fail_write:
            self.fail_write = False
            raise OSError("write response lost")

    def active(self):
        self.events.append("active")
        if isinstance(self.active_value, Exception):
            raise self.active_value
        return self.active_value

    def inventory(self):
        self.events.append("inventory")
        return {"debugger_count": None, "virtio_network_classes": [], "nic_inventory_status": "unsupported"}


class BootMarker(unittest.TestCase):
    def test_strict_raw_stdout_and_255_byte_whole_args_boundary(self):
        self.assertEqual(b.decode_bootmarker_stdout(b'alpha=1\n'), b'alpha=1')
        for raw in (b'alpha=1', b'alpha=1\n\n', b'alpha=1\r\n', b'alpha\t1\n', b'alpha\0\n', b'\xff\n', 'alpha=1\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): b.decode_bootmarker_stdout(raw)
        nonce='b'*64; token='vz_ci_nonce='+nonce
        args=('x'* (255-len(token)-len(' debug=0x102000 ')))+' debug=0x102000 '+token
        self.assertEqual(len(args),255)
        baseline=b.boot_argument_profile(args.split(' ')[0])
        result=b.bootmarker_control((args+'\n').encode(),nonce,baseline)
        self.assertEqual(set(result),{'status','marker_sha256','active_sha256','active_byte_count','full_profile','remaining_profile'})
        self.assertEqual(result['active_byte_count'],255)
        self.assertTrue(b.bootmarker_proven(result,nonce,baseline))
        with self.assertRaises(ValueError): b.bootmarker_control((args+' \n').encode(),nonce,baseline)

    def test_complete_token_profiles_and_strict_record_variants(self):
        nonce='b'*64; token='vz_ci_nonce='+nonce; baseline=b.boot_argument_profile('alpha=1 beta=2')
        raw=('alpha=1 beta=2 debug=0x102000 '+token+'\n').encode()
        fact=b.bootmarker_control(raw,nonce,baseline)
        self.assertEqual(b.checked_bootmarker_control(fact,nonce,baseline),fact)
        for args in ('alpha=1 beta=2 debug=0x102000', 'alpha=1 beta=2 debug=0x102000 -'+token,
                     'alpha=1 beta=2 debug=0x102000 '+token+' '+token,
                     'alpha=1 beta=2 debug=0x102000 '+token+'0',
                     'beta=2 alpha=1 debug=0x102000 '+token,
                     'alpha=1 beta=2 other=1 debug=0x102000 '+token):
            with self.subTest(args=args),self.assertRaises(ValueError): b.bootmarker_control((args+'\n').encode(),nonce,baseline)
        for changed in ({**fact,'active_byte_count':True},{**fact,'extra':'secret'},{**fact,'marker_sha256':'c'*64},
                        {**fact,'remaining_profile':{**fact['remaining_profile'],'nondebug_token_count':True}},
                        {'status':'observed'},{'status':'invalid','raw':'secret'}):
            self.assertFalse(b.bootmarker_proven(changed,nonce,baseline))
        for status in ('invalid','unavailable','uncertain'):
            self.assertEqual(b.checked_bootmarker_control({'status':status},nonce,baseline),{'status':status})
            self.assertFalse(b.bootmarker_proven({'status':status},nonce,baseline))

    def test_baseline_rejects_preexisting_owned_marker_aliases(self):
        for args in ('vz_ci_nonce=old','-vz_ci_nonce=old','--vz_ci_nonce','vz_ci_nonce =old','vz_ci_nonce=one vz_ci_nonce=two'):
            with self.subTest(args=args):
                self.assertEqual(b.observe_bootmarker_baseline(read=lambda *_a,**_k:(args+'\n').encode()),{'status':'invalid'})

    def test_baseline_fixed_read_uses_raw_output_and_native_child_seam(self):
        calls=[]; actual=b.capture
        def read(argv,limit,timeout):
            calls.append((argv,limit,timeout))
            return actual([sys.executable,'-c',"print('alpha=1')"],limit,timeout)
        self.assertEqual(b.observe_bootmarker_baseline(read=read),b.boot_argument_profile('alpha=1'))
        self.assertEqual(calls,[(['/usr/sbin/sysctl','-n','kern.bootargs'],1025,8)])
        self.assertEqual(b.observe_bootmarker_baseline(read=lambda *_a,**_k:b'alpha=1\n\n'),{'status':'invalid'})
        def failed(*_a,**_k): raise OSError('synthetic getter failure')
        self.assertEqual(b.observe_bootmarker_baseline(read=failed),{'status':'unavailable'})


class CaptureTimeoutObserver(unittest.TestCase):
    def test_observer_sees_owned_unreaped_pid_and_cannot_promote_late_value(self):
        import os,subprocess,time
        seen=[]
        def observer(pid,frozen):
            os.kill(pid,0);seen.append(pid)
            self.assertEqual(frozen,{'timeout_seconds':.02,'stdout':b'','stderr':b''})
            frozen['stdout']=b'changed observer copy'
            time.sleep(.12)
        program='import time;time.sleep(.06);print("VZKSTATE v1 debug_boot_arg u32 1056768\\n")'
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            b.capture([sys.executable,'-c',program],4096,timeout=.02,capture_stderr=True,on_timeout=observer)
        self.assertEqual((caught.exception.timeout,caught.exception.output,caught.exception.stderr),(.02,b'',b''))
        self.assertEqual(len(seen),1)
        with self.assertRaises(ProcessLookupError): os.kill(seen[0],0)

    def test_observer_failure_does_not_replace_original_timeout_or_skip_cleanup(self):
        import os,subprocess
        for error in (OSError('private diagnostic failure'),KeyboardInterrupt(),subprocess.TimeoutExpired(['sampler'],8)):
            with self.subTest(kind=type(error).__name__):
                seen=[]
                def observer(pid,frozen): seen.append(pid);raise error
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    b.capture([sys.executable,'-c','import time;time.sleep(10)'],4096,timeout=.02,capture_stderr=True,on_timeout=observer)
                self.assertEqual((caught.exception.timeout,caught.exception.output),(.02,b''))
                self.assertEqual(len(seen),1)
                with self.assertRaises(ProcessLookupError): os.kill(seen[0],0)

    def test_other_capture_outcomes_do_not_observe(self):
        import subprocess
        def forbidden(*_): self.fail('non timeout invoked sampler')
        self.assertEqual(b.capture([sys.executable,'-c','print("ok")'],4096,1,on_timeout=forbidden),b'ok\n')
        with self.assertRaises(subprocess.CalledProcessError):
            b.capture([sys.executable,'-c','raise SystemExit(1)'],4096,1,on_timeout=forbidden)
        with self.assertRaises(ValueError):
            b.capture([sys.executable,'-c','print("overflow")'],2,1,on_timeout=forbidden)


class BootArgumentProfile(unittest.TestCase):
    def test_optional_registry_summary_rejects_unknown_public_fields(self):
        snapshot = {'scope': 'current_registered_services_not_polled_io_proof', 'queries': {
            name: {'status': 'observed', 'returncode': 0, 'count': 0, 'nodes': []}
            for name in ('IOPlatformExpertDevice', 'IOKernelDebugger', 'IOKDP', 'IONVRAMController')}}
        self.assertEqual(b.optional_summary({'registered_services': snapshot})['registered_services'], snapshot)
        invalid = {**snapshot, 'private_path': '/private/secret'}
        self.assertNotIn('registered_services', b.optional_summary({'registered_services': invalid}))

    def test_canonical_spacing_and_exact_token_sequence(self):
        expected = {'status': 'observed', 'debug_mask': 8192, 'nondebug_token_count': 3,
                    'nondebug_sha256': '11a6f7c443706e6d2af0396c32aa8d5350a93892d43185cdacfe1430b82d9505'}
        self.assertEqual(b.boot_argument_profile(' alpha=1  beta\talpha=1  --debug=0x2000 '), expected)
        self.assertEqual(b.boot_argument_profile(b'alpha=1\tbeta alpha=1 -debug=8192'), expected)
        self.assertNotEqual(b.boot_argument_profile('beta alpha=1 alpha=1')['nondebug_sha256'], expected['nondebug_sha256'])
        self.assertNotEqual(b.boot_argument_profile('alpha=1 beta')['nondebug_sha256'], expected['nondebug_sha256'])

    def test_only_exact_debug_key_is_excluded(self):
        result = b.boot_argument_profile('debugger=1 xdebug=3 -debugger=2 debug=0')
        self.assertEqual(result['debug_mask'], 0)
        self.assertEqual(result['nondebug_token_count'], 3)
        self.assertEqual(result['nondebug_sha256'], b.boot_argument_profile('debugger=1 xdebug=3 -debugger=2')['nondebug_sha256'])
        self.assertNotIn('debugger', json.dumps(result))

    def test_empty_and_debug_only_have_same_nondebug_hash(self):
        empty = b.boot_argument_profile('')
        debug = b.boot_argument_profile('--debug=0x2000')
        self.assertEqual(empty['nondebug_sha256'], '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945')
        self.assertEqual((empty['nondebug_token_count'], debug['nondebug_token_count']), (0, 0))
        self.assertEqual(empty['nondebug_sha256'], debug['nondebug_sha256'])
        self.assertIsNone(empty['debug_mask'])

    def test_invalid_values_propagate(self):
        for value in ('debug=1 debug=2', 'debug=wat', 'debug', '_router_ip=1', b'x\n', 'x' * 1024, None, 'é'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                b.boot_argument_profile(value)


class Bootargs(unittest.TestCase):
    def save(self, path, data):
        with path.open("xb") as stream:
            stream.write(data)

    def test_two_key_combinations_are_observed_before_restore(self):
        for boot_staged in (False, True):
            for canary_staged in (False, True):
                with self.subTest(boot_staged=boot_staged, canary_staged=canary_staged), tempfile.TemporaryDirectory() as tmp:
                    directory, original = Path(tmp), {"boot-args": b"preempt=10"}
                    platform = Platform(original.copy())
                    b.stage(directory, MARKER, platform, self.save, lambda _p: None)
                    staged = platform.value.copy()
                    self.assertEqual(staged[CANARY], b"v1:123:1:" + b"b" * 64)
                    platform.value = {"boot-args": staged["boot-args"] if boot_staged else original["boot-args"]}
                    if canary_staged:
                        platform.value[CANARY] = staged[CANARY]
                    expected = {"boot_args": "staged" if boot_staged else "original",
                                "canary": "staged" if canary_staged else "original"}
                    def save(path, data):
                        self.save(path, data)
                        if path.name == "debug-boot-observed.json":
                            self.assertEqual(json.loads(data)["nvram_key_states"], expected)
                            self.assertEqual(CANARY in platform.value, canary_staged)
                    facts = b.finish(directory, MARKER, platform, save, lambda _p: None, current_boot_uuid="new", inventory=False)
                    self.assertEqual(facts["nvram_key_states"], expected)
                    self.assertEqual(facts["nvram_before_restore"], "staged" if all(expected[k] == "staged" for k in expected) else
                                     "original" if all(expected[k] == "original" for k in expected) else "partial")
                    self.assertEqual(platform.value, original)
                    self.assertNotIn(staged[CANARY].decode(), json.dumps(facts))
                    again = b.finish(directory, MARKER, platform, save, lambda _p: None, current_boot_uuid="new", inventory=False)
                    self.assertEqual(again["nvram_key_states"], expected)

    def test_existing_canary_and_foreign_values_never_mutate(self):
        for value in (b"", b"foreign", "foreign", 1):
            with self.subTest(existing=value), tempfile.TemporaryDirectory() as tmp:
                platform = Platform({CANARY: value})
                with self.assertRaises(ValueError):
                    b.stage(Path(tmp), MARKER, platform, self.save, lambda _p: None)
                self.assertNotIn("write", platform.events)
        for foreign in ({CANARY: b"other-nonce"}, {"boot-args": b"foreign=1"},
                        {CANARY: b.canary_value(MARKER).decode()}, {"boot-args": "preempt=10 debug=0x2000"}):
            with self.subTest(foreign=foreign), tempfile.TemporaryDirectory() as tmp:
                directory, platform = Path(tmp), Platform({"boot-args": b"preempt=10"})
                b.stage(directory, MARKER, platform, self.save, lambda _p: None)
                platform.value.update(foreign)
                before = platform.value.copy()
                platform.events.clear()
                staged = b.desired({"boot-args": b"preempt=10"}, MARKER)
                _whole, states = b.key_states({"boot-args": b"preempt=10"}, staged, before)
                self.assertIn("other", states.values())
                facts = b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertFalse(facts["nvram_restored"])
                self.assertEqual(facts["nvram_before_restore"], "other")
                self.assertEqual(facts["nvram_key_states"], states)
                self.assertEqual(json.loads((directory / "debug-boot-observed.json").read_text())["nvram_key_states"], states)
                self.assertEqual(platform.value, before)
                self.assertNotIn("write", platform.events)
                platform.value.update({"boot-args": "another foreign type", CANARY: b"another foreign nonce"})
                again = b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertFalse(again["nvram_restored"])
                self.assertEqual(again["nvram_key_states"], states)
                self.assertNotIn("write", platform.events)
                for marker in (dict(MARKER, nonce="c" * 64), dict(MARKER, binding="124/1/" + "a" * 40)):
                    with self.assertRaises(ValueError):
                        b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertNotIn("write", platform.events)
        with self.assertRaises(ValueError):
            b.parse_nvram(plistlib.dumps({"other:" + CANARY: b"foreign"}))

    def test_canary_payload_requires_bound_marker(self):
        for marker in (dict(MARKER, nonce="invalid"), dict(MARKER, binding="foreign")):
            with self.assertRaises(ValueError):
                b.canary_value(marker)

    def test_canary_removal_failure_and_silent_failure_retry(self):
        for failure in ("error", "silent"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                directory, state = Path(tmp), {"boot-args": b"preempt=10"}
                events, fail_delete = [], [True]
                def capture(argv, *_args):
                    if argv == ["/usr/sbin/nvram", "-x", "-p"]:
                        return plistlib.dumps(state)
                    if argv[0] == "/usr/sbin/sysctl":
                        return b"preempt=10\n"
                    if argv[1:3] == ["-x", "-f"]:
                        state.update(b.parse_nvram(Path(argv[3]).read_bytes()))
                        return b""
                    if argv[1] == "-d":
                        self.assertEqual(argv[2], CANARY)
                        events.append("delete")
                        if fail_delete[0]:
                            fail_delete[0] = False
                            if failure == "error":
                                raise OSError("delete response failed")
                        else:
                            state.pop(CANARY)
                        return b""
                    self.assertEqual(argv, ["/usr/sbin/nvram", "-s"])
                    events.append("sync")
                    return b""
                with patch.object(b, "capture", capture):
                    platform = b.MacPlatform()
                    b.stage(directory, MARKER, platform, self.save, lambda _p: None)
                    with self.assertRaises((OSError, ValueError)):
                        b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                    self.assertFalse((directory / "debug-boot-restored.json").exists())
                    self.assertIn(CANARY, state)
                    facts = b.finish(directory, MARKER, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertTrue(facts["nvram_restored"])
                self.assertEqual(facts["nvram_key_states"], {"boot_args": "staged", "canary": "staged"})
                self.assertEqual(state, {"boot-args": b"preempt=10"})
                self.assertEqual(events.count("delete"), 2)
                self.assertEqual(events[-2:], ["delete", "sync"])

    def test_writer_refuses_foreign_canary_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "original.plist"
            path.write_bytes(plistlib.dumps({"boot-args": b"preempt=10"}))
            calls = []
            def capture(argv, *_args):
                calls.append(argv)
                return plistlib.dumps({CANARY: b"foreign"})
            with patch.object(b, "capture", capture):
                with self.assertRaises(ValueError):
                    b.MacPlatform().write(path, b.canary_value(MARKER), {"boot-args": b"preempt=10", CANARY: b.canary_value(MARKER)})
            self.assertEqual(calls, [["/usr/sbin/nvram", "-x", "-p"]])

    def test_writer_does_not_ignore_changed_bootargs_on_second_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, platform = Path(tmp), Platform({"boot-args": b"preempt=10"})
            b.stage(directory, MARKER, platform, self.save, lambda _p: None)
            staged, calls, reads = platform.value.copy(), [], []
            def capture(argv, *_args):
                calls.append(argv)
                if argv[0] == "/usr/sbin/sysctl":
                    return b"preempt=10\n"
                self.assertEqual(argv, ["/usr/sbin/nvram", "-x", "-p"])
                reads.append("read")
                return plistlib.dumps(staged if len(reads) == 1 else {**staged, "boot-args": b"external=1"})
            with patch.object(b, "capture", capture):
                facts = b.finish(directory, MARKER, b.MacPlatform(), self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
            self.assertFalse(facts["nvram_restored"])
            self.assertEqual(facts["nvram_key_states"], {"boot_args": "staged", "canary": "staged"})
            self.assertFalse((directory / "debug-boot-restored.json").exists())
            self.assertEqual(len(calls), 3)

    def test_platform_write_and_delete_request_force_sync_after_mutation(self):
        for value in ({"boot-args": b"preempt=10"}, {}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "value.plist"
                path.write_bytes(plistlib.dumps(value))
                calls = []
                def capture(argv):
                    calls.append(argv)
                    return plistlib.dumps({"boot-args": b"preempt=10", CANARY: b.canary_value(MARKER)})
                with patch.object(b, "capture", capture):
                    b.MacPlatform().write(path, b.canary_value(MARKER), {"boot-args": b"preempt=10", CANARY: b.canary_value(MARKER)})
                mutations = [["/usr/sbin/nvram", "-x", "-f", str(path)]] if value else [["/usr/sbin/nvram", "-d", "boot-args"]]
                self.assertEqual(calls, [["/usr/sbin/nvram", "-x", "-p"], *mutations,
                                        ["/usr/sbin/nvram", "-d", CANARY], ["/usr/sbin/nvram", "-s"]])

    def test_failed_force_sync_prevents_restore_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            state, syncs = {"boot-args": b"preempt=10"}, []
            def capture(argv, *_args):
                if argv == ["/usr/sbin/nvram", "-x", "-p"]:
                    return plistlib.dumps(state)
                if argv[0] == "/usr/sbin/sysctl":
                    return b"preempt=10\n"
                if argv[1:3] == ["-x", "-f"]:
                    state.update(b.parse_nvram(Path(argv[3]).read_bytes()))
                    return b""
                if argv[1] == "-d":
                    state.pop(argv[2], None)
                    return b""
                self.assertEqual(argv, ["/usr/sbin/nvram", "-s"])
                syncs.append("sync")
                if len(syncs) == 2:
                    raise OSError("sync request failed")
                return b""
            with patch.object(b, "capture", capture):
                platform = b.MacPlatform()
                b.stage(directory, marker, platform, self.save, lambda _p: None)
                with self.assertRaises(OSError):
                    b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
                self.assertFalse((directory / "debug-boot-restored.json").exists())
                self.assertEqual(syncs, ["sync", "sync"])
                def save(path, data):
                    if path.name == "debug-boot-restored.json":
                        self.assertEqual(syncs, ["sync", "sync", "sync"])
                    self.save(path, data)
                facts = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new", inventory=False)
            self.assertTrue(facts["nvram_restored"])
            self.assertTrue((directory / "debug-boot-restored.json").exists())

    def test_input_and_type_preservation(self):
        for original in ({}, {"boot-args": "preempt=10"}, {"boot-args": b"preempt=10"}, {"boot-args": b""}):
            staged = b.desired(original, MARKER)
            self.assertEqual(b.debug_mask(staged["boot-args"]), 0x2000)
            if original:
                self.assertIs(type(staged["boot-args"]), type(original["boot-args"]))
        for raw in (b"", b"garbage", plistlib.dumps([]), plistlib.dumps({"boot-args": 1}),
                    plistlib.dumps({"other:boot-args": b""})):
            with self.assertRaises(ValueError):
                b.parse_nvram(raw)
        for value in ("debug=0", "_panicd_ip=1.1.1.1", "_router_ip=1.1.1.1", "_panicd_corename=x"):
            with self.assertRaises(ValueError):
                b.desired({"boot-args": value}, MARKER)

    def test_stage_saved_before_write_and_restore_before_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            original = {"boot-args": b"preempt=10"}
            platform = Platform(original)
            marker = dict(MARKER)
            def save(path, data):
                self.save(path, data)
                platform.events.append(path.name)
            b.stage(directory, marker, platform, save, lambda _p: platform.events.append("sync"))
            self.assertLess(platform.events.index("debug-boot-stage.json"), platform.events.index("write"))
            self.assertLess(platform.events.index("sync"), platform.events.index("write"))
            platform.events.clear()
            platform.active_value = b"preempt=10 debug=0x2000"
            facts = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(platform.value, original)
            self.assertEqual(facts["active_debug_mask"], 0x2000)
            self.assertTrue(facts["nvram_restored"])
            self.assertLess(platform.events.index("write"), platform.events.index("inventory"))
            self.assertEqual(facts["nic_inventory_status"], "unsupported")
            with self.assertRaises(FileExistsError):
                b.stage(directory, marker, platform, save, lambda _p: None)

    def test_write_failure_restores_and_absent_restores_to_absent(self):
        for original in ({}, {"boot-args": ""}):
            with self.subTest(original=original), tempfile.TemporaryDirectory() as tmp:
                directory, platform = Path(tmp), Platform(original)
                platform.fail_write = True
                with self.assertRaises(OSError):
                    b.stage(directory, dict(MARKER), platform, self.save, lambda _p: None)
                self.assertEqual(platform.value, original)
                self.assertTrue(json.loads((directory / "debug-boot-restored.json").read_text())["nvram_restored"])

    def test_invalid_active_mask_still_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.active_value = b"debug=invalid"
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertIsNone(facts["active_debug_mask"])
            self.assertTrue(facts["nvram_restored"])
            self.assertEqual(platform.value, original)

    def test_identity_or_unexpected_nvram_prevents_overwrite_and_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({"boot-args": "preempt=10"})
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.value = {"boot-args": "other=1"}
            platform.events.clear()
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertFalse(facts["nvram_restored"])
            self.assertEqual(facts["nvram_key_states"]["boot_args"], "other")
            with self.assertRaises(ValueError):
                b.finish(directory, dict(MARKER, baseline="other"), platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertNotIn("write", platform.events)
            self.assertNotIn("inventory", platform.events)

    def test_capture_rejects_oversized_child_output(self):
        with self.assertRaises(ValueError):
            b.capture([sys.executable, "-c", "print('oversized')"], limit=2)

    def test_unstaged_rollback_only_accepts_clean_nvram(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({"boot-args": "preempt=10"})
            b.rollback(directory, marker, platform, self.save, lambda _p: None)
            self.assertNotIn("write", platform.events)
            platform.value = {"boot-args": "debug=0x2000"}
            with self.assertRaises(ValueError):
                b.rollback(directory, marker, platform, self.save, lambda _p: None)
            original = directory / "debug-boot-original.plist"
            self.save(original, plistlib.dumps({"boot-args": "preempt=10"}))
            with self.assertRaises(ValueError):
                b.rollback(directory, marker, platform, self.save, lambda _p: None)
            original.write_bytes(b"")
            with self.assertRaises(ValueError):
                b.rollback(directory, marker, platform, self.save, lambda _p: None)
            self.assertNotIn("write", platform.events)

    def test_active_status_and_nvram_before_restore_are_distinct(self):
        for value, status, mask in ((b"preempt=10", "observed_no_debug", None),
                                    (b"debug=0x2000", "observed_debug", 0x2000),
                                    (OSError("unavailable"), "unavailable", None),
                                    (b"debug=invalid", "invalid", None)):
            for before in ("staged", "original"):
                with self.subTest(status=status, before=before), tempfile.TemporaryDirectory() as tmp:
                    directory, original = Path(tmp), {"boot-args": b"preempt=10"}
                    platform, marker = Platform(original), dict(MARKER)
                    b.stage(directory, marker, platform, self.save, lambda _p: None)
                    if before == "original":
                        platform.value = original
                    platform.active_value = value
                    platform.events.clear()
                    def save(path, data):
                        self.save(path, data)
                        platform.events.append(path.name)
                    facts = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
                    self.assertEqual(facts["active_bootargs_status"], status)
                    self.assertEqual(facts["active_debug_mask"], mask)
                    self.assertEqual(facts["nvram_before_restore"], before)
                    self.assertFalse(facts["restored_marker_preexisting"])
                    if before == "staged":
                        self.assertLess(platform.events.index("debug-boot-observed.json"), platform.events.index("write"))
                    again = b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
                    self.assertEqual(again["nvram_before_restore"], before)
                    self.assertFalse(again["restored_marker_preexisting"])

    def test_preexisting_restore_receipt_identifies_oldboot_writer_without_raw_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            self.assertEqual(b.rollback(directory, marker, platform, self.save, lambda _p: None), "staged")
            receipt = directory / "debug-boot-restored.json"
            data = json.loads(receipt.read_text())
            data["raw"] = "not published"
            receipt.write_text(json.dumps(data))
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertTrue(facts["restored_marker_preexisting"])
            self.assertEqual(facts["restore_receipt"], {"status": "observed", "cause": "preintent_abort",
                                                     "actual_boot_uuid": "old", "nvram_before_restore": "staged",
                                                     "nvram_key_states": {"boot_args": "staged", "canary": "staged"}})
            self.assertNotIn("not published", str(facts))

    def test_invalid_debugger_plist_does_not_hide_network_class(self):
        network = plistlib.dumps([{"IOObjectClass": "AppleVirtIONetwork", "secret": "not published"}])
        def capture(argv, *_args, **_kwargs):
            if argv[-1] == "IOKernelDebugger":
                return b""
            if argv[-1] == "IONetworkController":
                return network
            raise OSError("optional unavailable")
        with patch.object(b, "capture", capture):
            facts = b.MacPlatform().inventory()
        self.assertIsNone(facts["debugger_count"])
        self.assertEqual(facts["debugger_inventory_status"], "invalid")
        self.assertEqual(facts["network_inventory_status"], "observed")
        self.assertEqual(facts["virtio_network_classes"], ["AppleVirtIONetwork"])
        self.assertNotIn("not published", str(facts))

    def test_empty_ioreg_array_is_observed_zero(self):
        def capture(argv, *_args, **_kwargs):
            if argv[0] == "/usr/sbin/dtrace":
                raise OSError("unavailable")
            return plistlib.dumps([])
        with patch.object(b, "capture", capture):
            facts = b.MacPlatform().inventory()
        self.assertEqual(facts["debugger_count"], 0)
        self.assertEqual(facts["debugger_inventory_status"], "observed")
        self.assertEqual(facts["network_inventory_status"], "observed")
        self.assertTrue(all(value["status"] == "unavailable" and value["error"]["reason"] == "os_error" for value in facts["kernel_debug_state"].values()))

    def test_optional_kernel_summary_preserves_exact_types_and_rejects_bad_ranges(self):
        states={'debug_boot_arg':{'status':'observed','value':0x102000},
                'dtrace_destructive_disallow':{'status':'observed','value':-1},
                'coprocessor_paniclog_flush':{'status':'observed','value':False}}
        self.assertEqual(b.optional_summary({'kernel_debug_state':states})['kernel_debug_state'],states)
        for name, values in (('debug_boot_arg',(True,1.0,-1,4294967296)),
                ('dtrace_destructive_disallow',(False,-2147483649,2147483648,'-1')),
                ('coprocessor_paniclog_flush',(0,1,2,'false'))):
            for value in values:
                with self.subTest(name=name,value=value):
                    observed={'kernel_debug_state':{name:{'status':'observed','value':value}}}
                    self.assertEqual(b.optional_summary(observed)['kernel_debug_state'],{name:{'status':'invalid'}})

    def test_optional_kernel_observation_roundtrips_actual_files_without_reexecution(self):
        states={'debug_boot_arg':{'status':'observed','value':0x102000},
                'dtrace_destructive_disallow':{'status':'observed','value':-1},
                'coprocessor_paniclog_flush':{'status':'observed','value':False}}
        class Inventory:
            calls=0
            def inventory(self):
                self.calls+=1
                if self.calls!=1: raise AssertionError('inventory rerun')
                return {'kernel_debug_state':states}
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); platform=Inventory()
            first=b.observe_once(directory,MARKER,platform,self.save,lambda _:None,current_boot_uuid='new')
            saved=json.loads((directory/'debug-boot-inventory-result.json').read_text())
            again=b.observe_once(directory,MARKER,platform,self.save,lambda _:None,current_boot_uuid='new')
            self.assertEqual(first,again)
            self.assertEqual(saved['facts']['kernel_debug_state'],states)
            self.assertEqual(again['kernel_debug_state'],states)
            self.assertIs(again['kernel_debug_state']['coprocessor_paniclog_flush']['value'],False)
            self.assertIs(type(again['kernel_debug_state']['dtrace_destructive_disallow']['value']),int)
            self.assertEqual(platform.calls,1)

    def test_capture_stderr_preserves_success_stdout_and_bounded_failed_evidence(self):
        import subprocess
        marker=b'VZKSTATE v1 debug_boot_arg u32 0\n\n'
        program='import sys; sys.stdout.buffer.write('+repr(marker)+'); sys.stderr.write("private warning 0xffffabcd\\n")'
        self.assertEqual(b.capture([sys.executable,'-c',program],4096,timeout=1,capture_stderr=True),marker)
        self.assertEqual(b.capture([sys.executable,'-c','import os,time; os.close(2); time.sleep(.02); print("later")'],4096,timeout=1,capture_stderr=True),b'later\n')
        self.assertEqual(b.capture([sys.executable,'-c','import os,sys; os.close(1); sys.stderr.write("warning")'],4096,timeout=1,capture_stderr=True),b'')
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            b.capture([sys.executable,'-c',program+'; sys.stderr.write("[D_SYM_NOTYPES]"); sys.exit(1)'],4096,timeout=1,capture_stderr=True)
        error=caught.exception
        self.assertEqual(error.output,marker)
        self.assertIn(b'[D_SYM_NOTYPES]',error.stderr)
        facts=b.kernel_debug_state(read=lambda *args,**kwargs: (_ for _ in ()).throw(error))
        detail=facts['debug_boot_arg']['error']
        self.assertEqual(detail['reason'],'command_failed')
        self.assertEqual(detail['exit_code'],1)
        self.assertEqual(detail['tags'],['D_SYM_NOTYPES'])
        self.assertNotIn('0xffffabcd',str(facts))
        self.assertEqual(b.optional_summary({'kernel_debug_state':facts})['kernel_debug_state'],facts)

    def test_capture_stderr_both_pipe_quotas_and_timeout_keep_partial_bytes(self):
        import subprocess
        for stream in ('stdout','stderr'):
            with self.assertRaises(b.CaptureLimit) as caught:
                b.capture([sys.executable,'-c','import sys; sys.'+stream+'.write("x"*100000)'],64,timeout=1,capture_stderr=True)
            self.assertLessEqual(len(caught.exception.output)+len(caught.exception.stderr),64)
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            b.capture([sys.executable,'-c','import sys,time; print("part",flush=True); print("[D_IDENT_UNDEF]",file=sys.stderr,flush=True); time.sleep(10)'],4096,timeout=.1,capture_stderr=True)
        self.assertEqual(caught.exception.output,b'part\n')
        self.assertIn(b'D_IDENT_UNDEF',caught.exception.stderr)
        facts=b.kernel_debug_state(read=lambda *a,**k: (_ for _ in ()).throw(caught.exception))
        self.assertTrue(all(value['error']['reason']=='timeout' for value in facts.values()))

    def test_kernel_error_safe_fields_roundtrip_and_reject_raw_or_bad_types(self):
        import subprocess,hashlib
        stderr=b'private address 0xffff1234 [D_SYM_NOTYPES] [D_IDENT_UNDEF] [D_IDENT_UNDEF]'
        original=subprocess.CalledProcessError(1,['private-command'],output=b'0\n',stderr=stderr)
        detail=b.kernel_failure('command_failed',original)
        self.assertEqual(detail,{'reason':'command_failed','exit_code':1,'output_bytes':len(b'0\n'+stderr),
            'output_sha256':hashlib.sha256(b'0\n'+stderr).hexdigest(),'tags':['D_IDENT_UNDEF','D_SYM_NOTYPES']})
        for changed in ({'raw':'secret'},{'reason':'permission guessed'},{'exit_code':True},{'output_bytes':4097},
                {'output_sha256':'bad'},{'tags':['D_TAG','D_TAG']},{'tags':['private address']},
                {'tags':['D_A','D_B','D_C','D_D','D_E']},{'output_bytes':None}):
            value={'kernel_debug_state':{'debug_boot_arg':{'status':'unavailable','error':{**detail,**changed}}}}
            self.assertEqual(b.optional_summary(value)['kernel_debug_state'],{'debug_boot_arg':{'status':'invalid'}})
        states={'debug_boot_arg':{'status':'unavailable','error':detail}}
        class Inventory:
            calls=0
            def inventory(self):
                self.calls+=1
                return {'kernel_debug_state':states}
        with tempfile.TemporaryDirectory() as tmp:
            platform=Inventory(); directory=Path(tmp)
            first=b.observe_once(directory,MARKER,platform,self.save,lambda _:None,current_boot_uuid='new')
            again=b.observe_once(directory,MARKER,platform,self.save,lambda _:None,current_boot_uuid='new')
            self.assertEqual(first,again); self.assertEqual(again['kernel_debug_state'],states)
            self.assertEqual(platform.calls,1)
            saved=(directory/'debug-boot-inventory-result.json').read_text()
            self.assertNotIn('private address',saved); self.assertNotIn('private-command',saved)
            self.assertNotIn('0xffff1234',saved)

    def test_capture_exact_shared_limit_and_eof_and_default_path(self):
        program='import sys; sys.stdout.write("a"*2048); sys.stdout.flush(); sys.stderr.write("b"*2048)'
        self.assertEqual(b.capture([sys.executable,'-c',program],4096,timeout=1,capture_stderr=True),b'a'*2048)
        with self.assertRaises(b.CaptureLimit) as caught:
            b.capture([sys.executable,'-c',program.replace('"b"*2048','"b"*2049')],4096,timeout=1,capture_stderr=True)
        self.assertEqual(len(caught.exception.output)+len(caught.exception.stderr),4096)
        self.assertEqual(b.capture([sys.executable,'-c','print("a"*4095)'],4096,timeout=1),b'a'*4095+b'\n')
        with self.assertRaises(ValueError): b.capture([sys.executable,'-c','print("a"*4096)'],4096,timeout=1)

    def test_single_field_reader_default_and_explicit_budget_preserve_fixed_program(self):
        calls=[]
        def read(argv,limit,timeout,*,capture_stderr):
            self.assertEqual((limit,capture_stderr),(4096,True))
            calls.append((argv,timeout))
            return b.capture([sys.executable,'-c','print("VZKSTATE v1 debug_boot_arg u32 0\\n")'],limit,timeout,capture_stderr=True)
        self.assertEqual(b.kernel_field_state('debug_boot_arg',read=read),{'status':'observed','value':0})
        self.assertEqual(b.kernel_field_state('debug_boot_arg',read=read,timeout=30),{'status':'observed','value':0})
        self.assertEqual([item[1] for item in calls],[5,30])
        self.assertTrue(all(item[0]==['/usr/sbin/dtrace','-q','-x','errtags','-n',b.kernel_field_program('debug_boot_arg')] for item in calls))
        for timeout in (True,0,31,1.5,'5'):
            with self.assertRaises(ValueError): b.kernel_field_state('debug_boot_arg',read=read,timeout=timeout)
        with self.assertRaises(ValueError): b.kernel_field_state('foreign',read=read)
        self.assertEqual(len(calls),2)

    def test_initial_field_budget_accepts_real_5_1_second_output_while_single_default_stays_5(self):
        calls=[]
        def read(argv,limit,timeout,*,capture_stderr):
            name=next(name for name in b.KERNEL_FIELDS if 'VZKSTATE v1 '+name+' ' in argv[-1])
            self.assertEqual(argv,['/usr/sbin/dtrace','-q','-x','errtags','-n',b.kernel_field_program(name)])
            self.assertEqual((limit,capture_stderr),(4096,True))
            calls.append((name,timeout))
            line='VZKSTATE v1 '+name+' '+b.KERNEL_FIELDS[name][1]+' 0\n\n'
            program='import sys,time; time.sleep('+('5.1' if name=='debug_boot_arg' else '0')+'); sys.stdout.write('+repr(line)+')'
            return b.capture([sys.executable,'-c',program],limit,timeout,capture_stderr=True)
        short=b.kernel_field_state('debug_boot_arg',read=read)
        self.assertEqual(short['status'],'unavailable')
        self.assertEqual(short['error']['reason'],'timeout')
        self.assertEqual(short['error']['output_bytes'],0)
        self.assertEqual(calls,[('debug_boot_arg',5)])
        calls.clear()
        fields=b.kernel_debug_state(read=read)
        self.assertEqual(fields['debug_boot_arg'],{'status':'observed','value':0})
        self.assertEqual(calls,[('debug_boot_arg',30)]+[(name,5) for name in list(b.KERNEL_FIELDS)[1:]])
        self.assertTrue(all(field['status']=='observed' for field in fields.values()))

    def test_critical_inventory_once_roundtrips_positive_and_negative_without_reread(self):
        for number in (0x102000,0,None):
            with self.subTest(number=number),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp); calls=[]
                def read(argv,limit,timeout,*,capture_stderr):
                    self.assertEqual(argv,['/usr/sbin/dtrace','-q','-x','errtags','-n',b.kernel_field_program('debug_boot_arg')])
                    self.assertEqual((limit,timeout,capture_stderr),(4096,30,True)); calls.append(1)
                    raw='VZKSTATE v1 debug_boot_arg u32 '+str(0 if number is None else number)+'\n\n'
                    program='import sys; print('+repr(raw)+',end="")'
                    if number is None: program+='; sys.stderr.write("[D_IDENT_UNDEF]"); sys.exit(1)'
                    return b.capture([sys.executable,'-c',program],limit,timeout,capture_stderr=True)
                inventory=b.KernelMaskInventory(read=read)
                first=b.observe_once(directory,MARKER,inventory,self.save,lambda _:None,current_boot_uuid='B2')
                second=b.observe_once(directory,MARKER,inventory,self.save,lambda _:None,current_boot_uuid='B2')
                self.assertEqual(first,second); self.assertEqual(calls,[1])
                if number is None:
                    self.assertEqual(first['kernel_debug_state']['debug_boot_arg']['status'],'unavailable')
                    self.assertEqual(first['kernel_debug_state']['debug_boot_arg']['error']['tags'],['D_IDENT_UNDEF'])
                else: self.assertEqual(first['kernel_debug_state'],{'debug_boot_arg':{'status':'observed','value':number}})
                self.assertEqual(first['optional_inventory_status'],'completed')
                mismatch=b.observe_once(directory,MARKER,inventory,self.save,lambda _:None,current_boot_uuid='other')
                self.assertEqual(mismatch,{'optional_inventory_status':'scope_mismatch'}); self.assertEqual(calls,[1])
                changed={**MARKER,'source_identity':'f'*64}
                self.assertEqual(b.observe_once(directory,changed,inventory,self.save,lambda _:None,current_boot_uuid='B2'),{'optional_inventory_status':'scope_mismatch'})
                self.assertEqual(calls,[1])
                (directory/'debug-boot-inventory-result.json').unlink()
                self.assertEqual(b.observe_once(directory,MARKER,inventory,self.save,lambda _:None,current_boot_uuid='B2'),{'optional_inventory_status':'uncertain'})
                self.assertEqual(calls,[1])

    def test_critical_inventory_rejects_cached_extra_before_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); scope={'marker':MARKER,'current_boot_uuid':'B2'}
            self.save(directory/'debug-boot-inventory-started.json',json.dumps(scope).encode())
            invalid={'status':'observed','value':0x102000,'raw':'must not be dropped into success'}
            self.save(directory/'debug-boot-inventory-result.json',json.dumps({'scope':scope,'facts':{'kernel_debug_state':{'debug_boot_arg':invalid}}}).encode())
            def forbidden(*args,**kwargs): self.fail('cached record triggered kernel read')
            with self.assertRaises(ValueError):
                b.observe_once(directory,MARKER,b.KernelMaskInventory(read=forbidden),self.save,lambda _:None,current_boot_uuid='B2')

    def test_kernel_field_parser_requires_exact_typed_marker_and_cli_one_lf(self):
        self.assertEqual(b.parse_kernel_field('debug_boot_arg',b'VZKSTATE v1 debug_boot_arg u32 8192\n\n'),8192)
        self.assertEqual(b.parse_kernel_field('dtrace_destructive_disallow',b'VZKSTATE v1 dtrace_destructive_disallow i32 -1\n\n'),-1)
        self.assertIs(b.parse_kernel_field('coprocessor_paniclog_flush',b'VZKSTATE v1 coprocessor_paniclog_flush bool 1\n\n'),True)
        for raw in (b'8192\n\n',b'VZKSTATE v1 debug_boot_arg u32 8192\n',b'VZKSTATE v1 debug_boot_arg u32 8192\n\n\n',
                    b'VZKSTATE v1 other u32 8192\n\n',b'VZKSTATE v1 debug_boot_arg i32 8192\n\n',
                    b'VZKSTATE v1 debug_boot_arg u32 08192\n\n',b'VZKSTATE v1 debug_boot_arg u32 4294967296\n\n',
                    b'VZKSTATE v1 debug_boot_arg u32 -1\n\n',b'VZKSTATE v1 debug_boot_arg u32 8192\r\n\r\n'):
            with self.assertRaises(ValueError): b.parse_kernel_field('debug_boot_arg',raw)
        for name, kind, minimum, maximum in (('debug_boot_arg','u32',0,4294967295),
                ('dtrace_destructive_disallow','i32',-2147483648,2147483647),
                ('coprocessor_paniclog_flush','bool',0,1)):
            for value in (minimum,maximum):
                raw=('VZKSTATE v1 '+name+' '+kind+' '+str(value)+'\n\n').encode()
                self.assertEqual(b.parse_kernel_field(name,raw),value)
            for value in (minimum-1,maximum+1):
                raw=('VZKSTATE v1 '+name+' '+kind+' '+str(value)+'\n\n').encode()
                with self.assertRaises(ValueError): b.parse_kernel_field(name,raw)
        for name in ('unknown',True,None):
            with self.assertRaises(ValueError): b.kernel_field_program(name)
        source=b.kernel_field_program('dtrace_destructive_disallow')
        self.assertIn('dtrace:::ERROR { exit(1); }',source)
        self.assertIn('(int32_t)`dtrace_destructive_disallow',source)
        self.assertNotIn('*(',source)
        self.assertNotIn('panic()',source)

    def test_native_failed_reader_never_publishes_zero(self):
        import subprocess
        def read(argv,limit,timeout,*,capture_stderr=False):
            self.assertTrue(capture_stderr)
            self.assertEqual(argv[:5],['/usr/sbin/dtrace','-q','-x','errtags','-n'])
            name=next(name for name in b.KERNEL_FIELDS if 'VZKSTATE v1 '+name+' ' in argv[-1])
            self.assertEqual((limit,timeout),(4096,30 if name=='debug_boot_arg' else 5))
            kind=b.KERNEL_FIELDS[name][1]
            raw='VZKSTATE v1 '+name+' '+kind+' 0\n\n'
            return b.capture([sys.executable,'-c','import sys; sys.stdout.write('+repr(raw)+'); sys.exit(1)'],limit,timeout)
        result=b.kernel_debug_state(read=read)
        self.assertEqual(set(result),set(b.KERNEL_FIELDS))
        self.assertTrue(all(value['status']=='unavailable' and value['error']['exit_code']==1 for value in result.values()))

    def test_kernel_debug_state_has_only_allowed_numeric_fields(self):
        def capture(argv, *_args, **_kwargs):
            source = argv[-1]
            if "`debug_boot_arg" in source:
                return b"VZKSTATE v1 debug_boot_arg u32 8192\n\n"
            if "`kdp_flag" in source:
                return b"VZKSTATE v1 kdp_flag u32 129\n\n"
            raise OSError("static symbol unavailable")
        with patch.object(b, "capture", capture):
            facts = b.kernel_debug_state()
        unavailable={'status':'unavailable','error':{'reason':'os_error','exit_code':None,'output_bytes':None,'output_sha256':None,'tags':[]}}
        expected={name:unavailable for name in b.KERNEL_FIELDS}
        expected.update(debug_boot_arg={'status':'observed','value':8192},kdp_flag={'status':'observed','value':129})
        self.assertEqual(facts,expected)
        with patch.object(b, "capture", lambda *_args, **_kwargs: b"secret"):
            invalid = b.kernel_debug_state()
        self.assertTrue(all(value["status"] == "invalid" and value["error"]["reason"] == "output_invalid" for value in invalid.values()))
        self.assertNotIn("secret", str(invalid))

    def test_observation_save_failure_still_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            def save(path, data):
                if path.name == "debug-boot-observed.json":
                    raise OSError("observation storage unavailable")
                self.save(path, data)
            with self.assertRaises(OSError):
                b.finish(directory, marker, platform, save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(platform.value, original)
            self.assertTrue(json.loads((directory / "debug-boot-restored.json").read_text())["nvram_restored"])

    def test_active_distinguishes_empty_output_from_empty_bootargs(self):
        with patch.object(b, "capture", lambda *_args, **_kwargs: b""):
            with self.assertRaises(ValueError):
                b.MacPlatform().active()
        with patch.object(b, "capture", lambda *_args, **_kwargs: b"\n"):
            self.assertEqual(b.MacPlatform().active(), b"")

    def test_core_finish_does_not_run_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({"boot-args": "preempt=10"})
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.events.clear()
            facts = b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new", inventory=False)
            self.assertTrue(facts["nvram_restored"])
            self.assertNotIn("inventory", platform.events)

    def test_optional_inventory_started_marker_prevents_reexecution(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, marker = Path(tmp), dict(MARKER)
            platform = Platform({})
            original_inventory = platform.inventory
            def inventory():
                saved = json.loads((directory / "debug-boot-inventory-started.json").read_text())
                self.assertEqual(saved, {"marker": marker, "current_boot_uuid": "new"})
                return original_inventory()
            with patch.object(platform, "inventory", inventory):
                b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(platform.events, ["inventory"])
            (directory / "debug-boot-inventory-result.json").unlink()
            facts = b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="new")
            self.assertEqual(facts["optional_inventory_status"], "uncertain")
            self.assertEqual(platform.events, ["inventory"])
            facts = b.observe_once(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="future")
            self.assertEqual(facts["optional_inventory_status"], "scope_mismatch")
            self.assertEqual(platform.events, ["inventory"])

    def test_saved_observation_cannot_be_reused_for_another_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, original = Path(tmp), {"boot-args": "preempt=10"}
            platform, marker = Platform(original), dict(MARKER)
            b.stage(directory, marker, platform, self.save, lambda _p: None)
            platform.active_value = b"debug=0x2000"
            b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="first")
            self.assertEqual(platform.value, original)
            platform.active_value = b"preempt=10"
            with self.assertRaises(ValueError):
                b.finish(directory, marker, platform, self.save, lambda _p: None, current_boot_uuid="second")


if __name__ == "__main__":
    unittest.main()
