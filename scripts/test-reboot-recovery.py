import importlib.util
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("reboot-recovery.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Recovery(unittest.TestCase):
    def test_netdump_private_plan_binds_the_boot_mode_and_initial_profile(self):
        n = r.recovery_netdump
        ctx = {'run_id': '123', 'attempt': '1', 'sha': 'a' * 40, 'after_debug_boot': 'netdump-prime'}
        core, network = n.source_identity(r.__file__)
        profile = r.recovery_bootargs.boot_argument_profile('preempt=1')
        baseline = n.BootBaseline.from_profile('11111111-1111-1111-1111-111111111111', profile)
        offer = n.ReceiverOffer(r.binding(ctx), 'c' * 32, n.Endpoint('1.1.1.1', 10248), 43210,
                                'f' * 64, core, network, 'prime')
        settings = r.recovery_netdump_settings.NetdumpSettings('1.1.1.1', '192.168.64.1', 10248, 'b' * 16)
        plan = n.DiscoveryPlan(offer, 'b' * 64, n.Endpoint('8.8.8.8', 40000), '192.168.64.2', 'en0',
                               settings, n.HelloStats(True, True, 10), baseline)
        config = {'context': ctx, 'netdump_plan': plan.record(), 'nonce': plan.nonce,
                  'baseline': baseline.baseline_boot_uuid, 'cert_fingerprint': 'f' * 64,
                  'initial_boot_argument_profile': profile}
        self.assertEqual(r.netdump_plan(config), plan)
        for field, value in (('nonce', 'd' * 64), ('baseline', '22222222-2222-2222-2222-222222222222'),
                              ('cert_fingerprint', 'e' * 64), ('initial_boot_argument_profile', {'status': 'unavailable'})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.netdump_plan({**config, field: value})

    def test_netdump_prime_does_not_start_when_boot_restore_is_unproven(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            result = r.run_netdump_prime_once(directory, {'context': {'after_debug_boot': 'netdump-prime'}},
                                               'new', {}, 'token', 100)
            self.assertEqual(result, {'status': 'invalid'})
            self.assertEqual(list(directory.iterdir()), [])

    def test_netdump_prime_boot_success_requires_the_receiver_proof(self):
        ctx = {'run_id': '123', 'attempt': '1', 'sha': 'a' * 40, 'debug_source': 'bootplist',
               'debug_boot': True, 'trigger': 'reboot-quick', 'after_debug_boot': 'netdump-prime'}
        current = '22222222-2222-2222-2222-222222222222'
        facts = {'active_debug_mask': 0x22040, 'active_bootargs_status': 'observed_debug', 'current_boot_uuid': current,
                 'bootplist_restored': True, 'bootplist_file_states': {'data': 'staged', 'preboot': 'staged'},
                 'bootplist_restore': {name: {'bytes': True, 'metadata': True, 'timestamps': True} for name in ('data', 'preboot')}}
        pending = {'nonce': 'b' * 64, 'baseline_boot_uuid': '11111111-1111-1111-1111-111111111111',
                   'cert_fingerprint': 'c' * 64, 'check_id': 17}
        data = {'current_boot_uuid': current, 'debug_boot_facts': facts}
        self.assertTrue(r.debug_boot_proven(facts, 'bootplist', 0x22040))
        self.assertFalse(r.debug_lineage_matches(data, pending, ctx))
        facts['netdump_prime'] = {'status': 'verified', 'proof': {}}
        self.assertFalse(r.debug_lineage_matches(data, pending, ctx))

    def test_netdump_prime_is_a_certificate_bound_boot_control_without_panic(self):
        ctx = {'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
               'runner_environment': 'github-hosted', 'run_id': '123', 'attempt': '1', 'sha': 'a' * 40,
               'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'bootplist', 'after_debug_boot': 'netdump-prime'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.netdump_prime(ctx))
        self.assertEqual(r.expected_debug_mask(ctx), 0x22040)
        self.assertTrue(r.certificate_required(ctx))
        self.assertFalse(r.report_required(ctx))
        self.assertFalse(r.panic_followup(ctx))
        for change in ({'trigger': 'reboot'}, {'trigger': 'panic-control'}, {'debug_boot': False}, {'debug_source': 'nvram'}):
            self.assertFalse(r.valid_context({**ctx, **change}, 'Darwin', 'x86_64', r.KERNEL_UUID))

    def test_runtime_watch_identity_and_check_are_strict(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        check = {'id': 17, 'name': 'Runtime heartbeat 123', 'head_sha': 'a' * 40,
                 'external_id': r.runtime_watch_external(identity),
                 'app': {'id': 15368, 'slug': 'github-actions'},
                 'details_url': 'https://github.com/Code-Hex/vz-ci-test/runs/17'}
        self.assertTrue(r.runtime_watch_check(check, identity, 17))
        for change in ({'id': 18}, {'head_sha': 'b' * 40}, {'external_id': 'other'},
                       {'name': 'Runner recovery 123'}, {'app': {'id': 1, 'slug': 'github-actions'}}):
            self.assertFalse(r.runtime_watch_check({**check, **change}, identity, 17))
        with self.assertRaises(ValueError):
            r.runtime_watch_identity(config, {**saved['scope'], 'debug_boot_uuid': config['baseline']}, 'f' * 64)

    def test_runtime_watch_release_requires_exact_trigger(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        release = {'scope': saved['scope'], 'helper_sha256': 'f' * 64,
                   'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        raw = r.json.dumps(release).encode()
        self.assertEqual(r.runtime_watch_release(raw, raw, identity), r.hashlib.sha256(raw).hexdigest())
        for change in ({'ready': False}, {'helper_pid': True}, {'tracer_pid': 123},
                       {'helper_sha256': '0' * 64}, {'extra': 'private'},
                       {'scope': {**saved['scope'], 'nonce': '0' * 64}}):
            with self.assertRaises(ValueError):
                r.runtime_watch_release(r.json.dumps({**release, **change}).encode(), raw, identity)
        with self.assertRaises(ValueError):
            r.runtime_watch_release(raw, b'{}', identity)

    def test_runtime_watch_stage_needs_local_release_evidence(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'panic-control').mkdir()
            before = ('before_release', None)
            self.assertEqual(r.runtime_watch_stage(directory, identity, before), before)
            record = {'scope': saved['scope'], 'helper_sha256': 'f' * 64,
                      'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
            raw = r.json.dumps(record).encode()
            r.private_write(directory / 'panic-control' / 'release-attempt.json', raw)
            r.private_write(directory / 'panic-followup-trigger.json', raw)
            observed = r.runtime_watch_stage(directory, identity, before)
            self.assertEqual(observed, ('release_observed', r.hashlib.sha256(raw).hexdigest()))
            (directory / 'panic-control' / 'release-attempt.json').unlink()
            self.assertEqual(r.runtime_watch_stage(directory, identity, observed), observed)
            r.private_write(directory / 'panic-control' / 'release-attempt.json', b'{}')
            self.assertEqual(r.runtime_watch_stage(directory, identity, before), ('invalid', None))

    def test_runtime_watch_ready_requires_same_live_child_and_budget(self):
        config, saved, _b3 = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        receipt = {'identity': identity, 'check_id': 17, 'pid': 123, 'started_monotonic': 10.0,
                   'deadline_monotonic': 130.0, 'acknowledged': True}
        self.assertEqual(r.runtime_watch_ready(receipt, identity, 123, 9.0, 20.0), 130.0)
        for change in ({'pid': 456}, {'acknowledged': False}, {'deadline_monotonic': float('inf')},
                       {'check_id': True}, {'identity': {**identity, 'helper_sha256': '0' * 64}}):
            with self.assertRaises(ValueError):
                r.runtime_watch_ready({**receipt, **change}, identity, 123, 9.0, 20.0)
        with self.assertRaises(ValueError):
            r.runtime_watch_ready(receipt, identity, 123, 9.0, 71.0)

    def test_runtime_watch_ready_accepts_fractional_producer_deadlines(self):
        config, saved, _ = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        for started in (17.000000001, 27.123456789, 42.123456789, 72.123456789, 1024.0001):
            receipt = {'identity': identity, 'check_id': 17, 'pid': 123, 'started_monotonic': started,
                       'deadline_monotonic': started + 120, 'acknowledged': True}
            with self.subTest(started=started):
                self.assertEqual(r.runtime_watch_ready(receipt, identity, 123, started - .1, started + .1), started + 120)

    def test_runtime_watch_ready_is_published_complete_and_never_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            receipt = {'acknowledged': True, 'identity': {'fixture': 'complete'}}
            real_write = r.private_write
            def write(path, data):
                self.assertIn(path.name, ('runtime-watch-ready.pending.json', 'runtime-watch-ready.claim.json'))
                self.assertFalse((directory / 'runtime-watch-ready.json').exists())
                real_write(path, data)
            with patch.object(r, 'private_write', write):
                r.publish_runtime_watch_ready(directory, receipt)
            target = directory / 'runtime-watch-ready.json'
            self.assertEqual(r.json.loads(target.read_bytes()), receipt)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse((directory / 'runtime-watch-ready.pending.json').exists())
            with self.assertRaises(ValueError):
                r.publish_runtime_watch_ready(directory, {'replacement': True})
            self.assertEqual(r.json.loads(target.read_bytes()), receipt)

    def test_runtime_watch_retries_an_incomplete_release_observation(self):
        config, saved, _ = self.followup_fixture()
        identity = r.runtime_watch_identity(config, saved['scope'], 'f' * 64)
        release = {'scope': saved['scope'], 'helper_sha256': 'f' * 64, 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        raw = r.json.dumps(release).encode()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'panic-control').mkdir()
            path = directory / 'panic-control' / 'release-attempt.json'
            r.private_write(path, b'{')
            r.private_write(directory / 'panic-followup-trigger.json', raw)
            partial = r.runtime_watch_stage(directory, identity, ('before_release', None))
            self.assertEqual(partial, ('invalid', None))
            path.write_bytes(raw)
            self.assertEqual(r.runtime_watch_stage(directory, identity, partial), ('release_observed', r.hashlib.sha256(raw).hexdigest()))

    def test_runtime_watch_reaper_waits_for_a_real_child(self):
        child = subprocess.Popen([r.sys.executable, '-c', 'pass'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        waiter = r.reap_runtime_watch(child)
        waiter.join(3)
        self.assertTrue(waiter.daemon)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(child.returncode, 0)

    def test_runtime_watch_failure_prevents_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            events = []
            def prepare(*_args):
                (directory / 'panic-control').mkdir()
                return {'helper_sha256': 'f' * 64}
            def unavailable(*_args):
                events.append('watch_failed')
                raise TimeoutError('not ready')
            with patch.object(r.recovery_panic_control, 'prepare', prepare), \
                    patch.object(r, 'publish_followup', lambda *_a: events.append('prepared_ack')), \
                    patch.object(r, 'start_runtime_watch', unavailable), \
                    patch.object(r.recovery_panic_control, 'fire', lambda *_a: self.fail('watch failure reached fire')), \
                    patch.object(r, 'complete_recovery', lambda *_a: events.append('reported')):
                r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertEqual(events, ['prepared_ack', 'watch_failed', 'reported'])
            self.assertFalse((directory / 'panic-followup-trigger.json').exists())

    def test_runtime_watch_budget_is_checked_after_intent_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            events = []
            def prepare(*_args):
                (directory / 'panic-control').mkdir()
                return {'helper_sha256': 'f' * 64}
            def publish(_d, _c, _t, summary, _title):
                events.append(summary['phase'])
            def alive(_watch, minimum=60):
                self.assertIn(minimum, (60, 30))
                return 'panic_intent' not in events
            def fire(_d, scope, prepared, _save, _sync, on_ready, _boot):
                trigger = {'scope': scope, 'helper_sha256': prepared['helper_sha256'],
                           'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
                self.assertFalse(on_ready(trigger))
                self.assertFalse((directory / 'panic-control' / 'release-attempt.json').exists())
                events.append('not_released')
                return {'phase': 'not_released'}
            with patch.object(r.recovery_panic_control, 'prepare', prepare), patch.object(r.recovery_panic_control, 'fire', fire), \
                    patch.object(r, 'publish_followup', publish), patch.object(r, 'start_runtime_watch', lambda *_a: object()), \
                    patch.object(r, 'runtime_watch_alive', alive), patch.object(r, 'boot_uuid', lambda: saved['scope']['debug_boot_uuid']), \
                    patch.object(r, 'complete_recovery', lambda *_a: events.append('reported')):
                r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertEqual(events, ['panic_prepared', 'panic_intent', 'not_released', 'reported'])

    def test_boot_argument_profiles_keep_first_scoped_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            config['initial_boot_argument_profile'] = r.recovery_bootargs.boot_argument_profile('alpha=1 beta=2')
            current = saved['scope']['debug_boot_uuid']
            with patch.object(r, 'observe_boot_argument_profile', lambda: r.recovery_bootargs.boot_argument_profile('alpha=1 debug=0x102000 beta=2')):
                first = r.postboot_argument_profiles(directory, config, current)
            self.assertIs(first['nondebug_equal'], True)
            with patch.object(r, 'observe_boot_argument_profile', lambda: self.fail('observation was repeated')):
                self.assertEqual(r.postboot_argument_profiles(directory, config, current), first)
            self.assertEqual(r.postboot_argument_profiles(directory, config, 'C' * 8 + '-CCCC-CCCC-CCCC-' + 'C' * 12)['postboot'], {'status': 'invalid'})
            self.assertNotIn('alpha', (directory / 'boot-argument-observation.json').read_text())

    def test_boot_argument_observation_failure_does_not_claim_equality(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            config['initial_boot_argument_profile'] = r.recovery_bootargs.boot_argument_profile('alpha=1')
            with patch.object(r, 'observe_boot_argument_profile', lambda: {'status': 'unavailable'}):
                result = r.postboot_argument_profiles(directory, config, saved['scope']['debug_boot_uuid'])
            self.assertIsNone(result['nondebug_equal'])
            self.assertEqual(result['postboot'], {'status': 'unavailable'})
            (directory / 'boot-argument-observation.json').write_text('{broken')
            self.assertEqual(r.postboot_argument_profiles(directory, config, saved['scope']['debug_boot_uuid'])['postboot'], {'status': 'invalid'})

    def test_boot_argument_storage_failure_still_restores_and_acknowledges(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            current = saved['scope']['debug_boot_uuid']
            config['debug_boot'] = True
            config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
            r.private_write(directory / 'token', b'synthetic-token')
            r.private_write(directory / 'ready.json', r.json.dumps({'baseline': config['baseline'], 'nonce': config['nonce'], 'preboot_patch': True}).encode())
            original_write = r.private_write
            events = []
            def write(path, data):
                if path.name in ('boot-argument-observation.json', 'nvram-paniclog-control.json'):
                    raise OSError('synthetic storage failure')
                original_write(path, data)
            def finish(*_args, **_kwargs):
                events.append('restore')
                return dict(saved['facts'])
            def core(_directory, _config, _current, facts, _token):
                self.assertEqual(facts['boot_argument_profiles']['postboot'], {'status': 'invalid'})
                self.assertIsNone(facts['boot_argument_profiles']['nondebug_equal'])
                self.assertEqual(facts['nvram_paniclog_control'], {'status': 'invalid'})
                self.assertFalse(r.nvram_off_control_proven(facts))
                events.append('ack')
                return facts
            with patch.object(r, 'load_config', lambda _: config), patch.object(r, 'boot_uuid', lambda: current), \
                    patch.object(r, 'observe_boot_argument_profile', lambda: {'status': 'unavailable'}), \
                    patch.object(r.recovery_bootargs.MacPlatform, 'active', lambda _: 'alpha=1 nvram_paniclog=0 debug=0x102000'), \
                    patch.object(r, 'private_write', write), patch.object(r.recovery_bootplist, 'finish', finish), \
                    patch.object(r, 'publish_debug_core', core), patch.object(r, 'followup_start', lambda *_: events.append('followup')):
                r.collect(directory)
            self.assertEqual(events, ['restore', 'ack', 'followup'])

    def test_boot_argument_profile_boundary_rejects_raw_and_invalid_scalars(self):
        valid = r.recovery_bootargs.boot_argument_profile('alpha=1')
        for extra in ({'raw': 'private argument'}, {'debug_mask': True}, {'nondebug_token_count': True},
                      {'nondebug_token_count': -1}, {'nondebug_sha256': 'private argument'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                r.checked_boot_argument_profile({**valid, **extra})

    def test_runtime_watch_ready_timeout_reaps_its_own_child_before_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _ = self.followup_fixture()
            config['python'] = str(Path(r.sys.executable).resolve())
            (directory / 'panic-control').mkdir()
            child = subprocess.Popen([r.sys.executable, '-c', 'import time; time.sleep(60)'])
            try:
                with patch.object(r, 'runtime_watch_executable_matches', lambda *_: True), \
                        patch.object(r.subprocess, 'Popen', lambda *_args, **_kwargs: child), \
                        patch.object(r.time, 'monotonic', side_effect=[0, 26]):
                    with self.assertRaises(TimeoutError):
                        r.start_runtime_watch(directory, config, saved['scope'], {'helper_sha256': 'f' * 64})
                self.assertIsNotNone(child.poll())
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait()

    def test_runtime_watch_accepts_the_same_copied_script_through_a_directory_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / 'real'
            real.mkdir()
            (real / 'recovery.py').write_text('same script')
            alias = Path(tmp) / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            python = str(Path(r.sys.executable).resolve())
            with patch.object(r, '__file__', str(real / 'recovery.py')):
                self.assertTrue(r.runtime_watch_executable_matches(alias, python))
                self.assertFalse(r.runtime_watch_executable_matches(Path(tmp), python))
                self.assertFalse(r.runtime_watch_executable_matches(alias, '/unrelated/python'))

    def test_nvram_off_mode_is_bound_and_requires_the_exact_control_token(self):
        config, saved, _ = self.followup_fixture()
        ctx = {**config['context'], 'after_debug_boot': 'panic-nonce-nvram-off', 'actions': 'true', 'repo': r.REPO,
               'ref': 'refs/heads/main', 'event': 'workflow_dispatch', 'runner_environment': 'github-hosted'}
        self.assertTrue(r.valid_context(ctx, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.panic_followup(ctx))
        self.assertEqual(r.expected_debug_mask(ctx), 0x102000)
        initial = r.recovery_bootargs.boot_argument_profile('alpha=1 beta=2')
        active = 'alpha=1 beta=2 nvram_paniclog=0 debug=0x102000'
        control = r.parse_nvram_off_control(active)
        facts = {**saved['facts'], 'boot_argument_profiles': {'initial': initial,
                 'postboot': r.recovery_bootargs.boot_argument_profile(active)}, 'nvram_paniclog_control': control}
        self.assertTrue(r.nvram_off_control_proven(facts))
        for raw in ('alpha=1 beta=2 debug=0x102000', 'alpha=1 beta=2 -nvram_paniclog=0 debug=0x102000',
                    'alpha=1 beta=2 nvram_paniclog=0 nvram_paniclog=0 debug=0x102000',
                    'alpha=1 beta=2 nvram_paniclog=1 debug=0x102000'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                r.parse_nvram_off_control(raw)
        for changed in ('beta=2 alpha=1 nvram_paniclog=0 debug=0x102000',
                        'alpha=1 beta=2 extra=1 nvram_paniclog=0 debug=0x102000'):
            changed_control = r.parse_nvram_off_control(changed)
            self.assertFalse(r.nvram_off_control_proven({**facts, 'nvram_paniclog_control': changed_control,
                'boot_argument_profiles': {'initial': initial, 'postboot': changed_control['full_profile']}}))
        for bad in ({'status': 'unavailable'}, {'status': 'invalid'}, {**control, 'raw': 'private'}):
            self.assertFalse(r.nvram_off_control_proven({**facts, 'nvram_paniclog_control': bad}))

    def test_nvram_off_observation_is_immutable_and_bound_to_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _ = self.followup_fixture()
            config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
            current = saved['scope']['debug_boot_uuid']
            with patch.object(r.recovery_bootargs.MacPlatform, 'active', lambda _: 'alpha=1 nvram_paniclog=0 debug=0x102000'):
                first = r.postboot_paniclog_control(directory, config, current)
            self.assertEqual(first['status'], 'observed')
            with patch.object(r.recovery_bootargs.MacPlatform, 'active', lambda _: self.fail('repeated control read')):
                self.assertEqual(r.postboot_paniclog_control(directory, config, current), first)
            config['context']['after_debug_boot'] = 'panic-nonce'
            self.assertEqual(r.postboot_paniclog_control(directory, config, current), {'status': 'invalid'})

    def test_nvram_off_proof_is_required_by_replay_and_controller(self):
        config, saved, b3 = self.followup_fixture()
        config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
        initial = r.recovery_bootargs.boot_argument_profile('alpha=1')
        control = r.parse_nvram_off_control('alpha=1 nvram_paniclog=0 debug=0x102000')
        facts = {**saved['facts'], 'nvram_paniclog_control': control,
                 'boot_argument_profiles': {'initial': initial, 'postboot': control['full_profile']}}
        trigger = {'scope': saved['scope'], 'helper_sha256': 'f' * 64, 'helper_pid': 123, 'tracer_pid': 456, 'ready': True}
        pending = {'nonce': config['nonce'], 'baseline_boot_uuid': config['baseline']}
        data = {'debug_boot_facts': facts, 'debug_boot_uuid': saved['scope']['debug_boot_uuid'],
                'current_boot_uuid': b3, 'panic_trigger': trigger}
        self.assertTrue(r.debug_lineage_matches(data, pending, config['context']))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            target = directory / 'panic-followup-debug.json'
            target.write_text(r.json.dumps({'scope': saved['scope'], 'facts': facts}))
            self.assertEqual(r.read_followup_debug(directory, config)['facts'], facts)
            missing = {k: v for k, v in facts.items() if k != 'nvram_paniclog_control'}
            target.write_text(r.json.dumps({'scope': saved['scope'], 'facts': missing}))
            with self.assertRaises(ValueError):
                r.read_followup_debug(directory, config)
            self.assertFalse(r.debug_lineage_matches({**data, 'debug_boot_facts': missing}, pending, config['context']))

    def test_nvram_off_missing_proof_prevents_prepare_and_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _ = self.followup_fixture()
            config['context']['after_debug_boot'] = 'panic-nonce-nvram-off'
            completed = []
            def forbidden(*_args, **_kwargs):
                self.fail('unproven NVRAM logging control reached prepare or fire')
            with patch.object(r.recovery_panic_control, 'prepare', forbidden), patch.object(r.recovery_panic_control, 'fire', forbidden), \
                    patch.object(r, 'complete_recovery', lambda *_a: completed.append(True)):
                r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertEqual(completed, [True])
            self.assertFalse((directory / 'panic-control' / 'intent.json').exists())

    def test_debug_source_context_is_explicit_and_bound(self):
        base = {'actions': 'true', 'repo': r.REPO, 'ref': 'refs/heads/main', 'event': 'workflow_dispatch',
                'runner_environment': 'github-hosted', 'run_id': '123', 'attempt': '1', 'sha': 'a' * 40,
                'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'nvram'}
        self.assertTrue(r.valid_context(base, 'Darwin', 'x86_64', r.KERNEL_UUID))
        self.assertTrue(r.valid_context({**base, 'debug_source': 'bootplist'}, 'Darwin', 'x86_64', r.KERNEL_UUID))
        missing = {key: value for key, value in base.items() if key != 'debug_source'}
        for invalid in (missing, {**base, 'debug_source': 'unknown'},
                        {**base, 'debug_source': 'bootplist', 'debug_boot': False},
                        {**base, 'debug_source': 'bootplist', 'trigger': 'reboot'}):
            self.assertFalse(r.valid_context(invalid, 'Darwin', 'x86_64', r.KERNEL_UUID))
        data = {'trigger': 'reboot-quick', 'debug_boot': True, 'debug_source': 'nvram'}
        self.assertTrue(r.mode_matches(data, {}, base))
        self.assertFalse(r.mode_matches({key: value for key, value in data.items() if key != 'debug_source'}, {}, base))
        self.assertFalse(r.mode_matches({**data, 'debug_source': 'bootplist'}, {}, base))

    def cleanup_cli(self, *, check_id="126520221299", token="test-job-token", status="in_progress", system="Linux", repo="Code-Hex/vz-ci-test"):
        old_sha = "a" * 40
        check = {"id": 126520221299, "name": "Runner recovery 41814026408", "head_sha": old_sha,
                 "external_id": "41814026408/1/" + old_sha, "app": {"slug": "github-actions", "id": 15368},
                 "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/126520221299", "status": status}
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": repo, "GITHUB_RUN_ID": "999",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b" * 40, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
               "GITHUB_TOKEN": token, "RECOVERY_CLEANUP_CHECK_ID": check_id}
        calls = []

        def api(method, url, credential, payload=None):
            self.assertEqual(credential, token)
            self.assertEqual(url, r.CHECKS + "/126520221299")
            calls.append((method, payload))
            if method == "GET":
                return check
            self.assertEqual(method, "PATCH")
            return {}

        def command(command):
            return {("/usr/bin/uname", "-s"): system, ("/usr/bin/uname", "-m"): "x86_64",
                    ("/usr/sbin/sysctl", "-n", "kern.uuid"): r.KERNEL_UUID}[tuple(command)]

        def forbidden(*_args, **_kwargs):
            self.fail("cleanup entered controller or sudo path")

        with patch.dict(os.environ, env, clear=True), patch.object(r.sys, "argv", ["reboot-recovery.py", "cleanup"]), \
                patch.object(r, "api", api), patch.object(r, "command_output", command), \
                patch.object(r, "controller", forbidden), patch.object(r, "sudo_call", forbidden), \
                contextlib.redirect_stdout(io.StringIO()):
            r.main()
        return calls

    def test_cleanup_cli_only_cancels_verified_old_check(self):
        self.assertEqual(self.cleanup_cli(), [("GET", None), ("PATCH", {
            "status": "completed", "conclusion": "cancelled",
            "output": {"title": "Prior recovery attempt cancelled", "summary": "Superseded recovery attempt."}})])

    def test_cleanup_cli_completed_check_needs_no_patch(self):
        self.assertEqual(self.cleanup_cli(status="completed"), [("GET", None)])

    def test_cleanup_cli_requires_token_id_and_linux_context(self):
        for options in ({"token": ""}, {"check_id": ""}, {"check_id": "../126520221299"},
                        {"system": "Darwin"}, {"repo": "other"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.cleanup_cli(**options)

    def test_guard(self):
        ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "2",
               "sha": "a" * 40, "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        for key, value in [("actions", "false"), ("repo", "other"), ("run_id", "../1"),
                           ("attempt", "0"), ("sha", "bad"), ("event", "push")]:
            self.assertFalse(r.valid_context(dict(ctx, **{key: value}), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(ctx, "Darwin", "arm64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(ctx, "Darwin", "x86_64", "bad"))

    def test_force_preflight_errors_are_whitelisted(self):
        self.assertEqual(r.safe_force_preflight_error('secret\n{"event":"force_reset_guard_failed","token":"secret"}'), {"event": "force_reset_guard_failed"})
        self.assertEqual(r.safe_force_preflight_error('{"event":"force_reset_symbol_unavailable"}'), {"event": "force_reset_symbol_unavailable"})
        self.assertIsNone(r.safe_force_preflight_error('{"event":"secret"}'))
        self.assertIsNone(r.safe_force_preflight_error('{"event":[]}'))

    def test_force_return_diagnostic_is_numeric_and_redacted(self):
        text = 'secret\n{"event":"force_reset_unexpected_return","result":-1,"errno":1,"token":"secret"}\n'
        self.assertEqual(r.safe_force_return(text), {"event": "force_reset_unexpected_return", "result": -1, "errno": 1})
        self.assertIsNone(r.safe_force_return('{"event":"force_reset_unexpected_return","result":"secret","errno":1}'))
        self.assertIsNone(r.safe_force_return('secret'))

    def test_quick_trigger_and_return_facts_are_bound_and_redacted(self):
        ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1", "sha": "a" * 40,
               "ref": "refs/heads/main", "event": "workflow_dispatch", "runner_environment": "github-hosted",
               "trigger": "reboot-quick", "debug_boot": False}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, debug_boot=True), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.panic_mode(ctx))
        fact = r.safe_quick_return('raw-secret\n{"event":"quick_reboot_unexpected_return","result":-1,"errno":1,"token":"raw-secret"}')
        self.assertEqual(fact, {"event": "quick_reboot_unexpected_return", "result": -1, "errno": 1})
        self.assertIsNone(r.safe_quick_return('{"event":"quick_reboot_unexpected_return","result":true,"errno":1}'))
        self.assertFalse(r.mode_matches({"debug_source": "nvram", "trigger": "reboot"}, {}, ctx))
        pending = {"nonce": "n", "baseline_boot_uuid": "old"}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx),
                "nonce": "n", "baseline_boot_uuid": "old", "current_boot_uuid": "new", "trigger": "reboot-quick"}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, phase="quick_prepared"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, phase="quick_intent"), pending, ctx))

    def test_quick_main_only_routes_to_root_rpc(self):
        calls = []
        def sudo(operation, *_args, **kwargs):
            calls.append((operation, kwargs["timeout"]))
            return ""
        def forbidden(*_args, **_kwargs):
            self.fail("quick trigger used the normal reboot path")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "trigger"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot-quick", "debug_boot": False}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, [("quick-execute-root", 90)])

    def test_debug_quick_parent_only_requests_launchd_owner(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return ""
        def forbidden(*_args, **_kwargs):
            self.fail("debug quick parent directly executed reset")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "trigger"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot-quick", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                patch.object(r.time, "sleep", lambda seconds: calls.append(("wait", seconds))), contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root", ("wait", 90)])

    def test_quick_prepared_ack_precedes_execute_and_return_completes_failure(self):
        for acknowledged in (True, False):
            with self.subTest(acknowledged=acknowledged), tempfile.TemporaryDirectory() as tmp:
                directory, events, output = Path(tmp), [], io.StringIO()
                ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1", "sha": "a" * 40,
                       "ref": "refs/heads/main", "event": "workflow_dispatch", "runner_environment": "github-hosted",
                       "trigger": "reboot-quick", "debug_boot": False}
                helper = directory / "reboot-quick"
                helper.write_bytes(b"synthetic helper")
                config = {"context": ctx, "baseline": "old", "nonce": "n", "check_id": 9, "cert_fingerprint": "",
                          "helper_sha256": r.hashlib.sha256(helper.read_bytes()).hexdigest()}
                r.private_write(directory / "token", b"private-token")
                initial = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "phase": "armed", "binding": r.binding(ctx), "nonce": "n",
                           "baseline_boot_uuid": "old", "trigger": "reboot-quick", "debug_boot": False, "cert_fingerprint": ""}
                check = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                         "app": {"id": 15368, "slug": "github-actions"}, "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                         "status": "in_progress", "output": {"summary": r.json.dumps(initial)}}
                def api(method, _url, token, payload=None, **_kwargs):
                    self.assertEqual(token, "private-token")
                    if method == "GET":
                        events.append("ack" if "prepared" in events else "get")
                        result = dict(check)
                        if "prepared" in events and not acknowledged:
                            result["status"] = "completed"
                        return result
                    check.update(payload)
                    events.append("failed" if payload.get("status") == "completed" else "prepared")
                    return check
                def run(command, **kwargs):
                    self.assertEqual(command, [str(helper), "preflight"])
                    self.assertTrue((directory / "quick-trigger.json").exists())
                    self.assertEqual(kwargs["env"]["RECOVERY_TRIGGER"], "reboot-quick")
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    events.append("preflight")
                    return subprocess.CompletedProcess(command, 0, '{"event":"quick_reboot_preflight","flags":1024,"permission_verified":false}', '')
                class Child:
                    returncode = 70
                    pid = 1234
                    def communicate(self, timeout):
                        return ('raw-secret\n{"event":"quick_reboot_unexpected_return","result":-1,"errno":1}', '')
                def popen(command, **kwargs):
                    self.assertEqual(command, [str(helper), "execute"])
                    self.assertEqual(events[-1], "ack")
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    events.append("execute")
                    return Child()
                with patch.object(r, "root_only", lambda: None), patch.object(r, "require_context", lambda *_: None), \
                        patch.object(r, "root_dir", lambda _: directory), patch.object(r, "load_config", lambda _: config), \
                        patch.object(r, "verify_root", lambda _: None), patch.object(r, "boot_uuid", lambda: "old"), \
                        patch.object(r.os, "sync", lambda: events.append("sync")), patch.object(r.subprocess, "run", run), \
                        patch.object(r.subprocess, "Popen", popen), patch.object(r, "api", api), contextlib.redirect_stdout(output):
                    with self.assertRaises((RuntimeError, ValueError)):
                        r.quick_execute_root({"context": ctx})
                self.assertEqual(events[:2], ["sync", "preflight"])
                self.assertNotIn("raw-secret", output.getvalue())
                if acknowledged:
                    self.assertEqual(events[-2:], ["execute", "failed"])
                    self.assertEqual(check["conclusion"], "failure")
                else:
                    self.assertNotIn("execute", events)

    def test_root_error_kind_is_whitelisted(self):
        self.assertEqual(r.root_error_kind('noise SECRET\n{"event":"recovery_error","kind":"ValueError"}\n'), "ValueError")
        self.assertEqual(r.root_error_kind('{"event":"recovery_error","kind":"SECRET"}'), "unknown")
        self.assertEqual(r.root_error_kind('{"event":"other","kind":"ValueError"}'), "unknown")
        self.assertEqual(r.root_error_kind('unstructured SECRET'), "unknown")

    def test_force_reset_marker_and_guard(self):
        ctx = {"debug_source": "nvram", "actions": "true", "repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1",
               "sha": "a" * 40, "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted", "trigger": "panic-force-reset"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, trigger="panic-control"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertTrue(r.valid_context(dict(ctx, trigger="reboot"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertFalse(r.valid_context(dict(ctx, trigger="unknown"), "Darwin", "x86_64", r.KERNEL_UUID))
        self.assertEqual(r.force_marker(ctx, "b" * 64), "vz-force-reset:123:1:" + "b" * 64)
        with self.assertRaises(ValueError):
            r.force_marker(ctx, "not-a-nonce")

    def test_only_changed_nonempty_boot_is_recovery(self):
        self.assertFalse(r.reboot_observed("abc", "abc"))
        self.assertFalse(r.reboot_observed("abc", ""))
        self.assertTrue(r.reboot_observed("abc", "def"))

    def test_debug_boot_request_accepts_only_normal_reset_triggers(self):
        self.assertTrue(r.recovery_bootargs.requested("1", "reboot"))
        self.assertTrue(r.recovery_bootargs.requested("1", "reboot-quick"))
        self.assertFalse(r.recovery_bootargs.requested("", "reboot"))
        for value, trigger in (("true", "reboot"), ("1", "panic-control"), ("1", "panic-force-reset")):
            with self.assertRaises(ValueError):
                r.recovery_bootargs.requested(value, trigger)

    def test_debug_boot_proof_requires_mask_restore_and_mode_binding(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True}
        pending = {"nonce": "n", "baseline_boot_uuid": "old"}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx),
                "nonce": "n", "baseline_boot_uuid": "old", "current_boot_uuid": "new", "debug_boot": True,
                "debug_boot_facts": {"active_debug_mask": 0x2000, "active_bootargs_status": "observed_debug", "nvram_restored": True,
                                     "current_boot_uuid": "new",
                                     "debugger_count": None, "nic_inventory_status": "unsupported"}}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        core = dict(data, phase="boot_core")
        self.assertFalse(r.boot_proof_matches(core, pending, ctx))
        for facts in ({}, {"active_debug_mask": 0x2000, "nvram_restored": False},
                      {"active_debug_mask": 0x400, "nvram_restored": True},
                      {"active_debug_mask": 0x2000, "active_bootargs_status": "invalid", "nvram_restored": True}):
            self.assertFalse(r.boot_proof_matches(dict(data, debug_boot_facts=facts), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(data, debug_boot=False), pending, ctx))
        self.assertFalse(r.boot_proof_matches(data, pending, dict(ctx, debug_boot=False)))
        self.assertFalse(r.boot_proof_matches(dict(data, current_boot_uuid="another"), pending, ctx))
        quick_ctx = dict(ctx, trigger="reboot-quick")
        quick_data = dict(data, trigger="reboot-quick")
        self.assertTrue(r.boot_proof_matches(quick_data, pending, quick_ctx))
        self.assertFalse(r.boot_proof_matches(data, pending, quick_ctx))
        self.assertFalse(r.boot_proof_matches(quick_data, pending, ctx))

    def test_debug_parent_shutdown_cannot_restore_or_reboot(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            if operation == "verify-root":
                return "ready"
            self.assertEqual(operation, "debug-request-root")
            raise KeyboardInterrupt()
        def forbidden(*_args, **_kwargs):
            self.fail("runner parent performed debug mutation or reboot")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root"])

    def test_debug_parent_waits_after_request_without_mutation(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return "ready"
        def forbidden(*_args, **_kwargs):
            self.fail("runner parent mutated debug state")
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot", "debug_boot": True}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", forbidden), patch.object(r.subprocess, "run", forbidden), \
                patch.object(r.time, "sleep", lambda seconds: calls.append(("wait", seconds))), contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, ["verify-root", "debug-request-root", ("wait", 90)])

    def test_bootplist_proof_requires_file_restoration(self):
        facts = {"active_debug_mask": 0x2000, "active_bootargs_status": "observed_debug",
                 "nvram_restored": True}
        self.assertTrue(r.debug_boot_proven(facts, "nvram"))
        self.assertFalse(r.debug_boot_proven(facts, "bootplist"))
        facts.pop("nvram_restored")
        facts.update({"bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "original"},
                      "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}})
        self.assertTrue(r.debug_boot_proven(facts, "bootplist"))
        self.assertFalse(r.debug_boot_proven(facts, "nvram"))
        for invalid in ({"active_debug_mask": None}, {"bootplist_restored": False},
                        {"bootplist_file_states": {"data": "staged", "preboot": "other"}},
                        {"bootplist_restore": {}}):
            self.assertFalse(r.debug_boot_proven({**facts, **invalid}, "bootplist"))

    def test_bootplist_owner_ack_precedes_single_reboot_without_nvram(self):
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update(debug_source="bootplist", trigger="reboot-quick")
                events = []
                def stage(*_args, **_kwargs):
                    events.append("stage")
                    if uncertain:
                        raise r.recovery_bootplist.WriteUncertain()
                    return {"data": "staged", "preboot": "staged", "metadata_preserved": True}
                def prepared(*_args):
                    events.append("prepared")
                    return {"phase": "quick_prepared"}
                def acknowledged(_directory, _config, value):
                    self.assertTrue((directory / "debug-reboot-intent.json").exists())
                    evidence = r.read_debug_event(directory, config, "bootplist_staged")
                    self.assertTrue(evidence["bootplist_stage"]["metadata_preserved"])
                    events.append("ack")
                    return value
                def reboot(*_args, **_kwargs):
                    events.append("reboot")
                    return {"returncode": 1}
                def forbidden(*_args, **_kwargs):
                    self.fail("unexpected NVRAM operation or uncertain rollback")
                with patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                        patch.object(r.recovery_bootargs, "stage", forbidden), \
                        patch.object(r.recovery_bootargs, "rollback", forbidden), \
                        patch.object(r.recovery_bootplist, "stage", stage), \
                        patch.object(r.recovery_bootplist, "rollback", forbidden), \
                        patch.object(r, "native_force_sync", forbidden), \
                        patch.object(r, "quick_prepare", prepared), \
                        patch.object(r, "quick_intent_ack", acknowledged), \
                        patch.object(r, "quick_reboot_child", reboot):
                    r.debug_owner(directory, config, "old")
                    r.debug_owner(directory, config, "old")
                self.assertEqual(events, ["stage"] if uncertain else ["stage", "prepared", "ack", "reboot"])
                self.assertEqual((directory / "debug-reboot-intent.json").exists(), not uncertain)

    def test_bootplist_collection_restores_before_ack_and_inventory(self):
        for restored in (True, False):
            with self.subTest(restored=restored), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update(debug_source="bootplist", trigger="reboot-quick")
                config["check_id"] = 9
                r.private_write(directory / "token", b"synthetic-token")
                r.private_write(directory / "ready.json", r.json.dumps({"baseline": "old", "nonce": config["nonce"], "preboot_patch": True}).encode())
                events = []
                def finish(*_args, **_kwargs):
                    events.append("restore")
                    if not restored:
                        raise r.recovery_bootplist.WriteUncertain()
                    return {"current_boot_uuid": "new", "active_debug_mask": 0x2000, "active_bootargs_status": "observed_debug",
                            "bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "staged"},
                            "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}}
                def core(_directory, _config, _current, facts, _token):
                    self.assertNotIn("nvram_restored", facts)
                    self.assertEqual(facts["bootplist_restored"], restored)
                    events.append("ack")
                    return facts
                def inventory(*_args, **_kwargs):
                    events.append("inventory")
                    return {}
                def api(_method, _url, _token, payload, **_kwargs):
                    events.append(payload["conclusion"])
                    error = r.urllib.error.HTTPError("https://api.github.com", 401, "test refusal", {}, None)
                    self.addCleanup(error.close)
                    raise error
                def forbidden(*_args, **_kwargs):
                    self.fail("file collection used NVRAM restoration")
                with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: "new"), \
                        patch.object(r.recovery_bootplist, "finish", finish), patch.object(r.recovery_bootargs, "finish", forbidden), \
                        patch.object(r, "publish_debug_core", core), patch.object(r.recovery_bootargs, "observe_once", inventory), \
                        patch.object(r, "api", api):
                    r.collect(directory)
                self.assertEqual(events, ["restore", "ack", "inventory", "success"] if restored else ["restore", "ack", "failure"])

    def test_panic_followup_context_is_restricted_to_debug_bootplist(self):
        ctx = {"actions": "true", "repo": "Code-Hex/vz-ci-test", "ref": "refs/heads/main", "event": "workflow_dispatch",
               "runner_environment": "github-hosted", "run_id": "123", "attempt": "1", "sha": "a" * 40,
               "trigger": "reboot-quick", "debug_boot": True, "debug_source": "bootplist", "after_debug_boot": "panic-nonce"}
        self.assertTrue(r.valid_context(ctx, "Darwin", "x86_64", r.KERNEL_UUID))
        for changes in ({"debug_source": "nvram"}, {"debug_boot": False}, {"trigger": "reboot"}, {"after_debug_boot": "unknown"}):
            self.assertFalse(r.valid_context({**ctx, **changes}, "Darwin", "x86_64", r.KERNEL_UUID))
        data = {"trigger": "reboot-quick", "debug_boot": True, "debug_source": "bootplist", "after_debug_boot": "none"}
        self.assertFalse(r.mode_matches(data, {}, ctx))
        self.assertTrue(r.report_required(ctx))

    def test_followup_proof_keeps_three_boots_distinct(self):
        b1, b2, b3 = (letter * 8 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 12 for letter in ("A", "B", "C"))
        ctx = {"debug_source": "bootplist", "after_debug_boot": "panic-nonce", "trigger": "reboot-quick", "debug_boot": True,
               "run_id": "123", "attempt": "1", "sha": "a" * 40}
        pending = {"nonce": "d" * 64, "baseline_boot_uuid": b1, "cert_fingerprint": "e" * 64}
        scope = {"binding": r.binding(ctx), "nonce": pending["nonce"], "baseline": b1,
                 "source_identity": r.debug_source_identity(), "debug_boot_uuid": b2}
        facts = {"current_boot_uuid": b2, "active_debug_mask": 0x102000, "active_bootargs_status": "observed_debug",
                 "bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "staged"},
                 "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}}
        trigger = {"scope": scope, "helper_sha256": "f" * 64, "helper_pid": 123, "tracer_pid": 456, "ready": True}
        data = {"protocol": "vz-recovery-v1", "phase": "boot_observed", "binding": r.binding(ctx), **pending,
                "debug_source": "bootplist", "after_debug_boot": "panic-nonce", "trigger": "reboot-quick", "debug_boot": True,
                "current_boot_uuid": b3, "debug_boot_uuid": b2, "debug_boot_facts": facts, "panic_trigger": trigger}
        self.assertTrue(r.boot_proof_matches(data, pending, ctx))
        for invalid in ({"current_boot_uuid": b2}, {"debug_boot_uuid": b1}, {"debug_boot_facts": {**facts, "current_boot_uuid": b3}},
                        {"panic_trigger": {**trigger, "scope": {**scope, "debug_boot_uuid": b3}}},
                        {"panic_trigger": {**trigger, "scope": {**scope, "source_identity": "0" * 64}}}):
            self.assertFalse(r.boot_proof_matches({**data, **invalid}, pending, ctx))

    def followup_fixture(self):
        b1, b2, b3 = (letter * 8 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 4 + "-" + letter * 12 for letter in ("A", "B", "C"))
        ctx = {"debug_source": "bootplist", "after_debug_boot": "panic-nonce", "trigger": "reboot-quick", "debug_boot": True,
               "run_id": "123", "attempt": "1", "sha": "a" * 40}
        config = {"context": ctx, "baseline": b1, "nonce": "d" * 64, "check_id": 9,
                  "cert_fingerprint": "e" * 64, "debug_source_identity": r.debug_source_identity()}
        scope = {**r.debug_boot_marker(config), "debug_boot_uuid": b2}
        facts = {"current_boot_uuid": b2, "active_debug_mask": 0x102000, "active_bootargs_status": "observed_debug",
                 "bootplist_restored": True, "bootplist_file_states": {"data": "staged", "preboot": "staged"},
                 "bootplist_restore": {name: {"bytes": True, "metadata": True, "timestamps": True} for name in ("data", "preboot")}}
        return config, {"scope": scope, "facts": facts}, b3

    def test_followup_source_mismatch_never_prepares_or_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            config['debug_source_identity'] = '0' * 64
            def forbidden(*_args, **_kwargs):
                self.fail('source mismatch reached native preparation or firing')
            with patch.object(r.recovery_panic_control, 'prepare', forbidden), patch.object(r.recovery_panic_control, 'fire', forbidden):
                with self.assertRaises(ValueError):
                    r.followup_start(directory, config, saved['scope']['debug_boot_uuid'], saved['facts'], 'token')
            self.assertFalse((directory / 'panic-followup-debug.json').exists())

    def test_followup_start_persists_debug_proof_before_ready_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, _b3 = self.followup_fixture()
            events = []
            r.private_write(directory / "report-cert.pem", b"public certificate boundary")
            def prepare(*_args):
                self.assertEqual(r.read_followup_debug(directory, config), saved)
                events.append("prepare")
                (directory / "panic-control").mkdir()
                r.private_write(directory / "panic-control" / "trace.stdout", b"private trace output")
                return {"helper_sha256": "f" * 64}
            def publish(_directory, _config, _token, summary, _title):
                events.append(summary["phase"])
                if summary["phase"] == "panic_intent":
                    self.assertTrue((directory / "panic-followup-trigger.json").exists())
            def fire(_directory, scope, prepared, _save, _sync, ready, _boot):
                trigger = {"scope": scope, "helper_sha256": prepared["helper_sha256"], "helper_pid": 123, "tracer_pid": 456, "ready": True}
                self.assertTrue(ready(trigger))
                events.append("release")
                return {"phase": "returned"}
            def watch(*_args):
                events.append('watch_ready')
                return object()
            def encrypt(_certificate, metadata, report):
                self.assertEqual(metadata["kind"], "panic_control_failure")
                fragments = r.json.loads(report)
                self.assertEqual(r.base64.b64decode(fragments["trace.stdout"]), b"private trace output")
                return {"cert_fingerprint": config["cert_fingerprint"], "ciphertext": "encrypted-only", "cipher_sha256": "c" * 64}
            def complete(_directory, _config, _current, _token, output, successful, _deadline):
                self.assertFalse(successful)
                self.assertEqual(output.get("text"), "encrypted-only")
                self.assertNotIn("private trace output", r.json.dumps(output))
                self.assertEqual(r.json.loads(output["summary"])["phase"], "panic_returned")
                events.append("returned")
            with patch.object(r.recovery_panic_control, "prepare", prepare), patch.object(r.recovery_panic_control, "fire", fire), \
                    patch.object(r.recovery_nvram_panic, "read_panic_info", lambda: self.fail("boot 2 loaded IOKit before spawning tools")), \
                    patch.object(r, "publish_followup", publish), patch.object(r, "complete_recovery", complete), \
                    patch.object(r, "start_runtime_watch", watch), patch.object(r, "runtime_watch_alive", lambda *_a, **_k: True), \
                    patch.object(r.recovery_reports, "encrypt_bundle", encrypt), \
                    patch.object(r, "boot_uuid", lambda: saved["scope"]["debug_boot_uuid"]):
                r.followup_start(directory, config, saved["scope"]["debug_boot_uuid"], saved["facts"], "token")
            self.assertEqual(events, ["prepare", "panic_prepared", "watch_ready", "panic_intent", "release", "returned"])

    def test_followup_third_boot_bypasses_second_boot_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, saved, b3 = self.followup_fixture()
            r.private_write(directory / "panic-followup-debug.json", r.json.dumps(saved).encode())
            r.private_write(directory / "token", b"synthetic-token")
            calls = []
            def forbidden(*_args, **_kwargs):
                self.fail("third boot reran second-boot restoration or core publication")
            with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: b3), \
                    patch.object(r.recovery_bootplist, "finish", forbidden), patch.object(r, "publish_debug_core", forbidden), \
                    patch.object(r, "followup_finish", lambda *_args: calls.append("capture")):
                r.collect(directory)
            self.assertEqual(calls, ["capture"])
            with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: saved["scope"]["debug_boot_uuid"]), \
                    patch.object(r, "followup_finish", forbidden), patch.object(r, "followup_start", forbidden):
                r.collect(directory)

    def test_followup_capture_is_bound_encrypted_and_immutable(self):
        for matching in (True, False):
            with self.subTest(matching=matching), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, saved, b3 = self.followup_fixture()
                scope = saved["scope"]
                trigger = {"scope": scope, "helper_sha256": "f" * 64, "helper_pid": 123, "tracer_pid": 456, "ready": True}
                prepared = {"helper_sha256": "f" * 64}
                (directory / "panic-control").mkdir()
                for name, value in (("panic-followup-trigger.json", trigger), ("panic-control/release-attempt.json", trigger),
                                    ("panic-control/intent.json", {"scope": scope, "prepared": prepared})):
                    r.private_write(directory / name, r.json.dumps(value).encode())
                r.private_write(directory / "report-cert.pem", b"public certificate boundary")
                nonce = config["nonce"] if matching else "0" * 64
                raw = ("panic(cpu 1 caller 0xff): dtrace: panic action at probe pid123:helper:vz_nonce_" + nonce +
                       ":entry (ecb 0xff)\nKernel UUID: " + r.KERNEL_UUID + "\n").encode()
                cipher = b"encrypted boundary artifact"
                envelope = {"ciphertext": r.base64.b64encode(cipher).decode(), "cipher_sha256": r.hashlib.sha256(cipher).hexdigest(),
                            "cert_fingerprint": config["cert_fingerprint"]}
                outputs = []
                def encrypt(_cert, metadata, report):
                    self.assertEqual(report, raw)
                    self.assertEqual((metadata["baseline_boot_uuid"], metadata["debug_boot_uuid"], metadata["current_boot_uuid"]),
                                     (config["baseline"], scope["debug_boot_uuid"], b3))
                    return envelope
                def complete(_directory, _config, _current, _token, output, successful, _deadline):
                    self.assertEqual(successful, matching)
                    self.assertNotIn("dtrace: panic action", r.json.dumps(output))
                    outputs.append(output)
                with patch.object(r.recovery_panic_control, "validate_prepared", lambda *_: directory / "helper"), \
                        patch.object(r.recovery_nvram_panic, "read_panic_info", lambda: ("observed", raw)), \
                        patch.object(r.recovery_reports, "encrypt_bundle", encrypt), patch.object(r, "complete_recovery", complete):
                    r.followup_finish(directory, config, b3, saved, "token")
                with patch.object(r.recovery_panic_control, "validate_prepared", lambda *_: directory / "helper"), \
                        patch.object(r.recovery_nvram_panic, "read_panic_info", lambda: self.fail("reread first observation")), \
                        patch.object(r.recovery_reports, "encrypt_bundle", encrypt), patch.object(r, "complete_recovery", complete):
                    r.followup_finish(directory, config, b3, saved, "token")
                self.assertEqual(outputs[0], outputs[1])
                summary = r.json.loads(outputs[0]["summary"])
                self.assertEqual(summary["debug_boot_facts"]["current_boot_uuid"], scope["debug_boot_uuid"])
                self.assertEqual(summary["current_boot_uuid"], b3)
                self.assertEqual(summary["capture_state"], "fresh_fragment" if matching else "encrypted_unvalidated")

    def owner_fixture(self, directory):
        config = {"debug_source": "nvram", "context": {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True, "trigger": "reboot"},
                  "debug_boot": True, "baseline": "old", "nonce": "b" * 64, "debug_source_identity": r.debug_source_identity()}
        original = {"boot-args": b"preempt=10"}
        class Platform:
            fail_write = False
            def __init__(self):
                self.value = original.copy()
                self.active_value = b"preempt=10"
                self.events = []
            def read(self):
                return self.value.copy()
            def active(self):
                return self.active_value
            def write(self, path, owned_canary, expected_previous):
                self.events.append("write")
                self.value = r.recovery_bootargs.parse_nvram(path.read_bytes())
                if self.fail_write:
                    self.fail_write = False
                    raise OSError("write response lost")
            def inventory(self):
                self.events.append("inventory")
                return {"nic_inventory_status": "unsupported"}
        r.debug_event(directory, config, "request", "old")
        return config, Platform(), original

    def test_owner_preintent_failure_restores_without_reboot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            platform.fail_write = True
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("preintent reboot")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            self.assertFalse((directory / "debug-reboot-intent.json").exists())
            self.assertTrue((directory / "debug-reboot-aborted.json").exists())

    def test_owner_sync_request_failure_prevents_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, _platform, original = self.owner_fixture(directory)
            state, syncs = original.copy(), []
            def capture(argv, *_args):
                if argv == ["/usr/sbin/nvram", "-x", "-p"]:
                    return r.recovery_bootargs.plistlib.dumps(state)
                if argv[0] == "/usr/sbin/sysctl":
                    return b"preempt=10\n"
                if argv[1:3] == ["-x", "-f"]:
                    state.update(r.recovery_bootargs.parse_nvram(Path(argv[3]).read_bytes()))
                    return b""
                if argv[1] == "-d":
                    state.pop(argv[2], None)
                    return b""
                self.assertEqual(argv, ["/usr/sbin/nvram", "-s"])
                syncs.append("sync")
                if len(syncs) == 1:
                    raise OSError("sync request failed")
                return b""
            with patch.object(r.recovery_bootargs, "capture", capture), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("reboot after failed sync")):
                r.debug_owner(directory, config, "old")
            self.assertFalse((directory / "debug-reboot-intent.json").exists())
            self.assertEqual(state, original)
            self.assertEqual(syncs, ["sync", "sync", "sync"])

    def test_owner_postintent_timeout_or_signal_never_kills_restores_or_retries(self):
        for failure in (subprocess.TimeoutExpired("reboot", 15), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                calls = []
                class Child:
                    pid = 1234
                    def wait(self, timeout):
                        raise failure
                    def kill(self):
                        raise AssertionError("postintent kill")
                def popen(*_args, **_kwargs):
                    calls.append("reboot")
                    return Child()
                with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                        patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), patch.object(r.subprocess, "Popen", popen):
                    r.debug_owner(directory, config, "old")
                    r.debug_owner(directory, config, "old")
                self.assertNotEqual(platform.value, original)
                self.assertEqual(calls, ["reboot"])
                self.assertTrue((directory / "debug-reboot-intent.json").exists())
                self.assertFalse((directory / "debug-boot-restored.json").exists())

    def test_owner_orphan_stage_restores_without_reboot(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            r.recovery_bootargs.stage(directory, r.debug_boot_marker(config), platform, r.private_write, r.sync_directory)
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r, "debug_reboot_child", lambda: self.fail("orphan stage reboot")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            record = r.read_debug_event(directory, config, "aborted")
            self.assertEqual(record["reason"], "orphan_stage")
            self.assertEqual(record["nvram_before_rollback"], "staged")

    def test_owner_returned_request_is_immutable_and_never_reissued(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, _original = self.owner_fixture(directory)
            request = directory / "debug-reboot-request.json"
            first = request.read_bytes()
            r.debug_event(directory, config, "request", "old", reason="interrupted")
            self.assertEqual(request.read_bytes(), first)
            calls = []
            def reboot():
                calls.append("reboot")
                return {"returncode": 0, "reboot_pid": 1234}
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), patch.object(r, "debug_reboot_child", reboot):
                r.debug_owner(directory, config, "old")
                r.debug_owner(directory, config, "old")
            self.assertEqual(calls, ["reboot"])
            self.assertEqual(r.read_debug_event(directory, config, "returned")["returncode"], 0)
            self.assertFalse((directory / "debug-boot-restored.json").exists())

    def test_native_sync_fact_requires_exact_success(self):
        good = b'{"event":"sync","status":"returned","ioreturn":0}\n'
        states = {'boot_args': 'staged', 'canary': 'staged'}
        fact = r.native_sync_fact(good, 0, states, states, 'a' * 64, 'b' * 64)
        self.assertEqual(fact['ioreturn'], 0)
        self.assertEqual(fact['after_key_states'], states)
        for raw, code, keys in ((good, 70, states), (good + good, 0, states),
                                (good.replace(b':0', b':true'), 0, states),
                                (good, 0, {'boot_args': 'original', 'canary': 'staged'})):
            with self.assertRaises(ValueError): r.native_sync_fact(raw, code, states, keys, 'a' * 64, 'b' * 64)

    def test_native_spawn_interruption_is_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            helper = directory / 'nvram-backend'
            helper.write_bytes(b'synthetic helper')
            config = {'baseline': 'old', 'nonce': 'b' * 64,
                      'nvram_helper_sha256': r.hashlib.sha256(helper.read_bytes()).hexdigest(),
                      'context': {"debug_source": "nvram", 'actions': 'true', 'event': 'workflow_dispatch', 'repo': 'Code-Hex/vz-ci-test',
                                  'ref': 'refs/heads/main', 'runner_environment': 'github-hosted',
                                  'run_id': '123', 'attempt': '1', 'sha': 'a' * 40, 'trigger': 'reboot-quick'}}
            with patch.object(r, 'boot_uuid', lambda: 'old'), patch.object(r.subprocess, 'Popen', side_effect=KeyboardInterrupt()):
                try:
                    r.invoke_native_helper(directory, config)
                except BaseException as error:
                    self.assertIsInstance(error, r.NativeSyncUncertain)
                else:
                    self.fail('interrupted spawn reported success')

    def test_native_failure_fact_preserves_only_bounded_status(self):
        raw = b'{"event":"sync","status":"returned","ioreturn":3758097084,"private":"never"}\n'
        self.assertEqual(r.native_failure_fact(raw, 70), {'status': 'returned', 'exit': 70, 'ioreturn': 3758097084})
        self.assertEqual(r.native_failure_fact(raw.replace(b'3758097084', b'true'), 70), {'status': 'invalid'})

    def test_debug_quick_owner_ack_before_intent_and_no_reissue(self):
        for acknowledged, intent_acknowledged in ((True, True), (True, False), (False, True)):
            with self.subTest(acknowledged=acknowledged, intent_acknowledged=intent_acknowledged), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                config["context"]["trigger"] = "reboot-quick"
                config.update({"nvram_helper_sha256": "a" * 64, "nvram_source_sha256": "b" * 64})
                native_fact = r.native_sync_fact(b'{"event":"sync","status":"returned","ioreturn":0}', 0,
                    {"boot_args": "staged", "canary": "staged"}, {"boot_args": "staged", "canary": "staged"}, "a" * 64, "b" * 64)
                events = []
                def prepare(*_args):
                    self.assertNotEqual(platform.value, original)
                    self.assertTrue((directory / "debug-reboot-staged.json").exists())
                    self.assertFalse((directory / "debug-reboot-intent.json").exists())
                    events.append("prepare_ack")
                    if not acknowledged:
                        raise ValueError("checkpoint not acknowledged")
                    return {"phase": "quick_prepared"}
                def intent_ack(*_args):
                    self.assertTrue((directory / "debug-reboot-intent.json").exists())
                    self.assertFalse((directory / "debug-boot-restored.json").exists())
                    events.append("intent_ack")
                    if not intent_acknowledged:
                        raise ValueError("intent checkpoint not acknowledged")
                    return _args[2]
                def execute(*_args, **_kwargs):
                    self.assertTrue((directory / "debug-reboot-intent.json").exists())
                    events.append("execute")
                    return {"reason": "exec_error"}
                with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                        patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                        patch.object(r, "native_force_sync", lambda *_args: native_fact), \
                        patch.object(r, "quick_prepare", prepare), patch.object(r, "quick_reboot_child", execute), \
                        patch.object(r, "quick_intent_ack", intent_ack), \
                        patch.object(r, "debug_reboot_child", lambda: self.fail("normal reboot fallback")):
                    r.debug_owner(directory, config, "old")
                    r.debug_owner(directory, config, "old")
                expected = ["prepare_ack"] + (["intent_ack"] if acknowledged else [])
                if acknowledged and intent_acknowledged:
                    expected.append("execute")
                self.assertEqual(events, expected)
                self.assertEqual(platform.value == original, not acknowledged)
                self.assertEqual((directory / "debug-boot-restored.json").exists(), not acknowledged)
                if acknowledged and not intent_acknowledged:
                    self.assertEqual(r.read_debug_event(directory, config, "uncertain")["reason"], "intent_ack_failure")

    def test_unsettled_native_marker_blocks_retry_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config["context"]["trigger"] = "reboot-quick"
            r.debug_event(directory, config, "native_inflight", "old")
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: self.fail("unsettled native owner retried")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)
            self.assertFalse((directory / "debug-reboot-aborted.json").exists())
            self.assertFalse((directory / "debug-reboot-intent.json").exists())
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config["context"]["trigger"] = "reboot-quick"
            r.debug_event(directory, config, "rollback_inflight", "old")
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: self.fail("unsettled cleanup retried")):
                r.debug_owner(directory, config, "old")
            self.assertEqual(platform.value, original)

    def test_uncertain_native_and_invalid_terminal_never_mutate_again(self):
        for variant in ('uncertain', 'partial_synced', 'partial_failed', 'uncertain_failed', 'inconsistent_failed'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                config["context"]["trigger"] = "reboot-quick"
                calls = []
                if variant == 'uncertain':
                    def native(*_args):
                        calls.append('native')
                        raise r.NativeSyncUncertain()
                    with patch.object(r.recovery_bootargs, 'MacPlatform', lambda: platform), \
                            patch.object(r.recovery_bootargs, 'csr_allowed', lambda: True), \
                            patch.object(r, 'native_force_sync', native), \
                            patch.object(r.recovery_bootargs, 'rollback', lambda *_a, **_k: self.fail('uncertain rollback')), \
                            patch.object(r, 'rollback_native_sync', lambda *_: self.fail('uncertain cleanup')), \
                            patch.object(r, 'quick_reboot_child', lambda *_a, **_k: self.fail('uncertain reboot')):
                        r.debug_owner(directory, config, 'old')
                        r.debug_owner(directory, config, 'old')
                    self.assertEqual(calls, ['native'])
                    self.assertNotEqual(platform.value, original)
                else:
                    r.debug_event(directory, config, 'native_inflight', 'old')
                    event = 'native_synced' if variant == 'partial_synced' else 'native_failed'
                    path = directory / ('debug-reboot-' + event + '.json')
                    if variant == 'uncertain_failed':
                        r.debug_event(directory, config, event, 'old', sync_result={'status': 'failed_or_uncertain'})
                    elif variant == 'inconsistent_failed':
                        r.debug_event(directory, config, event, 'old', sync_result={'status': 'returned', 'exit': 0, 'ioreturn': 123})
                    else:
                        path.write_text('{')
                    with patch.object(r.recovery_bootargs, 'MacPlatform', lambda: self.fail('invalid record retried')):
                        r.debug_owner(directory, config, 'old')
                self.assertFalse((directory / 'debug-reboot-aborted.json').exists())
                self.assertFalse((directory / 'debug-reboot-intent.json').exists())

    def test_uncertain_cleanup_retains_marker_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config['context']['trigger'] = 'reboot-quick'
            calls = []
            def native(*_args):
                calls.append('native')
                raise r.NativeSyncFailure({'status': 'returned', 'exit': 70, 'ioreturn': 123})
            def cleanup(*_args):
                calls.append('cleanup')
                raise r.NativeSyncUncertain()
            with patch.object(r.recovery_bootargs, 'MacPlatform', lambda: platform), \
                    patch.object(r.recovery_bootargs, 'csr_allowed', lambda: True), \
                    patch.object(r, 'native_force_sync', native), patch.object(r, 'rollback_native_sync', cleanup), \
                    patch.object(r, 'quick_reboot_child', lambda *_a, **_k: self.fail('unexpected reboot')):
                r.debug_owner(directory, config, 'old')
                r.debug_owner(directory, config, 'old')
            self.assertEqual(calls, ['native', 'cleanup'])
            self.assertEqual(platform.value, original)
            self.assertTrue((directory / 'debug-reboot-rollback_inflight.json').exists())
            self.assertFalse((directory / 'debug-reboot-rollback_cleanup.json').exists())
            self.assertFalse((directory / 'debug-reboot-aborted.json').exists())

    def test_native_failure_rolls_back_and_never_reboots(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config, platform, original = self.owner_fixture(directory)
            config["context"]["trigger"] = "reboot-quick"
            calls = []
            def native(*_args):
                calls.append("native")
                raise r.NativeSyncFailure({"status": "returned", "exit": 70, "ioreturn": 123})
            def cleanup(*_args):
                self.assertEqual(platform.value, original)
                calls.append("cleanup")
                return {"status": "returned", "exit": 0, "ioreturn": 0, "sameboot_readback_original": True}
            with patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), \
                    patch.object(r.recovery_bootargs, "csr_allowed", lambda: True), \
                    patch.object(r, "native_force_sync", native), patch.object(r, "rollback_native_sync", cleanup), \
                    patch.object(r, "quick_prepare", lambda *_: self.fail("prepare after native failure")), \
                    patch.object(r, "quick_reboot_child", lambda *_a, **_k: self.fail("reboot after native failure")):
                r.debug_owner(directory, config, "old")
                r.debug_owner(directory, config, "old")
            self.assertEqual(calls, ["native", "cleanup"])
            self.assertEqual(platform.value, original)
            self.assertEqual(r.read_debug_event(directory, config, "native_failed")["sync_result"]["ioreturn"], 123)
            self.assertTrue(r.read_debug_event(directory, config, "rollback_cleanup")["sync_result"]["sameboot_readback_original"])
            self.assertFalse((directory / "debug-reboot-intent.json").exists())

    def test_quick_intent_canonical_ack_preserves_prepared_and_filters_owner_fields(self):
        for source, acknowledged in (("nvram", True), ("nvram", False), ("bootplist", True), ("bootplist", False)):
            with self.subTest(acknowledged=acknowledged), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update(trigger="reboot-quick", debug_source=source)
                config["check_id"] = 9
                config.update({"nvram_helper_sha256": "a" * 64, "nvram_source_sha256": "b" * 64})
                ctx = config["context"]
                config["cert_fingerprint"] = "e" * 64 if source == "bootplist" else ""
                prepared = {"debug_source": source, "protocol": "vz-recovery-v1", "phase": "quick_prepared", "binding": r.binding(ctx),
                            "nonce": config["nonce"], "baseline_boot_uuid": config["baseline"], "trigger": "reboot-quick",
                            "debug_boot": True, "cert_fingerprint": config["cert_fingerprint"], "quick_flags": 1024, "helper_sha256": "c" * 64,
                            "permission_verified": False}
                r.private_write(directory / "token", b"synthetic-token")
                for event in ("staged", "intent"):
                    r.debug_event(directory, config, event, "old")
                native_fact = r.native_sync_fact(b'{"event":"sync","status":"returned","ioreturn":0}', 0,
                    {"boot_args": "staged", "canary": "staged"}, {"boot_args": "staged", "canary": "staged"}, "a" * 64, "b" * 64)
                evidence = "native_synced" if source == "nvram" else "bootplist_staged"
                if source == "nvram":
                    r.debug_event(directory, config, evidence, "old", native_sync=native_fact)
                else:
                    r.debug_event(directory, config, evidence, "old", bootplist_stage={"data": "staged", "preboot": "staged", "metadata_preserved": True})
                path = directory / "debug-reboot-staged.json"
                raw = r.json.loads(path.read_text())
                path.write_text(r.json.dumps({**raw, "raw": "private-not-published"}))
                sent, operations = {}, []
                def api(method, _url, token, payload=None):
                    self.assertEqual(token, "synthetic-token")
                    operations.append(method)
                    if method == "PATCH":
                        sent.update(payload)
                        return {}
                    return {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                            "app": {"id": 15368 if acknowledged else 0, "slug": "github-actions"},
                            "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9", "status": "in_progress",
                            "conclusion": None, "output": sent["output"]}
                with patch.object(r, "api", api), patch.object(r, "boot_uuid", lambda: "old"):
                    if acknowledged:
                        result = r.quick_intent_ack(directory, config, prepared)
                        self.assertEqual(result["phase"], "quick_intent")
                        with self.assertRaises(ValueError):
                            r.quick_intent_ack(directory, config, {**prepared, "cert_fingerprint": "0" * 64})
                    else:
                        with self.assertRaises(ValueError):
                            r.quick_intent_ack(directory, config, prepared)
                self.assertEqual(operations, ["PATCH", "GET"])
                summary = r.json.loads(sent["output"]["summary"])
                self.assertEqual({key: summary[key] for key in prepared if key != "phase"},
                                 {key: value for key, value in prepared.items() if key != "phase"})
                self.assertEqual([event["event"] for event in summary["owner_events"]], ["staged", evidence, "intent"])
                self.assertNotIn("private-not-published", sent["output"]["summary"])

    def test_quick_timeout_retains_same_child_until_exit_without_kill(self):
        for interruption in (subprocess.TimeoutExpired("helper", 30), KeyboardInterrupt()):
            with self.subTest(interruption=type(interruption).__name__), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, _platform, _original = self.owner_fixture(directory)
                config["context"].update({"debug_source": "nvram", "actions": "true", "event": "workflow_dispatch", "repo": "Code-Hex/vz-ci-test",
                                          "ref": "refs/heads/main", "runner_environment": "github-hosted", "trigger": "reboot-quick"})
                helper = directory / "reboot-quick"
                helper.write_bytes(b"synthetic helper")
                config["helper_sha256"] = r.hashlib.sha256(helper.read_bytes()).hexdigest()
                waits, notices, starts = [], [], []
                class Child:
                    returncode, pid = 70, 1234
                    def communicate(self, timeout):
                        waits.append(timeout)
                        if len(waits) == 1:
                            raise interruption
                        return ('{"event":"quick_reboot_unexpected_return","result":-1,"errno":1}', '')
                    def kill(self):
                        raise AssertionError("helper killed")
                def popen(command, **kwargs):
                    starts.append(command)
                    self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                    return Child()
                with patch.object(r.subprocess, "Popen", popen):
                    result = r.quick_reboot_child(directory, config, notices.append)
                self.assertEqual(waits, [30, None])
                self.assertEqual(notices, ["timeout" if isinstance(interruption, subprocess.TimeoutExpired) else "interrupted"])
                self.assertEqual(starts, [[str(helper), "execute"]])
                self.assertEqual(result["quick_return"]["errno"], 1)

    def test_newboot_core_ack_precedes_inventory_and_failed_ack_skips_it(self):
        for acknowledged, restored in ((True, True), (False, True), (True, False)):
            with self.subTest(acknowledged=acknowledged, restored=restored), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config, platform, original = self.owner_fixture(directory)
                config["check_id"] = 9
                r.recovery_bootargs.stage(directory, r.debug_boot_marker(config), platform, r.private_write, r.sync_directory)
                platform.active_value = b"preempt=10 debug=0x2000"
                platform.events.clear()
                r.private_write(directory / "token", b"test-token")
                r.private_write(directory / "ready.json", r.json.dumps({"baseline": "old", "nonce": config["nonce"], "preboot_patch": True}).encode())
                output = {}
                final_conclusions = []
                original_finish = r.recovery_bootargs.finish
                def finish(*args, **kwargs):
                    if not restored:
                        raise OSError("restoration unavailable")
                    return original_finish(*args, **kwargs)
                def api(method, _url, _token, payload=None, **_kwargs):
                    if method == "PATCH" and payload.get("status") == "in_progress":
                        platform.events.append("core_patch")
                        output.update(payload["output"])
                        return {}
                    if method == "GET":
                        platform.events.append("core_ack")
                        ctx = config["context"]
                        return {"id": 9, "name": "Runner recovery " + ctx["run_id"], "head_sha": ctx["sha"],
                                "external_id": r.binding(ctx), "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                                "app": {"id": 15368 if acknowledged else 0, "slug": "github-actions"},
                                "status": "in_progress", "conclusion": None, "output": output.copy()}
                    platform.events.append("final_patch")
                    final_conclusions.append(payload["conclusion"])
                    error = r.urllib.error.HTTPError("https://api.github.com", 401, "test refusal", {}, None)
                    self.addCleanup(error.close)
                    raise error
                with patch.object(r, "load_config", lambda _: config), patch.object(r, "boot_uuid", lambda: "new"), \
                        patch.object(r.recovery_bootargs, "MacPlatform", lambda: platform), patch.object(r, "api", api), \
                        patch.object(r.recovery_bootargs, "finish", finish), \
                        patch.object(r, "debug_owner", lambda *_: self.fail("newboot invoked oldboot owner")):
                    r.collect(directory)
                if restored:
                    self.assertEqual(platform.value, original)
                    self.assertLess(platform.events.index("write"), platform.events.index("core_patch"))
                self.assertTrue((directory / "debug-boot-core.json").exists())
                self.assertEqual(r.json.loads((directory / "debug-boot-core.json").read_text())["facts"]["nvram_restored"], restored)
                if not restored:
                    self.assertEqual(r.json.loads((directory / "debug-boot-core.json").read_text())["facts"]["nvram_key_states"],
                                     {"boot_args": "unavailable", "canary": "unavailable"})
                if acknowledged and restored:
                    self.assertLess(platform.events.index("core_ack"), platform.events.index("inventory"))
                    self.assertLess(platform.events.index("inventory"), platform.events.index("final_patch"))
                    self.assertEqual(final_conclusions, ["success"])
                elif acknowledged:
                    self.assertNotIn("inventory", platform.events)
                    self.assertEqual(final_conclusions, ["failure"])
                else:
                    self.assertNotIn("inventory", platform.events)
                    self.assertNotIn("final_patch", platform.events)

    def test_default_reboot_path_still_uses_existing_command(self):
        calls = []
        def sudo(operation, *_args, **_kwargs):
            calls.append(operation)
            return "ready"
        def run(command, **kwargs):
            calls.append((command, kwargs))
        with patch.object(r.sys, "argv", ["reboot-recovery.py", "reboot"]), \
                patch.object(r, "context_from_env", lambda: {"debug_source": "nvram", "trigger": "reboot", "debug_boot": False}), \
                patch.object(r, "require_context", lambda *_: None), patch.object(r, "sudo_call", sudo), \
                patch.object(r.os, "sync", lambda: calls.append("sync")), patch.object(r.subprocess, "run", run), \
                contextlib.redirect_stdout(io.StringIO()):
            r.main()
        self.assertEqual(calls, ["verify-root", "sync", (["/usr/bin/sudo", "-n", "/sbin/reboot"], {"check": True, "timeout": 15})])

    def test_debug_controller_stop_does_not_overwrite_new_core_after_stale_get(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "debug_boot": True}
        armed = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx), "head_sha": ctx["sha"],
                 "app": {"id": 15368, "slug": "github-actions"}, "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9",
                 "status": "in_progress", "output": {"summary": '{"phase":"armed"}'}}
        core = {"title": "Boot core recovered", "summary": '{"phase":"boot_core","immutable_fact":true}'}
        server, patches = {"output": armed["output"]}, []
        def api(method, _url, _token, payload=None, **_kwargs):
            if method == "GET":
                server["output"] = core.copy()
                return armed
            self.assertEqual(method, "PATCH")
            patches.append(payload)
            server.update(payload)
            return {}
        def stop(_seconds):
            raise RuntimeError("controller interrupted")
        with patch.object(r, "list_check", lambda *_: armed), patch.object(r, "api", api), \
                patch.object(r.time, "sleep", stop), patch.object(r.signal, "signal", lambda *_: None):
            with self.assertRaises(RuntimeError):
                r.controller(ctx, "test-token")
        self.assertEqual(patches, [{"status": "completed", "conclusion": "failure"}])
        self.assertEqual(server["output"], core)

    def test_rsa_oaep_sha256_roundtrip_and_key_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "key.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(private)], check=True, stderr=subprocess.DEVNULL)
            public = subprocess.check_output(["openssl", "pkey", "-in", str(private), "-pubout"])
            ciphertext = r.encrypt_token(public, "test-job-token")
            self.assertNotIn(b"test-job-token", ciphertext)
            self.assertEqual(r.decrypt_token(private, ciphertext), "test-job-token")
            small = Path(tmp) / "small.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(small)], check=True, stderr=subprocess.DEVNULL)
            invalid = subprocess.check_output(["openssl", "pkey", "-in", str(small), "-pubout"])
            with self.assertRaises(ValueError):
                r.encrypt_token(invalid, "test-job-token")

    def test_sealed_retry_and_boot_proof_match_nonce_and_baseline(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "2", "sha": "a" * 40}
        pending = {"nonce": "b" * 64, "baseline_boot_uuid": "first", "ciphertext": "cipher"}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "sealed_token", **pending}
        self.assertTrue(r.sealed_matches(data, pending, ctx))
        self.assertFalse(r.sealed_matches(dict(data, ciphertext="other"), pending, ctx))
        proof = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "boot_observed",
                 "nonce": pending["nonce"], "baseline_boot_uuid": "first", "current_boot_uuid": "second"}
        armed = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "armed", "nonce": pending["nonce"], "baseline_boot_uuid": "first"}
        self.assertTrue(r.armed_matches(armed, pending, ctx))
        self.assertFalse(r.armed_matches(dict(armed, baseline_boot_uuid="other"), pending, ctx))
        self.assertTrue(r.boot_proof_matches(proof, pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, nonce="wrong"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, baseline_boot_uuid="other"), pending, ctx))
        self.assertFalse(r.boot_proof_matches(dict(proof, current_boot_uuid="first"), pending, ctx))

    def test_panic_proof_requires_matching_ciphertext(self):
        import base64
        import hashlib
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "1", "sha": "a" * 40, "trigger": "panic-control"}
        pending = {"nonce": "b" * 64, "baseline_boot_uuid": "old", "cert_fingerprint": "c" * 64}
        data = {"debug_source": "nvram", "protocol": "vz-recovery-v1", "binding": r.binding(ctx), "phase": "boot_observed", "nonce": pending["nonce"],
                "baseline_boot_uuid": "old", "current_boot_uuid": "new", "trigger": "panic-control",
                "cert_fingerprint": pending["cert_fingerprint"], "capture_state": "captured", "cipher_sha256": hashlib.sha256(b"cipher").hexdigest()}
        encoded = base64.b64encode(b"cipher").decode()
        self.assertTrue(r.panic_envelope_matches(data, encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(data, base64.b64encode(b"other").decode(), pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, capture_state="missing"), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, cert_fingerprint="d" * 64), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, trigger="reboot"), encoded, pending, ctx))
        self.assertFalse(r.panic_envelope_matches(dict(data, baseline_boot_uuid="wrong"), encoded, pending, ctx))
        force_ctx = dict(ctx, trigger="panic-force-reset")
        self.assertTrue(r.panic_envelope_matches(dict(data, trigger="panic-force-reset"), encoded, pending, force_ctx))
        self.assertFalse(r.panic_envelope_matches(data, encoded, pending, force_ctx))

    def test_old_check_cleanup_validates_canonical_binding(self):
        old_sha = "a" * 40
        old = {"id": 126478800449, "name": "Runner recovery 41801686112", "head_sha": old_sha,
               "external_id": "41801686112/1/" + old_sha, "app": {"slug": "github-actions", "id": 15368},
               "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/126478800449", "status": "in_progress"}
        current = {"run_id": "999", "attempt": "1", "sha": "b" * 40}
        self.assertTrue(r.cleanup_eligible(old, "126478800449", current))
        self.assertFalse(r.cleanup_eligible(old, "0", current))
        self.assertFalse(r.cleanup_eligible(old, "../126478800449", current))
        self.assertFalse(r.cleanup_eligible(old, "126478800449", dict(current, run_id="41801686112")))
        self.assertFalse(r.cleanup_eligible(dict(old, head_sha="b" * 40), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, status="completed"), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, status="unknown"), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, app={"id": 9, "slug": "github-actions"}), "126478800449", current))
        self.assertFalse(r.cleanup_eligible(dict(old, details_url="https://evil.example"), "126478800449", current))

    def test_binding_exact_and_no_duplicate(self):
        ctx = {"debug_source": "nvram", "run_id": "123", "attempt": "2", "sha": "a" * 40}
        check = {"id": 9, "name": "Runner recovery 123", "external_id": r.binding(ctx),
                 "head_sha": ctx["sha"], "app": {"slug": "github-actions", "id": 15368},
                 "details_url": "https://github.com/Code-Hex/vz-ci-test/runs/9", "status": "in_progress"}
        self.assertEqual(r.select_check([check], ctx)["id"], 9)
        self.assertIsNone(r.select_check([dict(check, external_id="wrong")], ctx))
        self.assertIsNone(r.select_check([dict(check, app={"id": 7, "slug": "github-actions"})], ctx))
        self.assertIsNone(r.select_check([dict(check, details_url="https://example.com")], ctx))
        self.assertIsNone(r.select_check([dict(check, details_url="https://github.com/Code-Hex/vz-ci-test/runs/10")], ctx))
        self.assertIsNone(r.select_check([dict(check, id="9")], ctx))
        with self.assertRaises(ValueError):
            r.select_check([check, check], ctx)


if __name__ == "__main__":
    unittest.main()
