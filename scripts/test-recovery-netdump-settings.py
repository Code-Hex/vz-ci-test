import dataclasses
import unittest

import recovery_bootargs as boot
import recovery_netdump_settings as n


class Settings(unittest.TestCase):
    def settings(self):
        return n.NetdumpSettings('1.1.1.1', '192.168.64.1', 10248, 'a1b2c3d4e5f60708')

    def test_frozen_record_roundtrip_fixed_tokens_and_stable_digest(self):
        settings = self.settings()
        record = {'receiver_ipv4': '1.1.1.1', 'router_ipv4': '192.168.64.1',
                  'port': 10248, 'corename': 'a1b2c3d4e5f60708'}
        self.assertEqual(settings.record(), record)
        self.assertEqual(n.NetdumpSettings.from_record(record), settings)
        self.assertEqual(settings.tokens(), ('_panicd_ip=1.1.1.1', '_router_ip=192.168.64.1',
                                             'panicd_port=10248', '_panicd_corename=a1b2c3d4e5f60708'))
        self.assertEqual(settings.digest(), 'ab8ef1774351437b19806bfcd7852b4cde4c9d596d1fef39ccba6593282c4d53')
        record['port'] = 1234
        self.assertEqual(settings.port, 10248)
        with self.assertRaises(dataclasses.FrozenInstanceError): settings.port = 1234

    def test_settings_reject_noncanonical_addresses_ports_and_names(self):
        fields = self.settings().record()
        invalid = {
            'receiver_ipv4': ['01.1.1.1', '1.1.1.1 ', 'localhost', '::1', '192.168.1.1', '0.0.0.0', '127.0.0.1', '224.0.0.1', True, 16843009],
            'router_ipv4': ['192.168.064.1', '::1', '0.0.0.0', '127.1.2.3', '224.0.0.1',
                            '0.1.2.3', '240.1.2.3', '255.255.255.255', True],
            'port': [0, -1, 65536, 41139, True, 10248.0, '10248'],
            'corename': ['', 'x' * 17, '.', '..', '../x', '/x', 'a\\b', 'a b', 'a\tb', 'a\x00b', 'é', 'a=b', True]}
        for key, values in invalid.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, '^netdump_settings_invalid$'):
                    n.NetdumpSettings.from_record({**fields, key: value})
        for record in ({}, {**fields, 'raw': 'private'}, None, []):
            with self.assertRaisesRegex(ValueError, '^netdump_settings_invalid$'):
                n.NetdumpSettings.from_record(record)
        class Record(dict): pass
        with self.assertRaisesRegex(ValueError, '^netdump_settings_invalid$'):
            n.NetdumpSettings.from_record(Record(fields))
        for gateway in ('10.0.0.1', '172.16.0.1', '192.168.64.1'):
            self.assertEqual(n.NetdumpSettings.from_record({**fields, 'router_ipv4': gateway}).router_ipv4, gateway)

    def test_strip_preserves_remaining_order_and_rejects_owned_aliases_duplicates_or_mismatches(self):
        settings = self.settings()
        tokens = settings.tokens()
        raw = 'alpha=1\t' + tokens[2] + ' beta ' + tokens[0] + ' debug=0x22040 ' + tokens[3] + ' alpha=1 ' + tokens[1]
        self.assertEqual(settings.strip_owned(raw), 'alpha=1 beta debug=0x22040 alpha=1')
        self.assertEqual(settings.strip_owned(raw.encode()), 'alpha=1 beta debug=0x22040 alpha=1')
        for index, token in enumerate(tokens):
            for replacement in ('-' + token, '--' + token, token + 'x', token.partition('=')[0], token + ' ' + token, ''):
                changed = list(tokens)
                changed[index] = replacement
                with self.subTest(token=token, replacement=replacement), self.assertRaisesRegex(ValueError, '^netdump_active_control_invalid$'):
                    settings.strip_owned(' '.join(changed))

    def test_active_control_uses_one_capture_and_keeps_full_and_remaining_profiles(self):
        settings = self.settings()
        raw = 'alpha=1 beta alpha=1 debug=0x22040 ' + ' '.join(settings.tokens())
        result = n.active_control(raw, settings, boot.boot_argument_profile('alpha=1 beta alpha=1'))
        self.assertEqual(set(result), {'status', 'settings_sha256', 'full_profile', 'remaining_profile'})
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['settings_sha256'], settings.digest())
        self.assertEqual(result['full_profile']['debug_mask'], 0x22040)
        self.assertEqual(result['full_profile']['nondebug_token_count'], 7)
        self.assertEqual(result['full_profile']['nondebug_sha256'], '627c5d6392614782f16bfa70c47a63484aa965e0f853142d5e3b562dbbd214c9')
        self.assertEqual(result['remaining_profile'], {'status': 'observed', 'debug_mask': 0x22040,
            'nondebug_token_count': 3, 'nondebug_sha256': '11a6f7c443706e6d2af0396c32aa8d5350a93892d43185cdacfe1430b82d9505'})
        self.assertNotIn('1.1.1.1', str(result))
        self.assertEqual(n.active_control(raw.replace(' ', '\t'), settings, boot.boot_argument_profile('alpha=1 beta alpha=1')), result)

    def test_full_profile_keeps_owned_token_order_while_remaining_sequence_stays_equal(self):
        settings = self.settings()
        tokens = settings.tokens()
        raw = 'alpha=1 ' + tokens[2] + ' beta ' + tokens[0] + ' debug=0x22040 ' + tokens[3] + ' alpha=1 ' + tokens[1]
        result = n.active_control(raw, settings, boot.boot_argument_profile('alpha=1 beta alpha=1'))
        self.assertEqual(result['full_profile']['nondebug_sha256'], 'acce15a039825b2c555f9653b94da187542a32df6f90899aa77a31f6ea6a7137')
        self.assertEqual(result['remaining_profile']['nondebug_sha256'], '11a6f7c443706e6d2af0396c32aa8d5350a93892d43185cdacfe1430b82d9505')

    def test_active_control_rejects_foreign_changes_reordering_bad_mask_and_bad_baseline(self):
        settings = self.settings()
        raw = 'alpha=1 beta alpha=1 debug=0x22040 ' + ' '.join(settings.tokens())
        baseline = boot.boot_argument_profile('alpha=1 beta alpha=1')
        for changed in (raw + ' foreign=1', raw.replace('alpha=1 beta', 'beta alpha=1', 1),
                        raw.replace('debug=0x22040', 'debug=0x2000'), raw + ' debug=0x22040',
                        raw.replace('debug=0x22040', ''), b'x\n', True, None, 'é', 'x' * 1024):
            with self.assertRaisesRegex(ValueError, '^netdump_active_control_invalid$'):
                n.active_control(changed, settings, baseline)
        for bad in ({'status': 'unavailable'}, {**baseline, 'debug_mask': 0}, {**baseline, 'nondebug_token_count': True},
                    {**baseline, 'nondebug_sha256': 'bad'}, {**baseline, 'raw': 'private'}, None):
            with self.assertRaisesRegex(ValueError, '^netdump_active_control_invalid$'):
                n.active_control(raw, settings, bad)


if __name__ == '__main__':
    unittest.main()
