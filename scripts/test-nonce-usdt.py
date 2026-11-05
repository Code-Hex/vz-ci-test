import dataclasses
import unittest

import nonce_usdt as usdt


class NonceUsdt(unittest.TestCase):
    def test_identity_derives_literal_provider_function_selector_and_predicate(self):
        spec = usdt.ProbeSpec('0123456789abcdef' * 4)
        probe = spec.bind(123)
        self.assertEqual(spec.provider, 'vzobs0123456789abcdefp')
        self.assertEqual(spec.argument, '0123456789abcdef')
        self.assertEqual(spec.function, 'vz_nonce_' + '0123456789abcdef' * 4)
        self.assertEqual(probe.fields, ('vzobs0123456789abcdefp123', 'helper', 'vz_nonce_' + '0123456789abcdef' * 4, 'observe'))
        self.assertEqual(probe.selector, 'vzobs0123456789abcdefp123:helper:vz_nonce_' + '0123456789abcdef' * 4 + ':observe')
        self.assertEqual(probe.predicate, ' /pid == 123 && arg0 == 0x0123456789abcdef/ ')
        for value, key in ((spec, 'nonce'), (probe, 'pid'), (probe, 'spec')):
            with self.assertRaises(dataclasses.FrozenInstanceError): setattr(value, key, None)

    def test_invalid_nonce_and_pid_cannot_form_partial_identity(self):
        spec = usdt.ProbeSpec('a' * 64)
        for value in ('A' * 64, 'a' * 63, 'a' * 65, 'a' * 63 + '\n', b'a' * 64, True, None):
            with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.ProbeSpec(value)
        for value in (True, 0, -1, 2**31, '123', None):
            with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): spec.bind(value)
        for value in (None, 'a' * 64):
            with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.ProbeIdentity(value, 123)

    def test_provider_and_function_sources_are_literal_c_fragments(self):
        spec = usdt.ProbeSpec('a' * 64)
        self.assertEqual(usdt.provider_source(spec), b'provider vzobsaaaaaaaaaaaaaaaap { probe observe(unsigned long long); };\n')
        self.assertEqual(usdt.function_source(spec),
                         b'__attribute__((noinline,used,visibility("default"))) void vz_nonce_' + b'a' * 64 +
                         b'(void) {\n    VZOBSAAAAAAAAAAAAAAAAP_OBSERVE(0xaaaaaaaaaaaaaaaaULL);\n}\n')
        for function in (usdt.provider_source, usdt.function_source):
            with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): function('a' * 64)

    def test_header_accepts_only_generated_macro_of_this_spec(self):
        spec = usdt.ProbeSpec('a' * 64)
        self.assertTrue(usdt.validate_header(b'#define VZOBSAAAAAAAAAAAAAAAAP_OBSERVE(arg0) whatever\n', spec))
        with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.validate_header(b'', None)
        for raw in (b'', b'#define FOREIGN_OBSERVE(arg0) x\n', b'\xff', b'x' * 65537, 'not bytes'):
            with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.validate_header(raw, spec)

    def test_listing_requires_all_rows_to_match_fullnonce_and_owned_pid(self):
        probe = usdt.ProbeSpec('a' * 64).bind(123)
        header = b'ID PROVIDER MODULE FUNCTION NAME\n'
        row = b'7 vzobsaaaaaaaaaaaaaaaap123 helper vz_nonce_' + b'a' * 64 + b' observe\n'
        self.assertEqual(usdt.parse_listing(header + row, probe), 1)
        self.assertEqual(usdt.parse_listing(header + row + row.replace(b'7 ', b'8 '), probe), 2)
        maximum = header + b''.join(str(number).encode() + row[row.index(b' '):] for number in range(1, 33))
        self.assertEqual(usdt.parse_listing(maximum, probe), 32)
        with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.parse_listing(header + row, None)
        for raw in (header, header + row + row, header + row.replace(b'123', b'124'),
                    header + row.replace(b'helper', b'foreign'), header + row.replace(b'vzobs', b'other'),
                    header + row.replace(b'observe', b'entry'), header + row.replace(b'a' * 64, b'a' * 63 + b'b'),
                    header + row.replace(b'vz_nonce_' + b'a' * 64, b'main'),
                    header + row + row.replace(b'7 ', b'8 ').replace(b'123', b'124'),
                    header + row.replace(b'7 ', b'0 '), maximum + row.replace(b'7 ', b'33 '), b'\xff', b'x' * 65537, 'not bytes'):
            with self.subTest(raw=raw[:40]):
                with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.parse_listing(raw, probe)

    def test_hit_requires_exact_fullnonce_pid_provider_module_probe_and_arg0(self):
        probe = usdt.ProbeSpec('a' * 64).bind(123)
        line = b'HIT 123 vzobsaaaaaaaaaaaaaaaap123 helper vz_nonce_' + b'a' * 64 + b' observe aaaaaaaaaaaaaaaa\n'
        usdt.parse_hit(line, probe)
        with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.parse_hit(line, None)
        for raw in (line.replace(b'HIT 123 ', b'HIT 124 '), line.replace(b'p123 ', b'p124 '),
                    line.replace(b'vzobs', b'other'), line.replace(b'helper', b'foreign'),
                    line.replace(b'observe', b'entry'), line.replace(b'a' * 64, b'a' * 63 + b'b'),
                    line.replace(b'vz_nonce_' + b'a' * 64, b'main'), line[:-17] + b'0' * 16 + b'\n',
                    line + b'extra\n', line + line, line.replace(b'\n', b'\r\n'), 'not bytes'):
            with self.subTest(raw=raw[:40]):
                with self.assertRaisesRegex(ValueError, '^invalid_usdt_probe$'): usdt.parse_hit(raw, probe)


if __name__ == '__main__': unittest.main()
