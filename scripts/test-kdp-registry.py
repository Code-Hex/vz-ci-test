import sys
import unittest

import kdp_registry as r


class Registry(unittest.TestCase):
    def test_class_names_are_bounded_ascii_and_never_raw_errors(self):
        self.assertEqual(r.decode_class(b'AppleARMPE\x00' + b'\x00' * 117), 'AppleARMPE')
        for raw in (b'x' * 128, b'\x00' * 128, b'/private/path\x00', b'bad\xff\x00', b'a\nb\x00'):
            self.assertIsNone(r.decode_class(raw))

    def test_only_a_complete_valid_iterator_produces_an_exact_count(self):
        self.assertEqual(r.query_result('observed', 0, [])['count'], 0)
        for status in ('truncated', 'invalid_iterator', 'error', 'unavailable'):
            result = r.query_result(status, 5, [{'class': 'IOService'}])
            self.assertIsNone(result['count'])
            self.assertEqual(result['returncode'], 5)
            self.assertEqual(result['nodes'], [{'class': 'IOService'}])

    @unittest.skipUnless(sys.platform == 'darwin', 'requires Darwin IOKit')
    def test_native_fixed_queries_have_a_positive_control_and_filtered_results(self):
        result = r.snapshot()
        self.assertEqual(result['scope'], 'current_registered_services_not_polled_io_proof')
        self.assertEqual(set(result), {'scope', 'queries'})
        self.assertEqual(set(result['queries']), {'IOPlatformExpertDevice', 'IOKernelDebugger', 'IOKDP', 'IONVRAMController'})
        positive = result['queries']['IOPlatformExpertDevice']
        self.assertEqual(positive['status'], 'observed')
        self.assertEqual(positive['returncode'], 0)
        self.assertGreater(positive['count'], 0)
        for query in result['queries'].values():
            self.assertEqual(query['status'], 'observed')
            self.assertEqual(query['returncode'], 0)
            self.assertEqual(set(query), {'status', 'returncode', 'count', 'nodes'})
            self.assertLessEqual(len(query['nodes']), 64)
            if query['status'] == 'observed': self.assertEqual(query['count'], len(query['nodes']))
            else: self.assertIsNone(query['count'])
            for node in query['nodes']:
                self.assertEqual(set(node), {'class', 'class_returncode', 'parents', 'parent_status',
                                             'parent_returncode', 'controller_enabled'})
                self.assertIsNotNone(node['class'])
                self.assertLessEqual(len(node['parents']), 8)
                for name in node['parents']: self.assertIsInstance(name, str)
                enabled = node['controller_enabled']
                self.assertEqual(set(enabled), {'status', 'value'})
                self.assertIn(enabled['status'], ('observed', 'unavailable', 'noncanonical'))
                if enabled['status'] == 'observed': self.assertIs(type(enabled['value']), bool)
                else: self.assertIsNone(enabled['value'])


if __name__ == '__main__':
    unittest.main()
