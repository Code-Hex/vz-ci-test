import sys
import unittest

import kdp_registry as r


class Registry(unittest.TestCase):
    def fixture(self):
        node = {'class': None, 'class_returncode': 5, 'parents': ['IOService'],
                'parent_status': 'stopped', 'parent_returncode': -536870208,
                'controller_enabled': {'status': 'observed', 'value': False}}
        return {'scope': 'current_registered_services_not_polled_io_proof', 'queries': {
            'IOPlatformExpertDevice': {'status': 'observed', 'returncode': 0, 'count': 1, 'nodes': [node]},
            'IOKernelDebugger': {'status': 'observed', 'returncode': 0, 'count': 0, 'nodes': []},
            'IOKDP': {'status': 'invalid_iterator', 'returncode': 0, 'count': None, 'nodes': []},
            'IONVRAMController': {'status': 'unavailable', 'returncode': None, 'count': None, 'nodes': []}}}

    def test_sanitize_preserves_fixed_facts_and_returns_an_independent_copy(self):
        value = self.fixture()
        public = r.sanitize_snapshot(value)
        self.assertEqual(public, value)
        value['queries']['IOPlatformExpertDevice']['nodes'][0]['parents'].append('Other')
        self.assertEqual(public['queries']['IOPlatformExpertDevice']['nodes'][0]['parents'], ['IOService'])

    def test_sanitize_rejects_unknown_fields_at_every_public_level(self):
        for location in ((), ('queries',), ('queries', 'IOKDP'),
                         ('queries', 'IOPlatformExpertDevice', 'nodes', 0),
                         ('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'controller_enabled')):
            value = self.fixture()
            target = value
            for key in location: target = target[key]
            target['raw'] = '/private/secret'
            with self.assertRaisesRegex(ValueError, '^registry_snapshot_invalid$'):
                r.sanitize_snapshot(value)

    def test_sanitize_rejects_bad_types_counts_classes_and_bounds(self):
        cases = [(('scope',), 'polled_io_proven'), (('queries',), {}),
                 (('queries', 'IOKDP', 'nodes'), ()),
                 (('queries', 'IOKDP', 'status'), 'unknown'),
                 (('queries', 'IOKDP', 'count'), 0),
                 (('queries', 'IOKDP', 'returncode'), True),
                 (('queries', 'IOKDP', 'returncode'), 2**31),
                 (('queries', 'IOPlatformExpertDevice', 'returncode'), 5),
                 (('queries', 'IOPlatformExpertDevice', 'count'), True),
                 (('queries', 'IOPlatformExpertDevice', 'count'), 2),
                 (('queries', 'IOPlatformExpertDevice', 'nodes'), []),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'class'), '/private/path'),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'class'), 'x' * 128),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'class'), 'Class\x00raw'),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'class_returncode'), False),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'parent_returncode'), None),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'parent_status'), 'unknown'),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'parents'), ['IOService'] * 9),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'parents'), ['/private/path']),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'controller_enabled', 'value'), 0),
                 (('queries', 'IOPlatformExpertDevice', 'nodes', 0, 'controller_enabled', 'status'), 'unknown')]
        for path, replacement in cases:
            with self.subTest(path=path, replacement=replacement):
                value = self.fixture()
                target = value
                for key in path[:-1]: target = target[key]
                target[path[-1]] = replacement
                with self.assertRaisesRegex(ValueError, '^registry_snapshot_invalid$'):
                    r.sanitize_snapshot(value)
        value = self.fixture()
        query = value['queries']['IOPlatformExpertDevice']
        query['nodes'] *= 65
        query['count'] = 65
        with self.assertRaises(ValueError): r.sanitize_snapshot(value)
        for status in ('unavailable', 'noncanonical'):
            value = self.fixture()
            enabled = value['queries']['IOPlatformExpertDevice']['nodes'][0]['controller_enabled']
            enabled.update(status=status, value=None)
            self.assertEqual(r.sanitize_snapshot(value), value)
            enabled['value'] = False
            with self.assertRaises(ValueError): r.sanitize_snapshot(value)

    def test_sanitize_accepts_exact_caps_and_partial_query_facts(self):
        value = self.fixture()
        query = value['queries']['IOPlatformExpertDevice']
        query['nodes'][0]['parents'] = ['IOService'] * 8
        query['nodes'] *= 64
        query['count'] = 64
        self.assertEqual(r.sanitize_snapshot(value), value)
        for status in ('truncated', 'invalid_iterator', 'error', 'unavailable'):
            query.update(status=status, count=None)
            self.assertEqual(r.sanitize_snapshot(value), value)

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
        self.assertEqual(r.sanitize_snapshot(result), result)
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
