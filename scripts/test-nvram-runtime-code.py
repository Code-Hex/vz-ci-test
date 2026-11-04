import importlib.util
import pathlib
import re
import subprocess
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('probe', pathlib.Path(__file__).with_name('nvram-runtime-code.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class TestParsing(unittest.TestCase):
    def test_disassembly_requires_exact_heading_and_bounds(self):
        name = '__ZN13AppleEFINVRAM4syncEv'
        correct = '0000000000001234 <__ZN13AppleEFINVRAM4syncEv>:\n 1234: pushq %rbp\n 1235: retq\n0000000000001236 <_next>:\n 1236: retq\n'
        self.assertEqual(probe.function_instructions(correct, name, 0x1234, 0x1236), [' 1234: pushq %rbp', ' 1235: retq'])
        self.assertEqual(probe.function_instructions(' 1234: pushq %rbp\n', name, 0x1234, 0x1236), [])
        self.assertEqual(probe.function_instructions(correct.replace(name, '_other'), name, 0x1234, 0x1236), [])
        self.assertEqual(probe.function_instructions(correct.replace(' 1235:', ' 1240:'), name, 0x1234, 0x1236), [])

    def test_streaming_census_keeps_member_boundaries_and_rank(self):
        lines = ['member-a:', '00000001 T __ZN13AppleEFINVRAM5startEv',
                 '00000010 T __ZN13AppleEFINVRAM4syncEv', '00000020 T __ZN13AppleEFINVRAM11setVariableEv',
                 '00000030 T _next', 'member-b:',
                 '00000001 T __ZN13AppleEFINVRAM4syncEv', '00000010 T _end']
        census = probe.SymbolCensus()
        for line in lines: census.feed(line)
        result = census.finish()
        self.assertEqual(result['target_count'], 4)
        self.assertEqual(result['candidates'][0]['name'], '__ZN13AppleEFINVRAM11setVariableEv')
        self.assertEqual(result['candidates'][0]['start'], 0x20)
        self.assertEqual(result['candidates'][0]['end'], 0x30)
        self.assertTrue(all(c['ambiguous'] for c in result['candidates'] if c['name'].endswith('4syncEv')))

    def test_candidate_limit_and_order_reversal(self):
        census = probe.SymbolCensus()
        for i in range(25):
            census.feed(f'{i:08x} T __ZN13AppleEFINVRAM5start{i}Ev')
        census.feed('00000019 T __ZN13AppleEFINVRAM11setVariableEv')
        census.feed('0000001a T _next')
        result = census.finish()
        self.assertEqual(result['target_count'], 26)
        self.assertEqual(len(result['candidates']), 24)
        self.assertIn('setVariable', result['candidates'][0]['name'])
        reverse = probe.SymbolCensus()
        reverse.feed('00000010 T __ZN13AppleEFINVRAM4syncEv')
        reverse.feed('00000020 T _next')
        reverse.feed('00000001 T _out_of_order')
        self.assertTrue(reverse.finish()['candidates'][0]['ambiguous'])

    def test_real_macho_symbol_selection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder)
            (path / 'f.cc').write_text('struct AppleEFINVRAM { int sync(int); int setVariable(int); };\nint AppleEFINVRAM::sync(int x){return x+17;}\nint AppleEFINVRAM::setVariable(int x){return x+29;}\n')
            subprocess.run(['xcrun', 'clang++', '-arch', 'x86_64', '-O0', '-c', str(path / 'f.cc'), '-o', str(path / 'f.o')], check=True, capture_output=True)
            status, result = probe.nm_census(['xcrun', 'nm', '-n', str(path / 'f.o')], time.monotonic() + 10)
            self.assertEqual(status, 'ok')
            candidate = next(c for c in result['candidates'] if '4syncE' in c['name'])
            self.assertFalse(candidate['ambiguous'])
            start, end = candidate['start'], candidate['end']
            def extract(name):
                result = subprocess.run(['xcrun', 'llvm-objdump', '--macho', '--arch=x86_64', '--disassemble', '--no-show-raw-insn', '--dis-symname', name, str(path / 'f.o')], check=True, capture_output=True, text=True)
                return probe.function_instructions(result.stdout, name, start, end)
            lines = extract(candidate['name'])
            self.assertTrue(lines)
            self.assertTrue(any('0x11' in line for line in lines))
            self.assertFalse(any('0x1d' in line for line in lines))
            self.assertEqual(extract('_missing'), [])

    def test_plist_summary_never_returns_content(self):
        self.assertEqual(probe.plist_summary({'Kernel Flags': 'secret debug=0x2000'}), {'status': 'observed', 'root_type': 'dictionary', 'kernel_flags_type': 'string', 'debug_present': True})
        self.assertEqual(probe.plist_summary({'Kernel Flags': ['debug=1']}), {'status': 'observed', 'root_type': 'dictionary', 'kernel_flags_type': 'array', 'debug_present': None})
        self.assertEqual(probe.plist_summary([]), {'status': 'observed', 'root_type': 'array', 'kernel_flags_type': 'absent', 'debug_present': None})

if __name__ == '__main__':
    unittest.main()
