import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('probe', pathlib.Path(__file__).with_name('nvram-runtime-code.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class TestParsing(unittest.TestCase):
    def test_symbols_are_exact_and_deduplicated(self):
        lines = ['0000000000001234 T __ZN13AppleEFINVRAM4syncEv',
                 '0000000000001234 T __ZN13AppleEFINVRAM4syncEv',
                 '0000000000001235 T __ZN13AppleEFINVRAM11setVariableEv',
                 '0000000000001236 T __ZN13AppleEFINVRAM8readDataEv',
                 '0000000000001237 T __ZN10OtherClass4syncEv',
                 '0000000000001238 T __ZN15AppleEFIRuntime11setVariableEv']
        self.assertEqual(probe.select_symbols(lines), ['__ZN13AppleEFINVRAM4syncEv', '__ZN13AppleEFINVRAM11setVariableEv', '__ZN15AppleEFIRuntime11setVariableEv'])

    def test_disassembly_requires_exact_heading_and_bounds(self):
        name = '__ZN13AppleEFINVRAM4syncEv'
        correct = '0000000000001234 <__ZN13AppleEFINVRAM4syncEv>:\n 1234: pushq %rbp\n 1235: retq\n0000000000001236 <_next>:\n 1236: retq\n'
        self.assertEqual(probe.function_instructions(correct, name, 0x1234, 0x1236), [' 1234: pushq %rbp', ' 1235: retq'])
        self.assertEqual(probe.function_instructions(' 1234: pushq %rbp\n', name, 0x1234, 0x1236), [])
        self.assertEqual(probe.function_instructions(correct.replace(name, '_other'), name, 0x1234, 0x1236), [])
        self.assertEqual(probe.function_instructions(correct.replace(' 1235:', ' 1240:'), name, 0x1234, 0x1236), [])

    def test_real_macho_symbol_selection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder)
            (path / 'f.c').write_text('int requested(int x){return x+17;}\nint other(int x){return x+29;}\n')
            subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O0', '-c', str(path / 'f.c'), '-o', str(path / 'f.o')], check=True, capture_output=True)
            nm = subprocess.run(['xcrun', 'nm', '-n', str(path / 'f.o')], check=True, capture_output=True, text=True).stdout
            start, end = probe.symbol_bounds(nm, ['_requested'])['_requested']
            def extract(name):
                result = subprocess.run(['xcrun', 'llvm-objdump', '--macho', '--arch=x86_64', '--disassemble', '--no-show-raw-insn', '--dis-symname', name, str(path / 'f.o')], check=True, capture_output=True, text=True)
                return probe.function_instructions(result.stdout, name, start, end)
            lines = extract('_requested')
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
