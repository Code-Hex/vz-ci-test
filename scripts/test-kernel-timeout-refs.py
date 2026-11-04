import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("refs", Path(__file__).with_name("kernel-timeout-refs.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class References(unittest.TestCase):
    def test_real_macho_symbolized_reads_and_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "control.c"
            binary = root / "control"
            source.write_text("volatile unsigned long long needle=1; __attribute__((noinline)) unsigned long long readit(void){return needle;} __attribute__((noinline)) void writeit(unsigned long long x){needle=x;} int main(void){writeit(readit());return 0;}")
            subprocess.run(["xcrun", "clang", "-target", "x86_64-apple-macos12", "-O1", str(source), "-o", str(binary)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            address = r.find_symbol(subprocess.check_output(["xcrun", "nm", "-n", str(binary)], text=True), "_needle")
            process = subprocess.Popen(["xcrun", "llvm-objdump", "--disassemble", "--symbolize-operands", "--no-show-raw-insn", str(binary)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            result = r.parse_disassembly(process.stdout, address, "_needle", "_readit")
            self.assertEqual(process.wait(), 0)
            process.stdout.close()
            self.assertTrue(result["known_handler_xref"])
            self.assertTrue({"_readit", "_writeit"}.issubset({x["function"] for x in result["functions"]}))
            access = {x["function"]: x["access"] for x in result["references"]}
            self.assertEqual(access["_readit"], "read")
            self.assertEqual(access["_writeit"], "write")
            plain = subprocess.Popen(["xcrun", "llvm-objdump", "--disassemble", "--no-show-raw-insn", str(binary)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            plain_result = r.parse_disassembly(plain.stdout, address, "_needle", "_readit")
            self.assertEqual(plain.wait(), 0)
            plain.stdout.close()
            self.assertTrue(plain_result["known_handler_xref"])
            self.assertTrue({"_readit", "_writeit"}.issubset({x["function"] for x in plain_result["functions"]}))
            self.assertTrue(r.positive_control())

    def test_bounded_context_and_no_symbol_suffix(self):
        lines = ["0000000000001000 <_handler>:\n"]
        lines += [f"{0x1000 + i:x}: movq <_target>\n" for i in range(80)]
        lines += ["2000: movq <_target_other>\n"]
        result = r.parse_disassembly(lines, 0x3000, "_target", "_handler")
        self.assertEqual(result["total_matches"], 80)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["references"]), 64)
        self.assertLessEqual(len(result["functions"][0]["context"]), 15)

    def test_symbol_operand_access(self):
        self.assertEqual(r.reference_access("1000: movq <_target>, %rax", "_target"), "read")
        self.assertEqual(r.reference_access("1000: movq %rax, <_target>", "_target"), "write")
        self.assertEqual(r.reference_access("1000: leaq <_target>, %rax", "_target"), "address")

    def test_calculates_signed_rip_displacement(self):
        lines = ["0000000000001000 <_handler>:\n", "1000: movq -0x10(%rip), %rax\n", "1007: retq\n"]
        result = r.parse_disassembly(lines, 0xff7, "_target", "_handler")
        self.assertEqual(result["total_matches"], 1)
        self.assertTrue(result["known_handler_xref"])


if __name__ == "__main__":
    unittest.main()
