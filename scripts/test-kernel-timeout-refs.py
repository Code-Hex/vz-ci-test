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
            self.assertTrue({"_readit", "_writeit"}.issubset({x["symbol_hint"] for x in result["symbol_hints"]}))
            access = {x["symbol_hint"]: x["access"] for x in result["references"]}
            self.assertEqual(access["_readit"], "read")
            self.assertEqual(access["_writeit"], "write")
            plain = subprocess.Popen(["xcrun", "llvm-objdump", "--disassemble", "--no-show-raw-insn", str(binary)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            plain_result = r.parse_disassembly(plain.stdout, address, "_needle", "_readit")
            self.assertEqual(plain.wait(), 0)
            plain.stdout.close()
            self.assertTrue(plain_result["known_handler_xref"])
            self.assertTrue({"_readit", "_writeit"}.issubset({x["symbol_hint"] for x in plain_result["symbol_hints"]}))
            self.assertTrue(r.positive_control())

    def test_stripped_handler_still_scans_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, binary = root / "control.c", root / "control"
            source.write_text("volatile unsigned long long needle=1; __attribute__((noinline)) static unsigned long long reader(void){return needle;} int main(void){return (int)reader();}")
            subprocess.run(["xcrun", "clang", "-target", "x86_64-apple-macos12", "-O1", str(source), "-o", str(binary)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["xcrun", "strip", "-x", str(binary)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            nm = subprocess.check_output(["xcrun", "nm", "-n", str(binary)], text=True)
            self.assertNotIn("_reader", nm)
            metadata = []
            result = r.analyze_binary(binary, nm, "_needle", "_reader", on_metadata=metadata.append)
            self.assertEqual(metadata[0]["reason_enum"], "handler_missing")
            self.assertIn("target_address", metadata[0])
            self.assertNotIn("references", metadata[0])
            self.assertEqual(result["status"], "unsupported")
            self.assertEqual(result["reason_enum"], "handler_missing")
            self.assertFalse(result["known_handler_xref"])
            self.assertGreaterEqual(result["total_matches"], 1)
            self.assertIn("target_address", result)
            self.assertTrue(result["symbol_hints"])

    def test_target_missing_reason(self):
        result = r.analyze_binary("not-opened", "0000000000001000 T _handler\n", "_target", "_handler")
        self.assertEqual(result["reason_enum"], "target_missing")
        self.assertEqual(result["status"], "unsupported")

    def test_bounded_context_and_no_symbol_suffix(self):
        lines = ["0000000000001000 <_handler>:\n"]
        lines += [f"{0x1000 + i:x}: movq <_target>\n" for i in range(80)]
        lines += ["2000: movq <_target_other>\n"]
        result = r.parse_disassembly(lines, 0x3000, "_target", "_handler")
        self.assertEqual(result["total_matches"], 80)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["references"]), 64)
        self.assertLessEqual(len(result["symbol_hints"][0]["context"]), 15)

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
