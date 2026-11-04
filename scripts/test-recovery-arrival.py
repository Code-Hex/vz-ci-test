import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("arrival", Path(__file__).with_name("recovery_arrival.py"))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
OLD = "AAAAAAAA-1111-1111-1111-111111111111"
NEW = "BBBBBBBB-2222-2222-2222-222222222222"


class Arrival(unittest.TestCase):
    def config(self, python="/usr/bin/python3"):
        return {"context": {"repo": "Code-Hex/vz-ci-test", "run_id": "123", "attempt": "1", "sha": "a" * 40},
                "baseline": OLD, "nonce": "b" * 64, "python": python}

    def test_credentials_and_identity_reject_injection(self):
        self.assertEqual(a.authorization_header("test-token"), b"Authorization: Bearer test-token\n")
        for token in ("", "a\rb", "a\nb", "a\x00b", "a b", "x" * 447):
            with self.assertRaises(ValueError):
                a.authorization_header(token)
        for key, value in (("repo", "other"), ("run_id", "1;exit"), ("sha", "bad")):
            config = self.config()
            config["context"][key] = value
            with self.assertRaises(ValueError):
                a.render(config, Path("/var/root/example"))
        config = self.config()
        config["baseline"] = "invalid"
        with self.assertRaises(ValueError):
            a.render(config, Path("/var/root/example"))
        config = self.config()
        config["arrival_api_ipv4"] = "127.0.0.1"
        with self.assertRaises(ValueError):
            a.render(config, Path("/var/root/example"))

    def test_generated_shell_syntax_and_curl_policy(self):
        script = a.render(self.config(), Path("/var/root/example"))
        subprocess.run(["/bin/sh", "-n"], input=script, check=True)
        self.assertIn(b"/usr/bin/curl --disable", script)
        self.assertIn(b"--connect-timeout 3 --max-time 8", script)
        self.assertIn(b'--header "@$directory/arrival.headers"', script)
        self.assertNotIn(b"Authorization: Bearer", script)
        self.assertNotIn(b" --location", script)

    def test_real_shell_with_only_local_command_seams(self):
        for boot, curl_exit in ((NEW, 0), (NEW, 7), (OLD, 0), (OLD.lower(), 0), ('invalid"', 0)):
            with self.subTest(boot=boot, curl_exit=curl_exit), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                def executable(name, text):
                    path = directory / name
                    path.write_text("#!/bin/sh\n" + text)
                    path.chmod(0o700)
                    return str(path)
                python = executable("python", '[ "${SECRET_ENV-x}" = x ] || exit 9\nprintf python >> "' + tmp + '/executed"\n')
                sysctl = executable("sysctl", "case \"$2\" in kern.bootsessionuuid) printf '%s' '" + boot + "';; kern.uuid) printf '%s' '" + NEW + "';; *) printf 1;; esac\n")
                uname = executable("uname", 'case "$1" in -s) printf Darwin;; *) printf x86_64;; esac\n')
                curl = executable("curl", 'printf "%s\\n" "$@" > "' + tmp + '/curl.args"\nprintf 201\nexit ' + str(curl_exit) + '\n')
                script = a.render(self.config(python), directory).decode()
                for original, replacement in (("/usr/sbin/sysctl", sysctl), ("/usr/bin/uname", uname), ("/usr/bin/curl", curl)):
                    script = script.replace(original, replacement)
                path = directory / "arrival.sh"
                path.write_text(script)
                subprocess.run(["/usr/bin/env", "-i", "/bin/sh", str(path)], env={"SECRET_ENV": "not-inherited"}, check=True)
                self.assertEqual((directory / "executed").read_text(), "python")
                expected = boot == NEW
                self.assertEqual((directory / "curl.args").exists(), expected)
                self.assertEqual((directory / ("arrival-" + boot + ".posted")).exists(), expected and curl_exit == 0)
                if expected:
                    body = json.loads((directory / ("arrival-" + boot + ".request.json")).read_text())
                    metadata = json.loads(body["output"]["summary"])
                    self.assertEqual(metadata["actual_boot_uuid"], NEW)
                    self.assertEqual(metadata["python_path_status"], "file_executable")
                    self.assertEqual(metadata["source_generator_sha256"], hashlib.sha256(Path(a.__file__).read_bytes()).hexdigest())
                    self.assertEqual(body["conclusion"], "neutral")
                    self.assertEqual((directory / "curl.args").read_text().splitlines()[0], "--disable")

    def test_python_exit_witness_is_fresh_only_and_skips_completed_cleanup(self):
        for boot, exit_code, cleanup, curl_exit in ((NEW, 7, False, 0), (OLD, 7, False, 0), (NEW, 0, True, 0),
                                                   (NEW, 0, False, 0), (NEW, 7, False, 7)):
            with self.subTest(boot=boot, exit_code=exit_code, cleanup=cleanup, curl_exit=curl_exit), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                def executable(name, text):
                    path = directory / name
                    path.write_text("#!/bin/sh\n" + text)
                    path.chmod(0o700)
                    return str(path)
                (directory / "arrival.headers").write_bytes(a.authorization_header("synthetic-token"))
                commands = 'touch "' + tmp + '/debug-boot-core.json" "' + tmp + '/debug-boot-restored.json" "' + tmp + '/failed.json"\n'
                if cleanup:
                    commands += 'touch "' + tmp + '/completed.json"\nrm "' + tmp + '/arrival.headers"\n'
                python = executable("python", commands + 'exit ' + str(exit_code) + '\n')
                sysctl = executable("sysctl", "case \"$2\" in kern.bootsessionuuid) printf '%s' '" + boot + "';; kern.uuid) printf '%s' '" + NEW + "';; *) printf 1;; esac\n")
                uname = executable("uname", 'case "$1" in -s) printf Darwin;; *) printf x86_64;; esac\n')
                curl = executable("curl", 'printf "call\\n" >> "' + tmp + '/curl.calls"\nprintf 201\nexit ' + str(curl_exit) + '\n')
                script = a.render(self.config(python), directory).decode()
                for original, replacement in (("/usr/sbin/sysctl", sysctl), ("/usr/bin/uname", uname), ("/usr/bin/curl", curl)):
                    script = script.replace(original, replacement)
                path = directory / "arrival.sh"
                path.write_text(script)
                result = subprocess.run(["/usr/bin/env", "-i", "/bin/sh", str(path)], capture_output=True)
                self.assertEqual(result.returncode, exit_code)
                expected = boot == NEW and not cleanup
                body_path = directory / ("python-exit-" + boot + ".request.json")
                self.assertEqual(body_path.exists(), expected)
                if expected:
                    body = json.loads(body_path.read_text())
                    facts = json.loads(body["output"]["summary"])
                    self.assertEqual(body["name"], "Recovery exit 123")
                    self.assertEqual(facts["protocol"], "python-exit-v1")
                    self.assertEqual(facts["actual_boot_uuid"], NEW)
                    self.assertEqual(facts["exit_code"], exit_code)
                    self.assertEqual(facts["files"], {"core_saved": True, "restore_marker": True, "failed": True, "completed": False})
                    self.assertNotIn("synthetic-token", body_path.read_text())
                    self.assertEqual((directory / ("python-exit-" + boot + ".posted")).exists(), curl_exit == 0)
                    before = (directory / "curl.calls").read_bytes()
                    subprocess.run(["/usr/bin/env", "-i", "/bin/sh", str(path)], capture_output=True)
                    self.assertEqual((directory / "curl.calls").read_bytes() == before, curl_exit == 0)


if __name__ == "__main__":
    unittest.main()
