import importlib.util
import hashlib
import json
import os
import sys
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


    def test_stage_writer_uses_bounded_nonblocking_pipe_and_tolerates_lost_reader(self):
        code = """
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('arrival', sys.argv[1])
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
r, w = os.pipe(); r2 = os.dup(r); os.dup2(w, 3)
a.pipe_stage('imports_done')
assert os.read(r2, 100) == b'imports_done\\n'
assert not os.get_blocking(3)
a.pipe_stage('raw secret'); a.pipe_stage(None)
os.set_blocking(r2, False)
try: os.read(r2, 1)
except BlockingIOError: pass
else: raise AssertionError('unknown stage written')
while True:
    try: os.write(3, b'x' * 4096)
    except BlockingIOError: break
a.pipe_stage('core_saved')
os.close(r2)
a.pipe_stage('core_saved')
os.close(3)
a.pipe_stage('core_saved')
"""
        subprocess.run([sys.executable, '-c', code, a.__file__], check=True, timeout=5)

    def test_observed_shell_posts_scoped_enums_once_and_preserves_python_exit_fact(self):
        for boot, mode in ((NEW, 'begin-nonce-control'), (OLD, 'begin-nonce-control'), (NEW, 'panic-nonce-begin')):
            with self.subTest(boot=boot, mode=mode), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                def executable(name, text):
                    path = directory / name
                    path.write_text('#!/bin/sh\n' + text)
                    path.chmod(0o700)
                    return str(path)
                python = executable('python', 'printf "RAW_PRIVATE\\n"\nprintf "%s\\n" "$@" > "' + tmp + '/python.args"\n'
                    'if [ "$2" = collect-observed ]; then printf "%s\\n" ' + ' '.join(a.STAGES + a.STAGES + ('raw-secret',)) + ' >&3; fi\nexit 7\n')
                sysctl = executable('sysctl', 'case "$2" in kern.bootsessionuuid) printf ' + boot + ';; kern.uuid) printf ' + NEW + ';; *) printf 1;; esac\n')
                uname = executable('uname', 'case "$1" in -s) printf Darwin;; *) printf x86_64;; esac\n')
                curl_path = directory / 'curl'
                curl_path.write_text('#!' + sys.executable + '\nimport os, sys\nfrom pathlib import Path\n'
                    'body = sys.argv[sys.argv.index("--data-binary") + 1]\n'
                    'data = sys.stdin.buffer.read() if body == "@-" else Path(body[1:]).read_bytes()\n'
                    'fd = os.open(' + repr(str(directory / 'posts')) + ', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n'
                    'os.write(fd, data + b"\\n"); os.close(fd)\nprint("201", end="")\n')
                curl_path.chmod(0o700)
                curl = str(curl_path)
                config = self.config(python)
                config['context']['after_debug_boot'] = mode
                config['debug_source_identity'] = 'c' * 64
                config['arrival_api_ipv4'] = '140.82.114.6'
                (directory / 'arrival.headers').write_bytes(a.authorization_header('synthetic-token'))
                script = a.render(config, directory).decode()
                for old, new in (('/usr/sbin/sysctl', sysctl), ('/usr/bin/uname', uname), ('/usr/bin/curl', curl)):
                    script = script.replace(old, new)
                result = subprocess.run(['/usr/bin/env', '-i', '/bin/sh'], input=script.encode(), capture_output=True, timeout=10)
                self.assertEqual(result.stdout, b'RAW_PRIVATE\n')
                posts = [json.loads(line) for line in (directory / 'posts').read_text().splitlines()] if (directory / 'posts').exists() else []
                stages = [json.loads(item['output']['summary']) for item in posts if item['name'].startswith('Collector stage ')]
                observed = boot == NEW and mode == 'begin-nonce-control'
                self.assertEqual([item['stage'] for item in stages], list(a.STAGES) if observed else [])
                self.assertEqual(len(stages), 24 if observed else 0)
                self.assertEqual((directory / 'python.args').read_text().splitlines()[1], 'collect-observed' if observed else 'collect')
                for item in stages:
                    self.assertEqual(item['actual_boot_uuid'], NEW)
                    self.assertEqual(item['baseline_boot_uuid'], OLD)
                    self.assertEqual(item['source_identity'], 'c' * 64)
                    self.assertEqual(item['phase'], 'collector_stage')
                if boot == NEW:
                    exit_post = next(item for item in posts if item['name'].startswith('Recovery exit '))
                    self.assertEqual(json.loads(exit_post['output']['summary'])['exit_code'], 7)
                self.assertNotIn('RAW_PRIVATE', json.dumps(posts))
                self.assertNotIn('raw-secret', json.dumps(posts))
                self.assertNotIn('synthetic-token', json.dumps(posts))
                if observed:
                    saved_posts = (directory / 'posts').read_bytes()
                    again = subprocess.run(['/usr/bin/env', '-i', '/bin/sh'], input=script.encode(), capture_output=True, timeout=10)
                    self.assertEqual(again.stdout, b'RAW_PRIVATE\n')
                    self.assertEqual(again.returncode, 7)
                    self.assertEqual((directory / 'python.args').read_text().splitlines()[1], 'collect')
                    self.assertEqual((directory / 'posts').read_bytes(), saved_posts)


    def test_observed_render_requires_pinned_source_and_public_address(self):
        config = self.config()
        config['context']['after_debug_boot'] = 'begin-nonce-control'
        config['debug_source_identity'] = 'c' * 64
        for address in ('', '127.0.0.1', 'not-an-address'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                a.render(dict(config, arrival_api_ipv4=address), Path('/var/root/example'))
        config['arrival_api_ipv4'] = '140.82.114.6'
        for source in (None, '', 'x' * 64):
            with self.subTest(source=source), self.assertRaises(ValueError):
                a.render(dict(config, debug_source_identity=source), Path('/var/root/example'))
        script = a.render(config, Path('/var/root/example'))
        subprocess.run(['/bin/sh', '-n'], input=script, check=True)
        self.assertIn(b'--resolve api.github.com:443:140.82.114.6', script)
        self.assertIn(b'--data-binary @-', script)

    def test_shell_stage_survives_closed_pipe(self):
        script = a.SHELL_STAGE + '\nexec 4>&1\n{ exec 3>&1 1>&4; /bin/sleep 0.1; stage python_dispatch; printf survived; } | :\n'
        result = subprocess.run(['/bin/sh'], input=script.encode(), capture_output=True, timeout=5)
        self.assertEqual(result.stdout, b'survived')


if __name__ == "__main__":
    unittest.main()
