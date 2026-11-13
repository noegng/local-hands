"""End-to-end tests: a real hub, real daemons, real TLS on 127.0.0.1."""

import json
import os
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import unittest

from harness import Rig, _alive, lh_core, wait_for


def tls_connect(rig, timeout=5):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", rig.port), timeout=timeout)
    return ctx.wrap_socket(raw)


def hello(rig, frame):
    """Send one pre-auth frame as a daemon would; return the hub's reply (or None)."""
    conn = tls_connect(rig)
    try:
        conn.sendall(lh_core.MAGIC + lh_core.encode_frame(frame))
        return lh_core.recv_frame(conn)
    except (OSError, ValueError):
        return None
    finally:
        conn.close()


class Exec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rig = Rig()
        cls.rig.join("mac")

    @classmethod
    def tearDownClass(cls):
        cls.rig.close()

    def test_runs_in_the_daemons_workspace(self):
        code, out = self.rig.run("pwd")
        self.assertEqual((code, out.decode().strip()), (0, self.rig.workspace("mac")))

    def test_exit_status_is_the_remote_one(self):
        for wanted in (0, 1, 3, 127, 255):
            self.assertEqual(self.rig.run("exit %d" % wanted)[0], wanted)

    def test_death_by_signal_reads_like_a_shell(self):
        self.assertEqual(self.rig.run("kill -9 $$")[0], 137)

    def test_stdout_and_stderr_are_merged_in_order(self):
        code, out = self.rig.run("echo one; echo two >&2; echo three")
        self.assertEqual(out, b"one\ntwo\nthree\n")

    def test_stdin_is_relayed(self):
        code, out = self.rig.run("cat | tr a-z A-Z", stdin=b"from the brain\n")
        self.assertEqual((code, out), (0, b"FROM THE BRAIN\n"))

    def test_large_stdin_and_stdout(self):
        blob = os.urandom(1_500_000)
        code, out = self.rig.run("cat", stdin=blob, timeout=60)
        self.assertEqual(code, 0)
        self.assertEqual(out, blob)

    def test_binary_and_invalid_utf8_output_is_untouched(self):
        code, out = self.rig.run(r"printf '\377\376\000ok\n'")
        self.assertEqual(out, b"\xff\xfe\x00ok\n")

    def test_multiline_script_with_quotes(self):
        script = "x='a \"b\" $c'\ncat <<'EOF'\nline $x `nope`\nEOF\necho \"$x\""
        code, out = self.rig.run(script)
        self.assertEqual(out.decode(), "line $x `nope`\na \"b\" $c\n")

    def test_environment_marks_the_run(self):
        code, out = self.rig.run('echo "$LOCAL_HANDS/$LOCAL_HANDS_BRAIN"')
        self.assertEqual(out.decode().strip(), "1/test-brain")

    def test_commands_run_concurrently(self):
        start = time.time()
        procs = [self.rig.popen("sleep 1; echo %d" % i) for i in range(6)]
        outs = sorted(p.communicate(timeout=20)[0] for p in procs)
        self.assertEqual(outs, [b"%d\n" % i for i in range(6)])
        self.assertLess(time.time() - start, 4)

    def test_killing_the_client_kills_the_remote_process_group(self):
        marker = "lh-kill-%d" % os.getpid()
        proc = self.rig.popen("echo started; (sleep 300; echo %s) & sleep 300 # %s" % (marker, marker))
        self.assertEqual(proc.stdout.readline(), b"started\n")
        self.assertTrue(_pgrep(marker))
        proc.kill()
        proc.wait()
        self.assertTrue(wait_for(lambda: not _pgrep(marker), 6), "remote processes survived the kill")
        self.assertEqual(self.rig.run("echo still-serving")[1], b"still-serving\n")

    def test_unknown_machine(self):
        code, out = self.rig.run("echo x", machine="nope")
        self.assertEqual(code, lh_core.EXIT_LINK)
        self.assertIn(b"[local-hands] no machine named 'nope'", out)

    def test_empty_script(self):
        code, out = self.rig.run("  \n")
        self.assertEqual(code, 2)

    def test_audit_log_on_the_brain(self):
        self.rig.run("true", display="audit-marker-brain", session="sess-42")
        entries = self.rig.rpc(op="log", n=50)["entries"]
        mine = [e for e in entries if e.get("command") == "audit-marker-brain"]
        self.assertEqual(len(mine), 1)
        self.assertEqual((mine[0]["machine"], mine[0]["exit"], mine[0]["session"]), ("mac", 0, "sess-42"))
        self.assertEqual(os.stat(self.rig.data / "audit.jsonl").st_mode & 0o077, 0)

    def test_audit_log_on_the_machine(self):
        self.rig.run("exit 4", display="audit-marker-machine")
        path = os.path.join(self.rig.config_home("mac"), "local-hands", "audit.jsonl")
        wait_for(lambda: os.path.exists(path) and "audit-marker-machine" in open(path).read(), 5)
        entries = [json.loads(line) for line in open(path)]
        mine = [e for e in entries if e.get("command") == "audit-marker-machine"]
        self.assertEqual(mine[0]["exit"], 4)
        self.assertEqual(mine[0]["brain"], "test-brain")
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)

    def test_status_describes_the_machine(self):
        machine = self.rig.machine("mac")
        self.assertTrue(machine["online"])
        self.assertEqual(machine["workspace"], self.rig.workspace("mac"))
        self.assertEqual(machine["approve"], "auto")
        self.assertIn(machine["os"], ("Darwin", "Linux"))

    def test_daemon_source_is_served_pinned(self):
        target = self.rig.tmp / "fetched.py"
        done = subprocess.run(["curl", "-fsSk", "--pinnedpubkey", "sha256//" + self.rig.pin,
                               "https://127.0.0.1:%d/hands.py" % self.rig.port, "-o", str(target)],
                              capture_output=True)
        if done.returncode in (2, 48, 91):
            self.skipTest("this curl has no --pinnedpubkey support")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(target.read_bytes(), open(os.path.join(os.path.dirname(lh_core.__file__), "hands.py"), "rb").read())

    def test_wrong_pin_makes_curl_refuse(self):
        done = subprocess.run(["curl", "-fsSk", "--pinnedpubkey", "sha256//" + "A" * 43 + "=",
                               "https://127.0.0.1:%d/hands.py" % self.rig.port, "-o", os.devnull],
                              capture_output=True)
        if done.returncode in (2, 48, 91):
            self.skipTest("this curl has no --pinnedpubkey support")
        self.assertNotEqual(done.returncode, 0)

    def test_only_the_daemon_source_is_served(self):
        for path in ("/", "/devices.json", "/../devices.json", "/tls/key.pem", "/hands.py/../lh_core.py"):
            conn = tls_connect(self.rig)
            conn.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
            reply = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                reply += chunk
            conn.close()
            self.assertTrue(reply.startswith(b"HTTP/1.1 404"), path)


class Pairing(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()

    def tearDown(self):
        self.rig.close()

    def info(self, **extra):
        return dict({"os": "Linux", "hostname": "evil", "user": "u", "workspace": "/w", "approve": "auto"}, **extra)

    def test_wrong_code_is_rejected(self):
        reply = hello(self.rig, self.info(t="pair", code="a" * 24, name="x"))
        self.assertEqual(reply["t"], "reject")
        self.assertEqual(self.rig.rpc(op="status")["machines"], [])

    def test_code_works_exactly_once(self):
        code = self.rig.rpc(op="invite", name="one")["code"]
        first = hello(self.rig, self.info(t="pair", code=code))
        self.assertEqual((first["t"], first["device"]), ("welcome", "one"))
        self.assertTrue(first["token"])
        second = hello(self.rig, self.info(t="pair", code=code))
        self.assertEqual(second["t"], "reject")

    def test_code_expires(self):
        reply = self.rig.rpc(op="invite", name="late", ttl=1)   # the hub clamps to >= 60 s
        self.assertGreaterEqual(reply["expires"] - time.time(), 55)
        self.assertLessEqual(reply["expires"] - time.time(), 3600)

    def test_token_is_stored_only_as_a_hash(self):
        code = self.rig.rpc(op="invite", name="one")["code"]
        token = hello(self.rig, self.info(t="pair", code=code))["token"]
        stored = (self.rig.data / "devices.json").read_text()
        self.assertNotIn(token, stored)
        self.assertNotIn(code, stored)
        self.assertEqual(os.stat(self.rig.data / "devices.json").st_mode & 0o077, 0)
        for name in ("hub.log", "hub.json"):
            text = (self.rig.data / name).read_text()
            self.assertNotIn(token, text)
            self.assertNotIn(code, text)

    def test_token_authenticates_and_revocation_ends_it(self):
        code = self.rig.rpc(op="invite", name="one")["code"]
        token = hello(self.rig, self.info(t="pair", code=code))["token"]
        self.assertEqual(hello(self.rig, self.info(t="hello", token=token))["t"], "welcome")
        self.assertEqual(hello(self.rig, self.info(t="hello", token=token + "x"))["t"], "reject")
        self.assertEqual(hello(self.rig, self.info(t="hello", token=""))["t"], "reject")
        self.assertTrue(self.rig.rpc(op="revoke", name="one")["ok"])
        reply = hello(self.rig, self.info(t="hello", token=token))
        self.assertEqual((reply["t"], reply.get("revoked")), ("reject", True))
        self.assertFalse(self.rig.rpc(op="revoke", name="one")["ok"])

    def test_names(self):
        self.assertFalse(self.rig.rpc(op="invite", name="brain")["ok"])
        self.assertFalse(self.rig.rpc(op="invite", name="Bad Name")["ok"])
        self.assertFalse(self.rig.rpc(op="invite", name="../x")["ok"])
        # unnamed invites take the hostname, cleaned, and never collide
        for expected in ("my-laptop", "my-laptop-2"):
            code = self.rig.rpc(op="invite")["code"]
            reply = hello(self.rig, self.info(t="pair", code=code, hostname="My Laptop.local"))
            self.assertEqual(reply["device"], expected)
        code = self.rig.rpc(op="invite")["code"]
        self.assertEqual(hello(self.rig, self.info(t="pair", code=code, hostname="brain"))["device"], "machine")

    def test_repeated_failures_are_throttled(self):
        for _ in range(8):
            self.assertIn("wrong", hello(self.rig, self.info(t="pair", code="b" * 24))["msg"])
        self.assertIn("too many", hello(self.rig, self.info(t="pair", code="b" * 24))["msg"])
        # even a valid code has to wait
        code = self.rig.rpc(op="invite", name="one")["code"]
        self.assertEqual(hello(self.rig, self.info(t="pair", code=code))["t"], "reject")

    def test_oversized_hello_is_dropped(self):
        conn = tls_connect(self.rig)
        conn.sendall(lh_core.MAGIC + struct.pack(">I", lh_core.MAX_HELLO + 1) + b"x" * 1024)
        conn.settimeout(5)
        try:
            self.assertEqual(conn.recv(10), b"")
        except OSError:
            pass
        conn.close()

    def test_garbage_does_not_hurt_the_hub(self):
        for blob in (b"", b"\x00\x00\x00\x00", b"LH1\n\x00\x00\x00\x02[]", b"LH1\n\x00\x00\x00\x05nope!", b"SSH-2.0-x\r\n"):
            conn = tls_connect(self.rig)
            conn.sendall(blob)
            conn.close()
        raw = socket.create_connection(("127.0.0.1", self.rig.port))
        raw.sendall(b"not tls at all\r\n\r\n")
        raw.close()
        self.assertTrue(self.rig.rpc(op="status")["ok"])

    def test_idle_unauthenticated_connections_are_capped(self):
        held = []
        try:
            for _ in range(12):
                held.append(socket.create_connection(("127.0.0.1", self.rig.port)))
            time.sleep(0.3)
            # this peer is over its share: new connections are dropped at once...
            extra = socket.create_connection(("127.0.0.1", self.rig.port))
            extra.settimeout(3)
            try:
                self.assertEqual(extra.recv(1), b"")
            except OSError:
                pass
            extra.close()
        finally:
            for sock in held:
                sock.close()
        # ...and the hub serves again as soon as they are gone
        self.assertTrue(wait_for(lambda: (hello(self.rig, self.info(t="pair", code="c" * 24)) or {}).get("t") == "reject", 5))

    def test_daemon_refuses_a_host_with_another_key(self):
        invite = self.rig.invite("mac")
        wrong = invite.split("#")[0] + "#" + "A" * 43
        done = subprocess.run(self.rig.daemon_argv("join", wrong, "--approve", "auto", "--workspace", self.rig.workspace("mac")),
                              env=self.rig.daemon_env("mac"), stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"does not hold the key", done.stderr)
        self.assertEqual(self.rig.rpc(op="status")["machines"], [])
        # the code was never sent, so the real invite still works
        self.rig.daemons.append(subprocess.Popen(
            self.rig.daemon_argv("join", invite, "--approve", "auto", "--workspace", self.rig.workspace("mac")),
            env=self.rig.daemon_env("mac"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.assertTrue(self.rig.wait_online("mac"))

    def test_daemon_explains_a_bad_invite(self):
        done = subprocess.run(self.rig.daemon_argv("join", "hands://nope"), env=self.rig.daemon_env("mac"),
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"does not look like a local-hands invite", done.stderr)

    def test_token_file_on_the_machine_is_private(self):
        self.rig.join("mac")
        folder = os.path.join(self.rig.config_home("mac"), "local-hands")
        # the hub sees the machine online a moment before the daemon has written its token file
        def brain_files():
            try:
                return [f for f in os.listdir(folder) if f.startswith("brain-") and not f.endswith(".tmp")]
            except FileNotFoundError:
                return []
        files = wait_for(brain_files, 10)
        self.assertEqual(len(files), 1)
        self.assertEqual(os.stat(os.path.join(folder, files[0])).st_mode & 0o077, 0)
        self.assertEqual(os.stat(folder).st_mode & 0o077, 0)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()

    def tearDown(self):
        self.rig.close()

    def test_offline_machine(self):
        daemon = self.rig.join("mac")
        daemon.terminate()
        daemon.wait(5)
        self.assertTrue(self.rig.wait_online("mac", False))
        code, out = self.rig.run("echo x")
        self.assertEqual(code, lh_core.EXIT_LINK)
        self.assertIn(b"[local-hands] machine 'mac' is offline", out)

    def test_daemon_reconnects_with_its_token(self):
        first = self.rig.join("mac")
        first.terminate()
        first.wait(5)
        self.assertTrue(self.rig.wait_online("mac", False))
        self.rig.up("mac")
        self.assertTrue(self.rig.wait_online("mac"), self.rig.daemon_log("mac"))
        self.assertEqual(self.rig.run("echo back")[1], b"back\n")

    def test_daemon_survives_a_hub_restart(self):
        self.rig.join("mac")
        self.rig.stop_hub()
        time.sleep(0.5)
        lh_core.spawn_hub(self.rig.data, bind="127.0.0.1", port=self.rig.port, brain_name="test-brain")
        self.assertTrue(self.rig.wait_online("mac", timeout=20), self.rig.daemon_log("mac"))
        self.assertEqual(self.rig.run("echo again")[1], b"again\n")
        self.assertIn("reconnected", self.rig.daemon_log("mac"))

    def test_command_waits_for_a_machine_that_is_coming_back(self):
        first = self.rig.join("mac")
        first.terminate()
        first.wait(5)
        self.assertTrue(self.rig.wait_online("mac", False))
        proc = self.rig.popen("echo late", wait=15)
        time.sleep(0.5)
        self.rig.up("mac")
        out, _ = proc.communicate(timeout=20)
        self.assertEqual((proc.returncode, out), (0, b"late\n"))

    def test_machine_dying_mid_command(self):
        daemon = self.rig.join("mac")
        proc = self.rig.popen("echo started; sleep 60")
        self.assertEqual(proc.stdout.readline(), b"started\n")
        daemon.send_signal(signal.SIGKILL)
        out, _ = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, lh_core.EXIT_LINK)
        self.assertIn(b"went offline while the command was running", out)

    def test_ctrl_c_on_the_daemon_stops_its_commands(self):
        marker = "lh-stop-%d" % os.getpid()
        daemon = self.rig.join("mac")
        proc = self.rig.popen("echo started; sleep 300 # " + marker)
        self.assertEqual(proc.stdout.readline(), b"started\n")
        daemon.send_signal(signal.SIGINT)
        daemon.wait(10)
        proc.communicate(timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(wait_for(lambda: not _pgrep(marker), 6))

    def test_revoking_disconnects_and_the_daemon_stops_for_good(self):
        daemon = self.rig.join("mac")
        self.assertTrue(self.rig.rpc(op="revoke", name="mac")["ok"])
        self.assertEqual(daemon.wait(10), 3)
        log = self.rig.daemon_log("mac")   # told directly, or on its immediate reconnect attempt
        self.assertTrue("unpaired" in log or "revoked" in log, log)
        self.assertEqual(self.rig.rpc(op="status")["machines"], [])
        again = self.rig.up("mac")
        self.assertEqual(again.wait(10), 1)

    def test_two_machines_are_kept_apart(self):
        self.rig.join("mac")
        self.rig.join("linux")
        self.assertEqual(self.rig.run("pwd", machine="mac")[1].decode().strip(), self.rig.workspace("mac"))
        self.assertEqual(self.rig.run("pwd", machine="linux")[1].decode().strip(), self.rig.workspace("linux"))

    def test_second_hub_for_the_same_home_refuses_to_start(self):
        done = subprocess.run([sys.executable, "-B", lh_core.__file__, "hub", "--data-dir", str(self.rig.data),
                               "--bind", "127.0.0.1", "--port", str(self.rig.port)], capture_output=True, timeout=20)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"already running", done.stderr)
        self.assertTrue(self.rig.rpc(op="status")["ok"])

    def test_busy_port_is_reported(self):
        other = self.rig.tmp / "other"
        with self.assertRaises(lh_core.HubUnavailable) as caught:
            lh_core.spawn_hub(other, bind="127.0.0.1", port=self.rig.port)
        self.assertIn("already in use", str(caught.exception))

    def test_stale_socket_is_replaced(self):
        pid = self.rig.rpc(op="status")["pid"]
        os.kill(pid, signal.SIGKILL)
        wait_for(lambda: not _alive(pid), 5)
        self.assertTrue(self.rig.ctl.exists())
        status = lh_core.spawn_hub(self.rig.data, bind="127.0.0.1", port=self.rig.port, brain_name="test-brain")
        self.assertNotEqual(status["pid"], pid)
        self.assertEqual(status["pin"], self.rig.pin)

    def test_control_socket_is_private(self):
        self.assertEqual(os.stat(self.rig.ctl).st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.rig.ctl.parent).st_mode & 0o077, 0)

    def test_exec_client_without_a_hub(self):
        self.rig.stop_hub()
        code, out = self.rig.run("echo x")
        self.assertEqual(code, lh_core.EXIT_LINK)
        self.assertIn(b"hub is not running", out)

    def test_exec_client_names_a_forbidden_socket(self):
        """The control socket exists but the OS refuses it (here: no permission on its folder)."""
        if os.geteuid() == 0:
            self.skipTest("root is never refused")
        os.chmod(self.rig.ctl.parent, 0)
        self.addCleanup(os.chmod, self.rig.ctl.parent, 0o700)
        code, out = self.rig.run("echo x")
        self.assertEqual(code, lh_core.EXIT_LINK)
        self.assertIn(b"refuses the Unix socket", out)
        self.assertIn(b"Nothing ran", out)
        self.assertNotIn(b"hub is not running", out)


def _pgrep(marker):
    pattern = "[%s]%s" % (marker[0], marker[1:])
    return subprocess.run(["pgrep", "-f", pattern], capture_output=True).stdout.split()


if __name__ == "__main__":
    unittest.main()
