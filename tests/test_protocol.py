"""Unit tests that need no hub: pins, invites, names, framing, and that the daemon and the
core agree on the wire format."""

import importlib.util
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from harness import HANDS, ROOT, lh_core, needs_unix_sockets

spec = importlib.util.spec_from_file_location("lh_hands_daemon", HANDS)
hands = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hands)


class PinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="lh-pin-")
        cls.cert, cls.key = lh_core.ensure_certificate(Path(cls.tmp))
        cls.der = ssl.PEM_cert_to_DER_cert(cls.cert.read_text())

    def test_key_is_private(self):
        self.assertEqual(os.stat(self.key).st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.key.parent).st_mode & 0o077, 0)

    def test_certificate_is_reused(self):
        before = self.cert.read_bytes()
        lh_core.ensure_certificate(Path(self.tmp))
        self.assertEqual(before, self.cert.read_bytes())

    def test_daemon_and_core_compute_the_same_pin(self):
        self.assertEqual(lh_core.spki_pin(self.der), hands.spki_pin(self.der))
        self.assertEqual(lh_core.certificate_pin(self.cert), hands.spki_pin(self.der))

    def test_pin_matches_openssl(self):
        """Same value `curl --pinnedpubkey sha256//...` checks."""
        try:
            pub = subprocess.run(["openssl", "x509", "-in", str(self.cert), "-pubkey", "-noout"],
                                 check=True, capture_output=True).stdout
            der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub,
                                 check=True, capture_output=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("openssl not available")
        import base64
        import hashlib
        self.assertEqual(lh_core.spki_pin(self.der), base64.b64encode(hashlib.sha256(der).digest()).decode())

    def test_pin_matches_cryptography(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest("cryptography not installed")
        import base64
        import hashlib
        spki = x509.load_der_x509_certificate(self.der).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(lh_core.spki_pin(self.der), base64.b64encode(hashlib.sha256(spki).digest()).decode())

    def test_garbage_is_not_a_certificate(self):
        for blob in (b"", b"\x00" * 40, b"\x30\x03\x02\x01\x01", self.der[:60]):
            with self.assertRaises((ValueError, IndexError)):
                lh_core.spki_pin(blob)


class InviteTests(unittest.TestCase):
    PIN = "Vcv/deiRHF6I6uLCLK0sYznY3HLio9C4HtdjHlreUzM="
    CODE = "uzp52e3qddh6m3ujr663zymn"

    def test_round_trip(self):
        invite = lh_core.make_invite("vps.example.org", 7717, self.CODE, self.PIN)
        self.assertNotIn("+", invite.split("#")[1])
        self.assertNotIn("/", invite.split("#")[1])
        self.assertEqual(hands.parse_invite(invite), ("vps.example.org", 7717, self.CODE, self.PIN))

    def test_ipv6(self):
        invite = lh_core.make_invite("fd7a:115c::1", 7717, self.CODE, self.PIN)
        self.assertIn("[fd7a:115c::1]:7717", invite)
        self.assertEqual(hands.parse_invite(invite)[0], "fd7a:115c::1")

    def test_surrounding_whitespace(self):
        invite = lh_core.make_invite("10.0.0.2", 7717, self.CODE, self.PIN)
        self.assertEqual(hands.parse_invite("  " + invite + "\n")[1], 7717)

    def test_rejects_malformed(self):
        good = lh_core.make_invite("10.0.0.2", 7717, self.CODE, self.PIN)
        for bad in ("", "https://10.0.0.2:7717/x", good.replace("hands://", "hand://"), good.split("#")[0],
                    good.replace(self.CODE, "short"), good + " extra", good.replace(":7717", "")):
            with self.assertRaises(ValueError, msg=bad):
                hands.parse_invite(bad)

    def test_pin_url_form_round_trips(self):
        for pin in (self.PIN, "+/+/" + "A" * 39 + "="):
            self.assertEqual(lh_core.pin_from_url(lh_core.pin_to_url(pin)), pin)
            self.assertEqual(hands.pin_from_url(lh_core.pin_to_url(pin)), pin)


class NameTests(unittest.TestCase):
    def test_clean_name(self):
        cases = {"MacBook-Air-de-Noe.local": "macbook-air-de-noe", "": "machine", "brain": "machine",
                 "Ünï cödé": "n-c-d", "---": "machine", "a" * 80: "a" * 32, "dev_box": "dev_box",
                 "../../etc/passwd": "machine"}
        for raw, expected in cases.items():
            self.assertEqual(lh_core.clean_name(raw), expected, raw)
            self.assertTrue(lh_core.NAME_RE.match(lh_core.clean_name(raw)))

    def test_control_socket_path_fits_sun_path(self):
        short = lh_core.control_socket_path(Path("/tmp/x"))
        self.assertEqual(short, Path("/tmp/x/hub.sock"))
        long = lh_core.control_socket_path(Path("/tmp") / ("d" * 120))
        self.assertLessEqual(len(str(long)), 96)
        self.assertEqual(long, lh_core.control_socket_path(Path("/tmp") / ("d" * 120)))


class FramingTests(unittest.TestCase):
    def test_same_bytes_on_both_sides(self):
        frame = {"t": "exec", "id": "é", "script": "echo 'x'\n"}
        self.assertEqual(lh_core.encode_frame(frame), hands.encode_frame(frame))

    @needs_unix_sockets
    def test_round_trip_over_a_socket(self):
        a, b = socket.socketpair()
        try:
            lh_core.send_frame(a, {"t": "out", "d": "x" * 2000})
            self.assertEqual(hands.recv_frame(b)["d"], "x" * 2000)
            b.sendall(hands.encode_frame({"t": "pong"}))
            self.assertEqual(lh_core.recv_frame(a), {"t": "pong"})
            a.close()
            self.assertIsNone(hands.recv_frame(b))
        finally:
            a.close()
            b.close()

    @needs_unix_sockets
    def test_oversized_frames_are_refused(self):
        a, b = socket.socketpair()
        try:
            a.sendall(struct.pack(">I", lh_core.MAX_FRAME + 1))
            with self.assertRaises(ValueError):
                lh_core.recv_frame(b)
            a.sendall(struct.pack(">I", lh_core.MAX_HELLO + 1))
            with self.assertRaises(ValueError):
                lh_core.recv_frame(b, lh_core.MAX_HELLO)
            with self.assertRaises(ValueError):
                lh_core.encode_frame({"d": "x" * (lh_core.MAX_FRAME + 1)})
        finally:
            a.close()
            b.close()

    @needs_unix_sockets
    def test_non_object_frame_is_refused(self):
        a, b = socket.socketpair()
        try:
            a.sendall(struct.pack(">I", 2) + b"[]")
            with self.assertRaises(ValueError):
                lh_core.recv_frame(b)
        finally:
            a.close()
            b.close()

    def test_constants_agree(self):
        for name in ("MAGIC", "PROTO", "MAX_FRAME", "CHUNK", "VERSION"):
            self.assertEqual(getattr(lh_core, name), getattr(hands, name), name)


class ScreenSafetyTests(unittest.TestCase):
    def test_control_characters_never_reach_the_terminal(self):
        hostile = "ls\x1b[2K\x1b[1A\rrm -rf ~ \x07\x00‮"
        shown = hands.UI.one_line(hostile)
        self.assertNotIn("\x1b", shown)
        self.assertNotIn("\r", shown)
        self.assertNotIn("\x07", shown)
        self.assertNotIn("‮", shown)
        self.assertIn("rm -rf ~", shown)

    def test_clean_keeps_ordinary_text(self):
        text = "echo 'héllo wörld' | grep -c é\n\tdone ✓"
        self.assertEqual(hands.UI.clean(text), text)


class SourceRules(unittest.TestCase):
    """Promises made in the README about the two standalone files."""

    STDLIB_ONLY = {"hands.py": set(), "lh_core.py": {"cryptography"}}

    def test_standard_library_only(self):
        import ast
        import sys
        stdlib = getattr(sys, "stdlib_module_names", None)
        if stdlib is None:
            self.skipTest("needs Python 3.10+")
        for name, allowed in self.STDLIB_ONLY.items():
            tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    mods = [node.module or ""]
                for mod in mods:
                    top = mod.split(".")[0]
                    self.assertTrue(top in stdlib or top in allowed, "%s imports %s" % (name, mod))

    def test_daemon_has_no_python39_only_syntax(self):
        import ast
        source = (ROOT / "hands.py").read_text(encoding="utf-8")
        try:
            ast.parse(source, feature_version=(3, 8))
        except TypeError:
            self.skipTest("feature_version not supported")


if __name__ == "__main__":
    unittest.main()
