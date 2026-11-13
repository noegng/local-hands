#!/usr/bin/env python3
"""local-hands core: wire protocol, the brain-side hub and the ssh-like exec client.

This file is self-contained on purpose. Hermes imports it as part of the plugin
(``from . import lh_core``) and also runs it as a plain script for two jobs:

``lh_core.py hub``   the long-running hub on the machine where Hermes lives ("the brain").
                     It listens for hands daemons on a TLS port and for local requests on a
                     Unix socket only the current user can open.
``lh_core.py exec``  one command on one paired machine, with stdin/stdout proxied and the
                     remote exit status as its own. This is what the terminal backend spawns,
                     the same way the SSH backend spawns ``ssh``.

Only the standard library is used, except for minting the hub's self-signed TLS certificate
once (``cryptography``, which Hermes already ships, or the ``openssl`` binary as a fallback).
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

PROTO = 1
VERSION = "1.1.0"
MAGIC = b"LH1\n"
DEFAULT_PORT = 7717
MAX_FRAME = 8 * 1024 * 1024
MAX_HELLO = 16 * 1024      # largest frame accepted from a peer that has not authenticated yet
CHUNK = 64 * 1024

# Exit statuses the exec client uses for failures of the link itself. They are chosen to read
# correctly to a model that knows shells: 126 "found but not allowed to run", 255 what ssh
# returns when the connection fails.
EXIT_REFUSED = 126
EXIT_LINK = 255
EXIT_BLOCKED = 77      # the hub process: the OS refused its Unix control socket

BRAIN = "brain"  # reserved machine name: the host Hermes itself runs on
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

log = logging.getLogger("local-hands")


# --------------------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------------------

def send_frame(sock, obj: dict, lock: Optional[threading.Lock] = None) -> None:
    """One frame: 4-byte big-endian length, then UTF-8 JSON."""
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError("frame too large")
    packet = struct.pack(">I", len(data)) + data
    if lock is None:
        sock.sendall(packet)
    else:
        with lock:
            sock.sendall(packet)


def _recv_exact(sock, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def recv_frame(sock, limit: int = MAX_FRAME) -> Optional[dict]:
    """Next frame, or None when the peer closed the connection."""
    head = _recv_exact(sock, 4)
    if head is None:
        return None
    (size,) = struct.unpack(">I", head)
    if size > limit:
        raise ValueError("frame too large")
    body = _recv_exact(sock, size)
    if body is None:
        return None
    obj = json.loads(body.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("frame is not an object")
    return obj


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def encode_frame(obj: dict) -> bytes:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError("frame too large")
    return struct.pack(">I", len(data)) + data


class Link:
    """A TLS connection after its handshake, driven by exactly one thread.

    An OpenSSL connection must not be read and written from two threads at once, so the thread
    that calls :meth:`run` does every read and write. Other threads only queue frames with
    :meth:`send`, which blocks while more than ``HIGH_WATER`` bytes are waiting (back-pressure).
    """

    HIGH_WATER = 16 * 1024 * 1024

    def __init__(self, sock):
        self.sock = sock
        sock.setblocking(False)
        self._out = bytearray()
        self._writing: Optional[bytes] = None
        self._in = bytearray()
        self._cv = threading.Condition()
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        os.set_blocking(self._wake_w, False)
        self.closed = False
        self._closing = 0.0
        self.last_rx = time.time()

    def send(self, frame: dict) -> bool:
        try:
            data = encode_frame(frame)
        except ValueError:
            return False
        with self._cv:
            while len(self._out) > self.HIGH_WATER and not self.closed:
                self._cv.wait(1.0)
            if self.closed or self._closing:
                return False
            self._out += data
        self._wake()
        return True

    def close(self) -> None:
        """End the connection once what is already queued has been written (2 s at most)."""
        if not self._closing:
            self._closing = time.time()
        self._wake()

    def _wake(self) -> None:
        try:
            os.write(self._wake_w, b"\0")
        except OSError:
            pass

    def run(self, on_frame, idle_timeout: float) -> None:
        """Serve the connection until it ends. ``on_frame`` runs on this thread: keep it short."""
        try:
            while not self.closed:
                with self._cv:
                    want_write = bool(self._out) or self._writing is not None
                readable, writable, _ = select.select(
                    [self.sock, self._wake_r], [self.sock] if want_write else [], [], 5.0)
                if self._wake_r in readable:
                    try:
                        os.read(self._wake_r, 4096)
                    except OSError:
                        pass
                if (self.sock in readable or self.sock.pending()) and not self._read(on_frame):
                    break
                if want_write and not self._write():
                    break
                if time.time() - self.last_rx > idle_timeout:
                    break
                if self._closing:
                    with self._cv:
                        drained = not self._out and self._writing is None
                    if drained or time.time() - self._closing > 2.0:
                        break
        finally:
            with self._cv:
                self.closed = True
                self._cv.notify_all()
            for closer in (self.sock.close, lambda: os.close(self._wake_r), lambda: os.close(self._wake_w)):
                try:
                    closer()
                except OSError:
                    pass

    def _read(self, on_frame) -> bool:
        while True:
            try:
                chunk = self.sock.recv(CHUNK)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                break
            except (OSError, ValueError):
                return False
            if not chunk:
                return False
            self.last_rx = time.time()
            self._in += chunk
        while len(self._in) >= 4:
            (size,) = struct.unpack(">I", self._in[:4])
            if size > MAX_FRAME:
                return False
            if len(self._in) < 4 + size:
                break
            body = bytes(self._in[4:4 + size])
            del self._in[:4 + size]
            try:
                frame = json.loads(body.decode("utf-8"))
            except ValueError:
                return False
            if isinstance(frame, dict):
                on_frame(frame)
        return True

    def _write(self) -> bool:
        for _ in range(64):
            if self._writing is None:
                with self._cv:
                    if not self._out:
                        return True
                    self._writing = bytes(self._out[:CHUNK])
                    del self._out[:len(self._writing)]
                    self._cv.notify_all()
            try:
                # A retried TLS write must pass the same bytes again, hence ``_writing``.
                sent = self.sock.send(self._writing)
            except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError):
                return True
            except (OSError, ValueError):
                return False
            self._writing = self._writing[sent:] or None
        return True



# --------------------------------------------------------------------------------------
# certificate pin (SHA-256 of the SubjectPublicKeyInfo, the value curl --pinnedpubkey takes)
# --------------------------------------------------------------------------------------

def _der_head(buf: bytes, off: int) -> tuple[int, int, int]:
    """(tag, header length, content length) of the DER element at *off*."""
    tag = buf[off]
    first = buf[off + 1]
    if first < 0x80:
        return tag, 2, first
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError("unsupported DER length")
    return tag, 2 + n, int.from_bytes(buf[off + 2:off + 2 + n], "big")


def spki_from_cert_der(der: bytes) -> bytes:
    """The SubjectPublicKeyInfo element of an X.509 certificate, header included."""
    tag, head, _ = _der_head(der, 0)
    if tag != 0x30:
        raise ValueError("not a certificate")
    tag, tbs_head, tbs_len = _der_head(der, head)
    if tag != 0x30:
        raise ValueError("not a certificate")
    pos = head + tbs_head
    end = pos + tbs_len
    fields = []
    while pos < end and len(fields) < 8:
        tag, h, length = _der_head(der, pos)
        fields.append((tag, pos, h + length))
        pos += h + length
    # tbsCertificate: [0] version (optional), serial, signature, issuer, validity, subject, SPKI
    index = 6 if fields and fields[0][0] == 0xA0 else 5
    tag, start, size = fields[index]
    if tag != 0x30:
        raise ValueError("certificate has no public key where one is expected")
    return der[start:start + size]


def spki_pin(der: bytes) -> str:
    """Base64 SHA-256 of the certificate's public key (``sha256//<this>`` for curl)."""
    return b64e(hashlib.sha256(spki_from_cert_der(der)).digest())


def pin_to_url(pin: str) -> str:
    return pin.replace("+", "-").replace("/", "_").rstrip("=")


def pin_from_url(text: str) -> str:
    text = text.replace("-", "+").replace("_", "/")
    return text + "=" * (-len(text) % 4)


def make_invite(host: str, port: int, code: str, pin: str) -> str:
    host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"hands://{host}:{port}/{code}#{pin_to_url(pin)}"


# --------------------------------------------------------------------------------------
# paths and small files
# --------------------------------------------------------------------------------------

def control_socket_path(data_dir: Path) -> Path:
    """Where the hub's Unix socket lives. Inside the data directory when the path fits in
    sun_path (104 bytes on macOS), else under a private directory in /tmp."""
    direct = Path(data_dir) / "hub.sock"
    if len(os.fsencode(str(direct))) <= 96:
        return direct
    digest = hashlib.sha256(os.fsencode(str(Path(data_dir).resolve()))).hexdigest()[:12]
    return Path("/tmp") / f"lh-{os.getuid()}-{digest}" / "hub.sock"


def _private_dir(path: Path) -> None:
    """Create *path* for this user only, and refuse a directory someone else got to first
    (the control socket may live under /tmp, where anyone can create names)."""
    path.mkdir(parents=True, exist_ok=True)
    info = os.lstat(path)
    if not os.path.isdir(path) or os.path.islink(path) or info.st_uid != os.getuid():
        raise PermissionError(f"{path} is not a directory owned by the current user")
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data: Any) -> None:
    """Atomic, owner-only write."""
    path = Path(path)
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)


def clean_name(text: str, fallback: str = "machine") -> str:
    """A machine name the hub accepts: lowercase letters, digits, '-' and '_'."""
    name = re.sub(r"[^a-z0-9_-]+", "-", (text or "").lower().split(".")[0]).strip("-_")[:32]
    if not name or name == BRAIN or not NAME_RE.match(name):
        return fallback
    return name


# --------------------------------------------------------------------------------------
# TLS certificate of the hub
# --------------------------------------------------------------------------------------

def ensure_certificate(data_dir: Path) -> tuple[Path, Path]:
    """Create the hub's self-signed certificate on first use; return (cert, key) paths."""
    tls_dir = Path(data_dir) / "tls"
    cert, key = tls_dir / "cert.pem", tls_dir / "key.pem"
    if cert.exists() and key.exists():
        return cert, key
    _private_dir(tls_dir)
    try:
        _mint_with_cryptography(cert, key)
    except ImportError:
        _mint_with_openssl(cert, key)
    os.chmod(key, 0o600)
    return cert, key


def _mint_with_cryptography(cert_path: Path, key_path: Path) -> None:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-hands hub")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _mint_with_openssl(cert_path: Path, key_path: Path) -> None:
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-keyout", str(key_path), "-out", str(cert_path), "-days", "3650",
             "-subj", "/CN=local-hands hub"],
            check=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            "local-hands could not create its TLS certificate: neither the Python 'cryptography' "
            "package nor the 'openssl' command is available") from exc


def certificate_pin(cert_path: Path) -> str:
    return spki_pin(ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text(encoding="ascii")))


# --------------------------------------------------------------------------------------
# hub
# --------------------------------------------------------------------------------------

class _Route:
    """One command in flight: frames from the machine go to the local client that asked."""

    def __init__(self, exec_id: str, client, machine: str, session: str, display: str):
        self.id = exec_id
        self.client = client
        self.client_lock = threading.Lock()
        self.machine = machine
        self.session = session
        self.display = display
        self.started = time.time()
        self.done = threading.Event()
        self.exit_code: Optional[int] = None

    def to_client(self, frame: dict) -> None:
        try:
            send_frame(self.client, frame, self.client_lock)
        except OSError:
            pass

    def finish(self, frame: dict, code: int) -> None:
        if self.done.is_set():
            return
        self.exit_code = code
        self.done.set()
        self.to_client(frame)
        try:
            self.client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class _Device:
    """A connected hands daemon."""

    def __init__(self, name: str, link: Link, info: dict, peer: str):
        self.name = name
        self.link = link
        self.info = info
        self.peer = peer
        self.connected = time.time()
        self.routes: dict[str, _Route] = {}

    def send(self, frame: dict) -> bool:
        return self.link.send(frame)

    def close(self) -> None:
        self.link.close()


class Hub:
    PAIR_TTL = 600
    HANDSHAKE_TIMEOUT = 10
    PING_EVERY = 20
    DEAD_AFTER = 75
    MAX_PREAUTH = 32            # connections that have not authenticated yet, all peers together
    MAX_PREAUTH_PER_PEER = 4
    MAX_FAILURES = 8            # failed pair/hello attempts per peer and minute

    def __init__(self, data_dir: Path, bind: str = "0.0.0.0", port: int = DEFAULT_PORT, brain_name: str = ""):
        self.data_dir = Path(data_dir)
        _private_dir(self.data_dir)
        self.bind, self.port = bind, int(port)
        self.brain_name = brain_name or clean_name(platform.node(), "brain-host")
        self.cert, self.key = ensure_certificate(self.data_dir)
        self.pin = certificate_pin(self.cert)
        self.devices_path = self.data_dir / "devices.json"
        self.audit_path = self.data_dir / "audit.jsonl"
        self.lock = threading.RLock()
        self.records: dict[str, dict] = read_json(self.devices_path, {})
        self.online: dict[str, _Device] = {}
        self.invites: dict[str, dict] = {}
        self.failures: dict[str, list[float]] = {}
        self.preauth: dict[str, int] = {}
        self.stop = threading.Event()
        self.started = time.time()
        self._tls_server = None
        self._ctl_server = None
        self._hands_source = Path(__file__).resolve().with_name("hands.py")

    # ---- lifecycle -------------------------------------------------------------------

    def serve(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(self.cert), str(self.key))

        ctl_path = control_socket_path(self.data_dir)
        _private_dir(ctl_path.parent)
        if ctl_path.exists():
            if _hub_alive(ctl_path):
                raise SystemExit("local-hands hub is already running for this Hermes home")
            ctl_path.unlink()
        old_umask = os.umask(0o177)
        try:
            self._ctl_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._ctl_server.bind(str(ctl_path))
        except OSError as exc:
            if exc.errno in (errno.EPERM, errno.EACCES):
                raise HubBlocked(blocked_message(ctl_path, exc)) from exc
            raise
        finally:
            os.umask(old_umask)
        self._ctl_server.listen(64)

        self._tls_server = socket.create_server((self.bind, self.port), backlog=64,
                                                family=socket.AF_INET6 if ":" in self.bind else socket.AF_INET)
        write_json(self.data_dir / "hub.json", {
            "pid": os.getpid(), "port": self.port, "bind": self.bind, "brain": self.brain_name,
            "pin": self.pin, "started": int(self.started), "version": VERSION})
        log.info("hub %s listening on %s:%d (pin sha256//%s)", self.brain_name, self.bind, self.port, self.pin)

        threading.Thread(target=self._accept_loop, args=(self._ctl_server, self._serve_control),
                         name="lh-control", daemon=True).start()
        threading.Thread(target=self._accept_loop, args=(self._tls_server, lambda c: self._serve_tls(c, ctx)),
                         name="lh-tls", daemon=True).start()
        threading.Thread(target=self._keepalive_loop, name="lh-ping", daemon=True).start()
        try:
            while not self.stop.wait(1.0):
                pass
        finally:
            self.shutdown(ctl_path)

    def shutdown(self, ctl_path: Optional[Path] = None) -> None:
        self.stop.set()
        with self.lock:
            devices = list(self.online.values())
        for device in devices:
            device.close()
        for server in (self._tls_server, self._ctl_server):
            try:
                if server is not None:
                    server.close()
            except OSError:
                pass
        if ctl_path is not None:
            try:
                ctl_path.unlink()
            except OSError:
                pass

    def _accept_loop(self, server, handler) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                if self.stop.is_set():
                    return
                time.sleep(0.05)
                continue
            threading.Thread(target=self._guard, args=(handler, conn), daemon=True).start()

    @staticmethod
    def _guard(handler, conn) -> None:
        try:
            handler(conn)
        except Exception:
            log.debug("connection handler failed", exc_info=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _keepalive_loop(self) -> None:
        while not self.stop.wait(self.PING_EVERY):
            now = time.time()
            with self.lock:
                devices = list(self.online.values())
                for code, invite in list(self.invites.items()):
                    if invite["expires"] < now:
                        del self.invites[code]
                for peer, times in list(self.failures.items()):
                    if not times or now - times[-1] > 60:
                        del self.failures[peer]
            for device in devices:
                device.send({"t": "ping"})

    # ---- persistence -----------------------------------------------------------------

    def _save(self) -> None:
        write_json(self.devices_path, self.records)

    def _audit(self, route: _Route) -> None:
        entry = {"ts": int(route.started), "machine": route.machine, "session": route.session,
                 "command": route.display, "exit": route.exit_code,
                 "ms": int((time.time() - route.started) * 1000)}
        try:
            if self.audit_path.exists() and self.audit_path.stat().st_size > 2_000_000:
                lines = self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()
                self.audit_path.write_text("\n".join(lines[len(lines) // 2:]) + "\n", encoding="utf-8")
            fd = os.open(self.audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError:
            log.debug("audit write failed", exc_info=True)

    # ---- machines (TLS side) ---------------------------------------------------------

    def _throttled(self, peer: str) -> bool:
        now = time.time()
        with self.lock:
            recent = [t for t in self.failures.get(peer, []) if now - t < 60]
            if recent:
                self.failures[peer] = recent
            else:
                self.failures.pop(peer, None)
            return len(recent) >= self.MAX_FAILURES

    def _note_failure(self, peer: str) -> None:
        with self.lock:
            self.failures.setdefault(peer, []).append(time.time())

    def _serve_tls(self, raw, ctx) -> None:
        peer = raw.getpeername()[0]
        # Until a peer has authenticated it gets a bounded share of the hub: a few connections,
        # one small frame, and a hard deadline for the whole exchange (not just per read).
        with self.lock:
            if sum(self.preauth.values()) >= self.MAX_PREAUTH or self.preauth.get(peer, 0) >= self.MAX_PREAUTH_PER_PEER:
                return
            self.preauth[peer] = self.preauth.get(peer, 0) + 1
        state = {"pending": True}

        def admitted() -> None:
            with self.lock:
                if state["pending"]:
                    state["pending"] = False
                    left = self.preauth.get(peer, 1) - 1
                    if left > 0:
                        self.preauth[peer] = left
                    else:
                        self.preauth.pop(peer, None)

        def expire() -> None:
            if state["pending"]:
                try:
                    raw.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(self.HANDSHAKE_TIMEOUT * 2, expire)
        watchdog.daemon = True
        watchdog.start()
        conn = None
        try:
            raw.settimeout(self.HANDSHAKE_TIMEOUT)
            try:
                conn = ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                return
            first = _recv_exact(conn, 4)
            if first == b"GET ":
                self._serve_http(conn)
            elif first == MAGIC:
                self._serve_device(conn, peer, admitted)
        except (OSError, ValueError):
            pass
        finally:
            admitted()
            watchdog.cancel()
            try:
                (conn or raw).close()
            except OSError:
                pass

    def _serve_http(self, conn) -> None:
        """The one thing served over plain HTTPS: the daemon's own source, so a new machine can
        fetch it from the brain it is about to trust (``curl --pinnedpubkey``)."""
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 4096:
            chunk = conn.recv(1024)
            if not chunk:
                break
            head += chunk
        path = head.split(b" ", 1)[0].decode("ascii", "replace").split("?", 1)[0]
        if path == "/hands.py" and self._hands_source.exists():
            body, status, ctype = self._hands_source.read_bytes(), "200 OK", "text/x-python; charset=utf-8"
        else:
            body, status, ctype = b"local-hands hub: only /hands.py is served here\n", "404 Not Found", "text/plain"
        conn.sendall((f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                      "Connection: close\r\n\r\n").encode("ascii") + body)

    def _serve_device(self, conn, peer: str, admitted=lambda: None) -> None:
        if self._throttled(peer):
            send_frame(conn, {"t": "reject", "msg": "too many failed attempts, wait a minute"})
            return
        hello = recv_frame(conn, MAX_HELLO)
        if not hello:
            return
        info = {k: str(hello.get(k, ""))[:200] for k in
                ("os", "release", "hostname", "user", "workspace", "approve", "python", "version")}
        token = None
        if hello.get("t") == "pair":
            name, token = self._redeem(str(hello.get("code", "")), str(hello.get("name", "")), info)
            if name is None:
                self._note_failure(peer)
                send_frame(conn, {"t": "reject", "msg": "this pairing code is wrong, used or expired"})
                return
        elif hello.get("t") == "hello":
            name = self._authenticate(str(hello.get("token", "")))
            if name is None:
                self._note_failure(peer)
                send_frame(conn, {"t": "reject", "msg": "unknown or revoked machine: pair it again", "revoked": True})
                return
        else:
            return
        welcome = {"t": "welcome", "brain": self.brain_name, "device": name, "v": PROTO}
        if token:
            welcome["token"] = token
        send_frame(conn, welcome)
        admitted()

        device = _Device(name, Link(conn), info, peer)
        with self.lock:
            previous = self.online.get(name)
            self.online[name] = device
            record = self.records.setdefault(name, {})
            record.update(info, last_seen=int(time.time()), peer=peer)
            self._save()
        if previous is not None:
            previous.close()
        log.info("machine %s connected from %s", name, peer)
        try:
            device.link.run(lambda frame: self._on_device_frame(device, frame), self.DEAD_AFTER)
        finally:
            with self.lock:
                if self.online.get(name) is device:
                    del self.online[name]
                if name in self.records:
                    self.records[name]["last_seen"] = int(time.time())
                    self._save()
                routes = list(device.routes.values())
                device.routes.clear()
            for route in routes:
                route.finish({"t": "err", "code": EXIT_LINK,
                              "msg": f"machine '{name}' went offline while the command was running"}, EXIT_LINK)
                self._audit(route)
            log.info("machine %s disconnected", name)

    def _on_device_frame(self, device: _Device, frame: dict) -> None:
        kind = frame.get("t")
        if kind == "out":
            route = device.routes.get(str(frame.get("id")))
            if route is not None:
                route.to_client({"t": "out", "d": frame.get("d", "")})
        elif kind in ("exit", "refused"):
            with self.lock:
                route = device.routes.pop(str(frame.get("id")), None)
            if route is None:
                return
            if kind == "exit":
                code = int(frame.get("code", 1))
                route.finish({"t": "exit", "code": code}, code)
            else:
                route.finish({"t": "err", "code": EXIT_REFUSED,
                              "msg": str(frame.get("msg") or "refused on the machine")[:500]}, EXIT_REFUSED)
            self._audit(route)
        elif kind == "info":
            with self.lock:
                for key in ("workspace", "approve"):
                    if key in frame:
                        device.info[key] = str(frame[key])[:200]
                        self.records.setdefault(device.name, {})[key] = device.info[key]
                self._save()

    def _redeem(self, code: str, wanted: str, info: dict) -> tuple[Optional[str], Optional[str]]:
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        with self.lock:
            invite = self.invites.pop(digest, None)
            if invite is None or invite["expires"] < time.time():
                return None, None
            name = invite.get("name") or clean_name(wanted or info.get("hostname", ""))
            if not invite.get("name"):
                base, n = name, 2
                while name in self.records:
                    name, n = f"{base[:29]}-{n}", n + 1
            token = secrets.token_urlsafe(32)
            self.records[name] = dict(info, token_sha256=hashlib.sha256(token.encode()).hexdigest(),
                                      paired=int(time.time()), last_seen=int(time.time()))
            self._save()
        log.info("paired new machine %s", name)
        return name, token

    def _authenticate(self, token: str) -> Optional[str]:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        found = None
        with self.lock:
            for name, record in self.records.items():
                if hmac.compare_digest(str(record.get("token_sha256", "")), digest):
                    found = name
        return found

    # ---- local requests (Unix socket) ------------------------------------------------

    def _serve_control(self, conn) -> None:
        conn.settimeout(self.HANDSHAKE_TIMEOUT)
        request = recv_frame(conn)
        if not request:
            return
        op = request.get("op")
        if op == "exec":
            conn.settimeout(None)
            self._control_exec(conn, request)
        elif op == "status":
            send_frame(conn, self.status())
        elif op == "invite":
            send_frame(conn, self.invite(str(request.get("name") or ""), int(request.get("ttl") or self.PAIR_TTL)))
        elif op == "revoke":
            send_frame(conn, self.revoke(str(request.get("name") or "")))
        elif op == "log":
            send_frame(conn, {"ok": True, "entries": self.recent(int(request.get("n") or 20))})
        elif op == "stop":
            send_frame(conn, {"ok": True})
            self.stop.set()
        else:
            send_frame(conn, {"ok": False, "error": f"unknown request {op!r}"})

    def status(self) -> dict:
        now = time.time()
        with self.lock:
            machines = []
            for name in sorted(self.records):
                record = self.records[name]
                device = self.online.get(name)
                machines.append({
                    "name": name, "online": device is not None,
                    "os": record.get("os", ""), "release": record.get("release", ""),
                    "hostname": record.get("hostname", ""), "user": record.get("user", ""),
                    "workspace": record.get("workspace", ""), "approve": record.get("approve", ""),
                    "last_seen": record.get("last_seen", 0), "paired": record.get("paired", 0),
                    "running": len(device.routes) if device else 0})
            pending = sum(1 for invite in self.invites.values() if invite["expires"] > now)
        return {"ok": True, "brain": self.brain_name, "port": self.port, "bind": self.bind, "pin": self.pin,
                "pid": os.getpid(), "uptime": int(now - self.started), "machines": machines,
                "invites": pending, "version": VERSION}

    def invite(self, name: str, ttl: int) -> dict:
        if name:
            if name == BRAIN or not NAME_RE.match(name):
                return {"ok": False, "error": "machine names use lowercase letters, digits, '-' and '_' "
                                              f"(and '{BRAIN}' is reserved)"}
        code = base64.b32encode(secrets.token_bytes(15)).decode("ascii").lower()
        expires = time.time() + max(60, min(int(ttl), 3600))
        with self.lock:
            self.invites[hashlib.sha256(code.encode()).hexdigest()] = {"name": name, "expires": expires}
        return {"ok": True, "code": code, "expires": int(expires), "port": self.port, "pin": self.pin,
                "brain": self.brain_name}

    def revoke(self, name: str) -> dict:
        with self.lock:
            if name not in self.records:
                return {"ok": False, "error": f"no machine named '{name}'"}
            del self.records[name]
            self._save()
            device = self.online.pop(name, None)
        if device is not None:
            device.send({"t": "reject", "msg": "this machine was unpaired from the brain", "revoked": True})
            device.close()
        return {"ok": True}

    def recent(self, n: int) -> list:
        try:
            lines = self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        entries = []
        for line in lines[-max(1, min(n, 200)):]:
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        return entries

    def _control_exec(self, conn, request: dict) -> None:
        machine = str(request.get("machine") or "")
        deadline = time.time() + max(0.0, min(float(request.get("wait") or 0), 300.0))
        while True:
            with self.lock:
                device = self.online.get(machine)
                known = machine in self.records
            if device is not None or time.time() >= deadline or not known:
                break
            time.sleep(0.25)
        if device is None:
            if known:
                msg = (f"machine '{machine}' is offline. Ask the user to start the hands daemon on it "
                       "(python3 hands.py up), then retry.")
            else:
                msg = f"no machine named '{machine}' is paired with this brain (hermes hands pair)."
            send_frame(conn, {"t": "err", "code": EXIT_LINK, "msg": msg})
            return

        exec_id = secrets.token_hex(8)
        route = _Route(exec_id, conn, machine, str(request.get("session") or "")[:64],
                       str(request.get("display") or "")[:500])
        with self.lock:
            device.routes[exec_id] = route
        sent = device.send({"t": "exec", "id": exec_id, "script": str(request.get("script") or ""),
                            "login": bool(request.get("login")), "session": route.session,
                            "label": str(request.get("label") or "")[:64], "display": route.display})
        if not sent:
            with self.lock:
                device.routes.pop(exec_id, None)
            route.finish({"t": "err", "code": EXIT_LINK, "msg": f"machine '{machine}' just went offline"}, EXIT_LINK)
            return
        # Forward stdin until the local client goes away. A client that disappears before the
        # command exits was killed (timeout, /stop, interrupt): stop the command on the machine.
        try:
            while not route.done.is_set():
                frame = recv_frame(conn)
                if frame is None:
                    break
                if frame.get("t") in ("stdin", "eof"):
                    device.send({"t": frame["t"], "id": exec_id, "d": frame.get("d", "")})
        except (OSError, ValueError):
            pass
        if not route.done.is_set():
            device.send({"t": "kill", "id": exec_id})
            with self.lock:
                device.routes.pop(exec_id, None)
            route.exit_code = 130
            route.done.set()
            self._audit(route)


def _hub_alive(ctl_path: Path) -> bool:
    try:
        return bool(rpc(ctl_path, {"op": "status"}, timeout=1.5).get("ok"))
    except OSError:
        return False


# --------------------------------------------------------------------------------------
# local clients of the hub
# --------------------------------------------------------------------------------------

class HubUnavailable(OSError):
    """The hub is not running (or its socket is unusable)."""


class HubBlocked(HubUnavailable):
    """The operating system refused the Unix control socket itself. Starting the hub would not
    help, so this is reported as what it is instead of as "the hub is not running"."""


def blocked_message(ctl_path: Path, exc: OSError) -> str:
    return (f"this environment refuses the Unix socket Hermes and its hub talk through "
            f"({ctl_path}: {exc.strerror or exc}). A sandbox, container or seccomp policy that forbids "
            f"Unix sockets causes this, as does a socket owned by another user. Local Hands cannot "
            f"reach any machine from here; run Hermes where Unix sockets are allowed")


def _connect_control(ctl_path: Path, timeout: Optional[float]):
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(ctl_path))
    except OSError as exc:
        if sock is not None:
            sock.close()
        if exc.errno in (errno.EPERM, errno.EACCES):
            raise HubBlocked(blocked_message(ctl_path, exc)) from exc
        raise HubUnavailable(str(exc)) from exc
    return sock


def rpc(ctl_path: Path, request: dict, timeout: float = 3.0) -> dict:
    """One request, one reply."""
    sock = _connect_control(ctl_path, timeout)
    try:
        send_frame(sock, request)
        reply = recv_frame(sock)
    except (OSError, ValueError) as exc:
        raise HubUnavailable(str(exc)) from exc
    finally:
        sock.close()
    if reply is None:
        raise HubUnavailable("the hub closed the connection")
    return reply


_SPAWNED: list = []


def spawn_hub(data_dir: Path, *, bind: str, port: int, brain_name: str = "", wait: float = 8.0) -> dict:
    """Start the hub as a detached process and wait until it answers. Returns its status."""
    data_dir = Path(data_dir)
    _private_dir(data_dir)
    ctl_path = control_socket_path(data_dir)
    # -P (3.11+) keeps the script's directory off sys.path; older interpreters do without.
    safe = ["-P"] if sys.version_info >= (3, 11) else []
    argv = [sys.executable, *safe, str(Path(__file__).resolve()), "hub", "--data-dir", str(data_dir),
            "--bind", bind, "--port", str(port)]
    if brain_name:
        argv += ["--name", brain_name]
    fd = os.open(data_dir / "hub.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fd, stderr=fd,
                                start_new_session=True, close_fds=True)
    finally:
        os.close(fd)
    _SPAWNED[:] = [old for old in _SPAWNED if old.poll() is None]   # reap hubs that have exited
    _SPAWNED.append(proc)   # the hub outlives us on purpose; keep the handle so it is never reaped noisily
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            return rpc(ctl_path, {"op": "status"}, timeout=1.0)
        except HubUnavailable:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
    if proc.poll() == EXIT_BLOCKED:
        raise HubBlocked(blocked_message(ctl_path, PermissionError(errno.EPERM, "the hub could not create it")))
    tail = ""
    try:
        tail = (data_dir / "hub.log").read_text(encoding="utf-8", errors="replace").strip().splitlines()[-1]
    except (OSError, IndexError):
        pass
    raise HubUnavailable(f"the hub did not start{': ' + tail if tail else ''}")


def exec_argv(ctl_path: Path, machine: str, *, session: str = "", label: str = "", login: bool = False,
              display: str = "", script_fd: Optional[int] = None, wait: float = 0.0) -> list[str]:
    """argv of the exec client, the local-hands counterpart of ``ssh host``."""
    argv = [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "exec",
            "--sock", str(ctl_path), "--machine", machine]
    if session:
        argv += ["--session", session]
    if label:
        argv += ["--label", label]
    if login:
        argv.append("--login")
    if display:
        argv += ["--display", display]
    if wait:
        argv += ["--wait", str(wait)]
    if script_fd is not None:
        argv += ["--script-fd", str(script_fd)]
    return argv


def run_exec_client(args) -> int:
    out = sys.stdout.buffer

    def say(message: str) -> None:
        out.write(f"[local-hands] {message}\n".encode("utf-8"))
        out.flush()

    if args.script_fd is not None:
        with os.fdopen(args.script_fd, "rb") as handle:
            script = handle.read().decode("utf-8", "replace")
    else:
        import shlex
        script = shlex.join(args.command)
    if not script.strip():
        say("nothing to run")
        return 2
    try:
        sock = _connect_control(Path(args.sock), None)
    except HubBlocked as exc:
        say(f"{exc}. Nothing ran.")
        return EXIT_LINK
    except HubUnavailable:
        say("the local-hands hub is not running on the Hermes host. Start it with: hermes hands up")
        return EXIT_LINK
    lock = threading.Lock()
    try:
        send_frame(sock, {"op": "exec", "machine": args.machine, "script": script, "login": args.login,
                          "session": args.session, "label": args.label,
                          "display": args.display or script[:500], "wait": args.wait}, lock)
    except OSError:
        say("lost the connection to the local-hands hub")
        return EXIT_LINK

    def pump_stdin() -> None:
        try:
            fd = sys.stdin.fileno()
            while True:
                chunk = os.read(fd, CHUNK)
                if not chunk:
                    break
                send_frame(sock, {"t": "stdin", "d": b64e(chunk)}, lock)
            send_frame(sock, {"t": "eof"}, lock)
        except (OSError, ValueError):
            pass

    threading.Thread(target=pump_stdin, daemon=True).start()
    try:
        while True:
            frame = recv_frame(sock)
            if frame is None:
                say("the local-hands hub closed the connection before the command finished")
                return EXIT_LINK
            kind = frame.get("t")
            if kind == "out":
                out.write(b64d(frame.get("d", "")))
                out.flush()
            elif kind == "exit":
                code = int(frame.get("code", 1))
                return code if 0 <= code <= 255 else (128 + min(abs(code), 127))
            elif kind == "err":
                say(str(frame.get("msg", "failed")))
                return int(frame.get("code", EXIT_LINK))
    except BrokenPipeError:
        return 141
    except (OSError, ValueError):
        say("lost the connection to the local-hands hub")
        return EXIT_LINK


# --------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="lh_core.py", description="local-hands hub and exec client")
    sub = parser.add_subparsers(dest="cmd", required=True)
    hub = sub.add_parser("hub", help="run the hub in the foreground")
    hub.add_argument("--data-dir", required=True)
    hub.add_argument("--bind", default="0.0.0.0")
    hub.add_argument("--port", type=int, default=DEFAULT_PORT)
    hub.add_argument("--name", default="")
    ex = sub.add_parser("exec", help="run one command on a paired machine")
    ex.add_argument("--sock", required=True)
    ex.add_argument("--machine", required=True)
    ex.add_argument("--session", default="")
    ex.add_argument("--label", default="")
    ex.add_argument("--display", default="")
    ex.add_argument("--login", action="store_true")
    ex.add_argument("--wait", type=float, default=0.0)
    ex.add_argument("--script-fd", type=int, default=None)
    ex.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    if args.cmd == "exec":
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        return run_exec_client(args)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    hub_obj = Hub(Path(args.data_dir), bind=args.bind, port=args.port, brain_name=args.name)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: hub_obj.stop.set())
    try:
        hub_obj.serve()
    except HubBlocked as exc:
        log.error("%s", exc)
        return EXIT_BLOCKED
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            log.error("port %d is already in use: pick another with `hermes config set "
                      "plugins.entries.local-hands.settings.port <port>`", args.port)
            return 98
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
