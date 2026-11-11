#!/usr/bin/env python3
"""hands.py - the local-hands daemon. Run it on the computer Hermes should act on.

    python3 hands.py join 'hands://HOST:PORT/CODE#PIN'   pair this machine with a Hermes host, then serve
    python3 hands.py up                                  reconnect to a host you already paired
    python3 hands.py list                                hosts this machine is paired with
    python3 hands.py forget BRAIN                        drop a pairing

The daemon dials OUT to the Hermes host (the "brain"); nothing listens on this machine. It
checks the brain's TLS public key against the pin in the invite, then runs the shell commands
the brain sends, in the directory you started it in, as you. You decide how much to trust it:

    --approve session   ask once per Hermes conversation (default)
    --approve every     ask before every single command
    --approve auto      never ask (for a brain you fully trust)

Every command is printed here as it runs and appended to an audit log. Ctrl-C stops the
daemon and every command it started.

One file, standard library only, Python 3.8+. macOS, Linux and WSL (commands run in bash).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import platform
import queue
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

VERSION = "1.0.0"
PROTO = 1
MAGIC = b"LH1\n"
MAX_FRAME = 8 * 1024 * 1024
CHUNK = 64 * 1024
IDLE_TIMEOUT = 75


# --------------------------------------------------------------------------------------
# wire format (kept identical to lh_core.py on the brain)
# --------------------------------------------------------------------------------------

def encode_frame(obj):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError("frame too large")
    return struct.pack(">I", len(data)) + data


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def recv_frame(sock):
    head = recv_exact(sock, 4)
    if head is None:
        return None
    (size,) = struct.unpack(">I", head)
    if size > MAX_FRAME:
        raise ValueError("frame too large")
    body = recv_exact(sock, size)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


class Link:
    """A TLS connection after its handshake, driven by exactly one thread (an OpenSSL
    connection must not be read and written from two threads at once). Other threads queue
    frames with send(); the thread inside run() does all reading and writing."""

    HIGH_WATER = 16 * 1024 * 1024

    def __init__(self, sock):
        self.sock = sock
        sock.setblocking(False)
        self._out = bytearray()
        self._writing = None
        self._in = bytearray()
        self._cv = threading.Condition()
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        os.set_blocking(self._wake_w, False)
        self.closed = False
        self.last_rx = time.time()

    def send(self, frame):
        try:
            data = encode_frame(frame)
        except ValueError:
            return False
        with self._cv:
            while len(self._out) > self.HIGH_WATER and not self.closed:
                self._cv.wait(1.0)
            if self.closed:
                return False
            self._out += data
        self._wake()
        return True

    def close(self):
        with self._cv:
            self.closed = True
            self._cv.notify_all()
        self._wake()

    def _wake(self):
        try:
            os.write(self._wake_w, b"\0")
        except OSError:
            pass

    def run(self, on_frame, idle_timeout=IDLE_TIMEOUT):
        try:
            while not self.closed:
                with self._cv:
                    want_write = bool(self._out) or self._writing is not None
                readable, _, _ = select.select(
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
        finally:
            with self._cv:
                self.closed = True
                self._cv.notify_all()
            for closer in (self.sock.close, lambda: os.close(self._wake_r), lambda: os.close(self._wake_w)):
                try:
                    closer()
                except OSError:
                    pass

    def _read(self, on_frame):
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

    def _write(self):
        for _ in range(64):
            if self._writing is None:
                with self._cv:
                    if not self._out:
                        return True
                    self._writing = bytes(self._out[:CHUNK])
                    del self._out[:len(self._writing)]
                    self._cv.notify_all()
            try:
                # A retried TLS write must pass the same bytes again, hence _writing.
                sent = self.sock.send(self._writing)
            except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError):
                return True
            except (OSError, ValueError):
                return False
            self._writing = self._writing[sent:] or None
        return True


# --------------------------------------------------------------------------------------
# public-key pin
# --------------------------------------------------------------------------------------

def _der_head(buf, off):
    tag = buf[off]
    first = buf[off + 1]
    if first < 0x80:
        return tag, 2, first
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError("unsupported DER length")
    return tag, 2 + n, int.from_bytes(buf[off + 2:off + 2 + n], "big")


def spki_from_cert_der(der):
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
    index = 6 if fields and fields[0][0] == 0xA0 else 5
    tag, start, size = fields[index]
    if tag != 0x30:
        raise ValueError("certificate has no public key where one is expected")
    return der[start:start + size]


def spki_pin(der):
    return base64.b64encode(hashlib.sha256(spki_from_cert_der(der)).digest()).decode("ascii")


def pin_from_url(text):
    text = text.replace("-", "+").replace("_", "/")
    return text + "=" * (-len(text) % 4)


INVITE_RE = re.compile(r"^hands://(\[[0-9a-fA-F:.]+\]|[^:/\s]+):(\d{1,5})/([a-z2-7]{16,64})#([A-Za-z0-9_\-+/=]{40,48})$")


def parse_invite(text):
    match = INVITE_RE.match(text.strip())
    if not match:
        raise ValueError("that does not look like a local-hands invite (hands://HOST:PORT/CODE#PIN)")
    host, port, code, pin = match.groups()
    return host.strip("[]"), int(port), code, pin_from_url(pin)


# --------------------------------------------------------------------------------------
# terminal output
# --------------------------------------------------------------------------------------

class UI:
    def __init__(self):
        self.lock = threading.Lock()
        self.color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.tty_in = sys.stdin.isatty()

    def paint(self, code, text):
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def dim(self, text):
        return self.paint("2", text)

    def bold(self, text):
        return self.paint("1", text)

    def green(self, text):
        return self.paint("32", text)

    def red(self, text):
        return self.paint("31", text)

    def yellow(self, text):
        return self.paint("33", text)

    def cyan(self, text):
        return self.paint("36", text)

    def line(self, text=""):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def raw(self, text):
        with self.lock:
            sys.stdout.write(text)
            sys.stdout.flush()

    def stamp(self):
        return self.dim(time.strftime("%H:%M:%S"))

    @staticmethod
    def clean(text):
        """Text from the brain, safe to print: no escape sequences or other control characters
        (they could redraw the screen and disguise what is being approved)."""
        return "".join(ch if ch in "\n\t" or (ch.isprintable() and ch not in "\u2028\u2029") else "\ufffd"
                       for ch in text)

    @staticmethod
    def one_line(text, width=None):
        text = " ".join(UI.clean(text).split())
        width = width or max(40, shutil.get_terminal_size((100, 20)).columns - 24)
        return text if len(text) <= width else text[:width - 1] + "…"


# --------------------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------------------

def config_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    path = os.path.join(base, "local-hands")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _brain_file(host, port):
    safe = re.sub(r"[^A-Za-z0-9.-]+", "_", host)
    return os.path.join(config_dir(), "brain-%s-%d.json" % (safe, port))


def save_brain(cfg):
    path = _brain_file(cfg["host"], cfg["port"])
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(cfg, handle, indent=2, sort_keys=True)
    os.replace(path + ".tmp", path)
    return path


def load_brains():
    found = []
    for name in sorted(os.listdir(config_dir())):
        if name.startswith("brain-") and name.endswith(".json"):
            try:
                with open(os.path.join(config_dir(), name)) as handle:
                    cfg = json.load(handle)
                cfg["_path"] = os.path.join(config_dir(), name)
                found.append(cfg)
            except (OSError, ValueError):
                continue
    return found


def pick_brain(selector):
    brains = load_brains()
    if not brains:
        raise SystemExit("This machine is not paired with any Hermes host yet.\n"
                         "On the Hermes host run:  hermes hands pair\n"
                         "then here:               python3 hands.py join '<invite>'")
    if selector:
        chosen = [b for b in brains if selector in (b.get("brain"), b.get("host"), "%s:%s" % (b.get("host"), b.get("port")))]
        if not chosen:
            raise SystemExit("No pairing matches %r. Try: python3 hands.py list" % selector)
        return chosen[0]
    if len(brains) > 1:
        names = ", ".join(sorted(str(b.get("brain")) for b in brains))
        raise SystemExit("This machine is paired with several hosts (%s). Say which: python3 hands.py up NAME" % names)
    return brains[0]


def audit(entry):
    try:
        path = os.path.join(config_dir(), "audit.jsonl")
        if os.path.exists(path) and os.path.getsize(path) > 5_000_000:
            os.replace(path, path + ".1")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------------------
# approvals
# --------------------------------------------------------------------------------------

class Job:
    def __init__(self, exec_id, session, display, label):
        self.id = exec_id
        self.session = UI.clean(session or "-")[:64]
        self.display = display
        self.label = label
        self.proc = None
        self.cancelled = False
        self.stdin = queue.Queue()
        self.started = time.time()


class Approver:
    """Decides, on this machine, whether a command from the brain may run."""

    REFUSAL_MEMORY = 20  # seconds a "no" keeps answering for the same session without asking again

    def __init__(self, mode, timeout, ui, brain, device):
        self.mode = mode
        self.timeout = timeout
        self.ui = ui
        self.brain = brain
        self.device = device
        self.sessions = set()
        self.refused = {}
        self.changed = False
        self.lock = threading.Lock()

    def check(self, job, script):
        """(allowed, message for the brain when refused)"""
        if self.mode == "auto":
            return True, ""
        with self.lock:  # one question on screen at a time
            if job.cancelled:
                return False, "cancelled"
            if self.mode == "auto" or job.session in self.sessions:
                return True, ""
            if time.time() < self.refused.get(job.session, 0):
                return False, self._refusal()
            if not self.ui.tty_in:
                return False, ("the hands daemon on '%s' has no terminal to ask its user on. They can restart "
                               "it with --approve auto to trust this Hermes host." % self.device)
            answer = self._ask(job, script)
            if answer == "cancelled":
                return False, "cancelled"
            if answer == "timeout":
                self.ui.line("    " + self.ui.yellow("no answer - refused"))
                return False, ("nobody answered the approval prompt on '%s' within %d s. Tell the user it is "
                               "waiting on their machine before you retry." % (self.device, self.timeout))
            if answer == "a":
                self.mode = "auto"
                self.changed = True
                self.ui.line("    " + self.ui.green("always allowing this brain until the daemon restarts"))
                return True, ""
            if answer == "s" or (answer == "y" and self.mode == "session"):
                self.sessions.add(job.session)
                return True, ""
            if answer == "y":
                return True, ""
            self.refused[job.session] = time.time() + self.REFUSAL_MEMORY
            return False, self._refusal()

    def _refusal(self):
        return ("the user refused this on their machine '%s'. Do not retry it or work around it: "
                "ask them what they want instead." % self.device)

    def _ask(self, job, script):
        ui = self.ui
        what = UI.one_line(job.display) if job.display else "(no description sent)"
        if self.mode == "session":
            ui.line("")
            ui.line("  %s brain %s wants to run commands here %s" % (
                ui.yellow("?"), ui.bold('"%s"' % self.brain), ui.dim("session " + job.session[:8])))
            ui.line("    first command: %s" % ui.cyan(what))
            choices = "[y] allow this session   [a] always allow   [n] refuse"
            valid = "yan"
        else:
            ui.line("")
            ui.line("  %s %s" % (ui.yellow("?"), ui.cyan(what)))
            choices = "[y] run   [s] allow this session   [a] always allow   [v] view script   [n] refuse"
            valid = "ysavn"
        deadline = time.time() + self.timeout
        self._drop_typeahead()
        while True:
            ui.raw("    %s  › " % choices)
            answer = self._read_key(job, deadline)
            if answer in ("cancelled", "timeout"):
                ui.line("")
                if answer == "cancelled":
                    ui.line("    " + ui.dim("the brain withdrew the request"))
                return answer
            answer = (answer.strip().lower() or "?")[0]
            if answer == "v" and "v" in valid:
                lines = UI.clean(script).split("\n")
                ui.line(ui.dim("\n".join("      | " + line for line in lines[:400])))
                if len(lines) > 400:
                    ui.line(ui.dim("      | … %d more lines not shown" % (len(lines) - 400)))
                deadline = time.time() + self.timeout
                continue
            if answer in valid:
                return answer
            ui.line("    " + ui.dim("answer with one of the letters shown"))

    @staticmethod
    def _drop_typeahead():
        """Forget keys typed before the question appeared, so a stray Enter cannot answer it."""
        try:
            import termios
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        except Exception:
            pass

    @staticmethod
    def _read_key(job, deadline):
        while True:
            if job.cancelled:
                return "cancelled"
            if time.time() > deadline:
                return "timeout"
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 0.25)
            except (OSError, ValueError):
                return "timeout"
            if ready:
                line = sys.stdin.readline()
                if line == "":
                    return "timeout"
                return line


# --------------------------------------------------------------------------------------
# the daemon
# --------------------------------------------------------------------------------------

class Rejected(Exception):
    def __init__(self, message, revoked=False):
        Exception.__init__(self, message)
        self.revoked = revoked


class PinMismatch(Exception):
    pass


class Daemon:
    def __init__(self, cfg, workspace, approve, approve_timeout, ui):
        self.cfg = cfg
        self.workspace = workspace
        self.ui = ui
        self.bash = shutil.which("bash") or "/bin/bash"
        self.approver = Approver(approve, approve_timeout, ui, cfg.get("brain", cfg["host"]), cfg.get("device", "this machine"))
        self.link = None
        self.jobs = {}
        self.jobs_lock = threading.Lock()
        self.stopping = False
        self.revoked = False

    # ---- connection ------------------------------------------------------------------

    def info(self):
        return {"os": platform.system(), "release": platform.release(), "hostname": platform.node(),
                "user": getpass.getuser(), "workspace": self.workspace, "approve": self.approver.mode,
                "python": platform.python_version(), "version": VERSION, "v": PROTO}

    def connect(self, pair_code=None, wanted_name=""):
        cfg = self.cfg
        # The brain's certificate is self-signed, so the usual CA and hostname checks cannot
        # apply. It is authenticated instead by comparing its public key with the pin from the
        # invite, before anything secret is sent.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection((cfg["host"], cfg["port"]), timeout=10)
        try:
            tls = ctx.wrap_socket(raw)
        except Exception:
            raw.close()
            raise
        try:
            der = tls.getpeercert(binary_form=True)
            if not der or not hmac.compare_digest(spki_pin(der), cfg["pin"]):
                raise PinMismatch()
            hello = dict(self.info())
            if pair_code:
                hello.update(t="pair", code=pair_code, name=wanted_name)
            else:
                hello.update(t="hello", token=cfg["token"])
            tls.sendall(MAGIC + encode_frame(hello))
            reply = recv_frame(tls)
            if not reply:
                raise OSError("the brain closed the connection")
            if reply.get("t") != "welcome":
                raise Rejected(UI.clean(str(reply.get("msg") or "refused by the brain"))[:300], bool(reply.get("revoked")))
            if reply.get("token"):
                cfg["token"] = reply["token"]
            cfg["brain"] = UI.clean(str(reply.get("brain") or cfg.get("brain") or cfg["host"]))[:64]
            cfg["device"] = UI.clean(str(reply.get("device") or cfg.get("device") or ""))[:64]
            self.approver.brain, self.approver.device = cfg["brain"], cfg["device"]
            tls.settimeout(None)
            return tls
        except Exception:
            tls.close()
            raise

    def serve(self, tls):
        """Serve one connection until it drops."""
        link = Link(tls)
        self.link = link
        try:
            link.run(self.on_frame)
        finally:
            self.link = None
            self.kill_all()

    def run_forever(self, first=None):
        ui = self.ui
        delay = 1
        tls = first
        while not self.stopping:
            if tls is None:
                try:
                    tls = self.connect()
                    ui.line("  %s reconnected to %s" % (ui.green("✓"), ui.bold('"%s"' % self.cfg["brain"])))
                except Rejected as exc:
                    ui.line("  %s %s" % (ui.red("✗"), exc))
                    if exc.revoked:
                        return 3
                except PinMismatch:
                    ui.line("  %s %s" % (ui.red("✗"), "the host at %s:%s does not hold the key this machine was paired "
                                         "with. Not connecting. If you reinstalled the brain, pair again."
                                         % (self.cfg["host"], self.cfg["port"])))
                    return 4
                except (OSError, ssl.SSLError, ValueError) as exc:
                    ui.line("  %s %s" % (ui.dim("…"), ui.dim("brain unreachable (%s), retrying in %ds" % (
                        exc.__class__.__name__, delay))))
            if tls is not None:
                delay = 1
                self.serve(tls)
                tls = None
                if self.stopping:
                    break
                ui.line("  %s %s" % (ui.yellow("!"), "connection to the brain lost; running commands were stopped"))
            for _ in range(delay * 10):
                if self.stopping:
                    break
                time.sleep(0.1)
            delay = min(delay * 2, 30)
        return 3 if self.revoked else 0

    def stop(self):
        self.stopping = True
        link = self.link
        if link is not None:
            link.close()
        self.kill_all()

    # ---- frames from the brain (called on the link thread: never block here) ---------

    def on_frame(self, frame):
        kind = frame.get("t")
        if kind == "ping":
            self.link.send({"t": "pong"})
        elif kind == "exec":
            job = Job(str(frame.get("id")), str(frame.get("session") or ""), str(frame.get("display") or ""),
                      str(frame.get("label") or ""))
            with self.jobs_lock:
                self.jobs[job.id] = job
            threading.Thread(target=self.run_job, args=(job, str(frame.get("script") or ""), bool(frame.get("login"))),
                             daemon=True).start()
        elif kind in ("stdin", "eof"):
            job = self.jobs.get(str(frame.get("id")))
            if job is not None:
                job.stdin.put(base64.b64decode(frame.get("d") or "") if kind == "stdin" else None)
        elif kind == "kill":
            job = self.jobs.get(str(frame.get("id")))
            if job is not None:
                self.kill_job(job)
        elif kind == "reject":
            self.ui.line("  %s %s" % (self.ui.red("✗"), UI.clean(str(frame.get("msg") or "disconnected by the brain"))[:300]))
            if frame.get("revoked"):
                self.revoked = True
                self.stopping = True
            self.link.close()

    # ---- commands --------------------------------------------------------------------

    def send(self, frame):
        link = self.link
        return link.send(frame) if link is not None else False

    def run_job(self, job, script, login):
        ui = self.ui
        try:
            allowed, message = self.approver.check(job, script)
            if self.approver.changed:
                self.approver.changed = False
                self.send({"t": "info", "approve": self.approver.mode})
            if job.cancelled:
                return
            what = UI.one_line(job.display) if job.display else ui.dim("(no description sent)")
            if not allowed:
                ui.line("  %s %s %s  %s" % (ui.stamp(), ui.red("✗"), what, ui.red("refused")))
                self.send({"t": "refused", "id": job.id, "msg": message})
                audit({"ts": int(time.time()), "brain": self.cfg.get("brain"), "session": job.session,
                       "command": job.display, "result": "refused"})
                return
            if job.display:
                ui.line("  %s %s %s" % (ui.stamp(), ui.cyan("▸"), what))
            env = dict(os.environ, LOCAL_HANDS="1", LOCAL_HANDS_BRAIN=str(self.cfg.get("brain", "")))
            argv = [self.bash] + (["-l"] if login else []) + ["-c", script]
            try:
                cwd = self.workspace if os.path.isdir(self.workspace) else os.path.expanduser("~")
                proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, start_new_session=True)
            except OSError as exc:
                self.send({"t": "out", "id": job.id,
                           "d": base64.b64encode(("[local-hands] could not start bash on this machine: %s\n" % exc).encode()).decode()})
                self.send({"t": "exit", "id": job.id, "code": 127})
                return
            job.proc = proc
            if job.cancelled:
                self.kill_job(job)
            threading.Thread(target=self.feed_stdin, args=(job,), daemon=True).start()
            fd = proc.stdout.fileno()
            while True:
                try:
                    chunk = os.read(fd, CHUNK)
                except OSError:
                    break
                if not chunk:
                    break
                if not self.send({"t": "out", "id": job.id, "d": base64.b64encode(chunk).decode("ascii")}):
                    self.kill_job(job)
                    break
            code = proc.wait()
            job.stdin.put(None)
            if code < 0:
                code = 128 - code
            took = int((time.time() - job.started) * 1000)
            if not job.cancelled:
                self.send({"t": "exit", "id": job.id, "code": code})
            if job.display:
                mark = ui.green("✓") if code == 0 else ui.red("✗")
                tail = "stopped by the brain" if job.cancelled else "exit %d" % code
                ui.line("  %s   %s %s" % (" " * 8, mark, ui.dim("%s · %s" % (tail, _ms(took)))))
            audit({"ts": int(job.started), "brain": self.cfg.get("brain"), "session": job.session,
                   "command": job.display, "exit": code, "ms": took, "stopped": job.cancelled})
        finally:
            with self.jobs_lock:
                self.jobs.pop(job.id, None)

    @staticmethod
    def feed_stdin(job):
        pipe = job.proc.stdin
        try:
            while True:
                data = job.stdin.get()
                if data is None:
                    break
                pipe.write(data)
                pipe.flush()
        except (OSError, ValueError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def kill_job(self, job):
        job.cancelled = True
        proc = job.proc
        if proc is None or proc.poll() is not None:
            return

        def _signal(sig):
            try:
                os.killpg(proc.pid, sig)
            except (OSError, AttributeError):
                try:
                    proc.kill()
                except OSError:
                    pass

        _signal(signal.SIGTERM)
        timer = threading.Timer(2.0, lambda: proc.poll() is None and _signal(signal.SIGKILL))
        timer.daemon = True
        timer.start()

    def kill_all(self):
        with self.jobs_lock:
            jobs = list(self.jobs.values())
        for job in jobs:
            self.kill_job(job)


def _ms(value):
    return "%d ms" % value if value < 1000 else "%.1f s" % (value / 1000.0)


# --------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------

APPROVE_HELP = {
    "session": "ask once per Hermes conversation",
    "every": "ask before every command",
    "auto": "never ask",
}


def banner(ui, cfg, daemon, paired_now):
    ui.line("")
    ui.line("  %s %s" % (ui.bold("local-hands"), ui.dim(VERSION)))
    verb = "paired with" if paired_now else "connected to"
    ui.line("  %s %s brain %s as %s" % (ui.green("✓"), verb, ui.bold('"%s"' % cfg["brain"]), ui.bold('"%s"' % cfg["device"])))
    ui.line("    workspace  %s" % daemon.workspace)
    ui.line("    approvals  %s %s" % (daemon.approver.mode, ui.dim("(" + APPROVE_HELP[daemon.approver.mode] + ")")))
    if daemon.approver.mode != "auto" and not ui.tty_in:
        ui.line("    " + ui.yellow("no terminal attached: every command will be refused. Use --approve auto to run unattended."))
    ui.line("    " + ui.dim("Ctrl-C stops the daemon and every command it started."))
    ui.line("")


def cmd_serve(args, pair=None):
    ui = UI()
    if os.name == "nt":
        raise SystemExit("hands.py runs on macOS, Linux and WSL. On Windows, start it inside WSL.")
    workspace = os.path.abspath(os.path.expanduser(args.workspace or os.getcwd()))
    if not os.path.isdir(workspace):
        raise SystemExit("workspace %s is not a directory" % workspace)
    if pair is not None:
        host, port, code, pin = pair
        cfg = {"host": host, "port": port, "pin": pin}
    else:
        cfg = pick_brain(getattr(args, "brain", None))
        cfg.pop("_path", None)
    daemon = Daemon(cfg, workspace, args.approve, args.approve_timeout, ui)

    def on_signal(*_):
        ui.line("")
        ui.line("  " + ui.dim("stopping…"))
        daemon.stop()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        if pair is not None:
            tls = daemon.connect(pair_code=pair[2], wanted_name=args.name or "")
            save_brain(cfg)
        else:
            tls = daemon.connect()
    except PinMismatch:
        raise SystemExit("Refusing to connect: the host at %s:%s does not hold the key in your invite.\n"
                         "Check the address, or create a fresh invite with: hermes hands pair" % (cfg["host"], cfg["port"]))
    except Rejected as exc:
        raise SystemExit("The brain refused this machine: %s" % exc)
    except (OSError, ssl.SSLError) as exc:
        if pair is not None:
            raise SystemExit("Could not reach the Hermes host at %s:%s (%s).\nIs the port open and is the "
                             "address the one this machine can reach?" % (cfg["host"], cfg["port"], exc))
        ui.line("  %s %s" % (ui.dim("…"), ui.dim("brain unreachable (%s), will keep trying" % exc.__class__.__name__)))
        tls = None
    if tls is not None:
        banner(ui, cfg, daemon, pair is not None)
    return daemon.run_forever(first=tls)


def cmd_list(_args):
    brains = load_brains()
    if not brains:
        print("Not paired with any Hermes host yet.")
        return 0
    for cfg in brains:
        print("%-20s %s:%s  (this machine is %r there)" % (cfg.get("brain"), cfg.get("host"), cfg.get("port"), cfg.get("device")))
    return 0


def cmd_forget(args):
    cfg = pick_brain(args.brain)
    os.unlink(cfg["_path"])
    print("Forgot %s. Its token is gone from this machine; also run `hermes hands revoke %s` on the brain."
          % (cfg.get("brain"), cfg.get("device")))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="hands.py", description="local-hands daemon: let a remote Hermes act on this machine, on your terms.")
    sub = parser.add_subparsers(dest="cmd")

    def serve_options(p):
        p.add_argument("--workspace", "-w", default=None, help="directory commands start in (default: where you run this)")
        p.add_argument("--approve", choices=sorted(APPROVE_HELP), default="session",
                       help="when to ask you before running: session (default), every, auto")
        p.add_argument("--approve-timeout", type=int, default=120, help="seconds an approval prompt waits (default 120)")

    join = sub.add_parser("join", help="pair with a Hermes host using an invite from `hermes hands pair`")
    join.add_argument("invite")
    join.add_argument("--name", default="", help="name for this machine on the brain (default: its hostname)")
    serve_options(join)
    up = sub.add_parser("up", help="reconnect to a Hermes host you already paired")
    up.add_argument("brain", nargs="?", default=None)
    serve_options(up)
    sub.add_parser("list", help="show the Hermes hosts this machine is paired with")
    forget = sub.add_parser("forget", help="delete a pairing from this machine")
    forget.add_argument("brain")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "join":
        try:
            pair = parse_invite(args.invite)
        except ValueError as exc:
            raise SystemExit(str(exc))
        return cmd_serve(args, pair=pair)
    if args.cmd == "up":
        return cmd_serve(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "forget":
        return cmd_forget(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
