"""Shared test rig: a real hub and real hands daemons on 127.0.0.1, in temporary directories.

Standard library only, so the suite runs with ``python3 -m unittest discover -s tests`` as well
as with pytest.
"""

import os
import pty
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import lh_core  # noqa: E402

HANDS = str(ROOT / "hands.py")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(predicate, timeout=10.0, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return predicate()


class Rig:
    """One hub plus any number of daemons. Use as a context manager."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="lh-"))
        self.data = self.tmp / "data"
        self.port = free_port()
        self.daemons = []
        self.status = lh_core.spawn_hub(self.data, bind="127.0.0.1", port=self.port, brain_name="test-brain")
        self.ctl = lh_core.control_socket_path(self.data)
        self.pin = self.status["pin"]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        for proc in self.daemons:
            if proc.poll() is None:
                proc.terminate()
        for proc in self.daemons:
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.stop_hub()
        shutil.rmtree(self.tmp, ignore_errors=True)
        if self.ctl.parent != self.data:
            shutil.rmtree(self.ctl.parent, ignore_errors=True)

    def stop_hub(self):
        try:
            pid = lh_core.rpc(self.ctl, {"op": "status"})["pid"]
            lh_core.rpc(self.ctl, {"op": "stop"})
        except OSError:
            return
        wait_for(lambda: not _alive(pid), 5)

    def rpc(self, **request):
        return lh_core.rpc(self.ctl, request)

    def invite(self, name="", host="127.0.0.1"):
        reply = self.rpc(op="invite", name=name)
        assert reply["ok"], reply
        return lh_core.make_invite(host, self.port, reply["code"], reply["pin"])

    def config_home(self, name):
        return str(self.tmp / ("cfg-" + name))

    def daemon_argv(self, *args):
        return [sys.executable, "-B", HANDS, *args]

    def daemon_env(self, name):
        return dict(os.environ, XDG_CONFIG_HOME=self.config_home(name), NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")

    def workspace(self, name):
        path = self.tmp / ("ws-" + name)
        path.mkdir(exist_ok=True)
        return str(path.resolve())

    def join(self, name="mac", approve="auto", wait=True, extra=()):
        """Pair a new daemon (no terminal attached) and wait until the hub sees it."""
        log = open(self.tmp / ("daemon-%s.log" % name), "ab")
        proc = subprocess.Popen(
            self.daemon_argv("join", self.invite(name), "--workspace", self.workspace(name), "--approve", approve, *extra),
            env=self.daemon_env(name), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        self.daemons.append(proc)
        if wait:
            assert self.wait_online(name), self.daemon_log(name)
        return proc

    def up(self, name="mac", approve="auto"):
        log = open(self.tmp / ("daemon-%s.log" % name), "ab")
        proc = subprocess.Popen(
            self.daemon_argv("up", "--workspace", self.workspace(name), "--approve", approve),
            env=self.daemon_env(name), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        self.daemons.append(proc)
        return proc

    def daemon_log(self, name="mac"):
        try:
            return (self.tmp / ("daemon-%s.log" % name)).read_text(errors="replace")
        except OSError:
            return ""

    def machine(self, name):
        for machine in self.rpc(op="status")["machines"]:
            if machine["name"] == name:
                return machine
        return None

    def wait_online(self, name, online=True, timeout=10):
        return wait_for(lambda: (self.machine(name) or {}).get("online", False) == online, timeout)

    def popen(self, script, machine="mac", session="s1", stdin=subprocess.DEVNULL, display="", wait=0.0):
        read_fd, write_fd = os.pipe()
        argv = lh_core.exec_argv(self.ctl, machine, session=session, display=display, script_fd=read_fd, wait=wait)
        proc = subprocess.Popen(argv, pass_fds=(read_fd,), stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        os.close(read_fd)
        os.write(write_fd, script.encode("utf-8"))
        os.close(write_fd)
        return proc

    def run(self, script, machine="mac", session="s1", stdin=None, timeout=30, display=""):
        proc = self.popen(script, machine, session, subprocess.PIPE if stdin is not None else subprocess.DEVNULL, display)
        out, _ = proc.communicate(stdin, timeout=timeout)
        return proc.returncode, out


def _alive(pid):
    for proc in lh_core._SPAWNED:   # hubs started by this process stay zombies until polled
        proc.poll()
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class PtyDaemon:
    """A hands daemon attached to a pseudo-terminal, to drive its approval prompts."""

    def __init__(self, rig, name="mac", approve="session", timeout=120, mode="join"):
        self.rig, self.name = rig, name
        self.master, slave = pty.openpty()
        args = ["join", rig.invite(name)] if mode == "join" else ["up"]
        self.proc = subprocess.Popen(
            rig.daemon_argv(*args, "--workspace", rig.workspace(name), "--approve", approve,
                            "--approve-timeout", str(timeout)),
            env=rig.daemon_env(name), stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        rig.daemons.append(self.proc)
        self.seen = ""
        assert rig.wait_online(name), self.read(1)

    def read(self, seconds=0.2):
        deadline = time.time() + seconds
        while time.time() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if ready:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    break
                if not data:
                    break
                self.seen += data.decode("utf-8", "replace")
        return self.seen

    def expect(self, text, timeout=10):
        deadline = time.time() + timeout
        while text not in self.seen and time.time() < deadline:
            self.read(0.1)
        assert text in self.seen, "did not see %r in:\n%s" % (text, self.seen)
        self.seen = self.seen.split(text, 1)[1]

    def type(self, text):
        os.write(self.master, text.encode())

    def answer(self, text):
        """Type an answer once the daemon is actually reading it. The daemon discards whatever
        was typed before the question was fully shown (it flushes the terminal's input, then
        prints the choices ending in "›"), so typing as soon as the first line of the question
        appears can lose the answer on a slow machine."""
        self.expect("\u203a")
        self.type(text)

    def close(self):
        try:
            os.close(self.master)
        except OSError:
            pass
