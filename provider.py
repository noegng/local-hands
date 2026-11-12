"""Terminal backend ``hands``: Hermes' terminal and file tools run on a paired machine.

The environment spawns ``lh_core.py exec`` per command, exactly as the SSH backend spawns
``ssh``: a real subprocess whose stdout is the remote output and whose exit status is the
remote exit status. BaseEnvironment therefore gives us interrupts, timeouts, cwd tracking,
env snapshots and background-process polling unchanged.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment

from . import lh_core

logger = logging.getLogger(__name__)

PROBE_TASK_ID = "prompt-backend-probe"   # agent/prompt_builder.py::_run_backend_probe
_MARK = "#LH:"                            # first line of a wrapped script: routing + display text
SETUP_DISPLAY = "(shell session setup: Hermes reads your shell environment)"
_OS_NAMES = {"Darwin": "macOS", "Linux": "Linux", "Windows": "Windows"}


def describe_machine(machine: dict) -> str:
    os_name = _OS_NAMES.get(machine.get("os", ""), machine.get("os") or "unknown OS")
    return f"{machine['name']} ({os_name}, user {machine.get('user') or '?'}, workspace {machine.get('workspace') or '~'})"


class Runtime:
    """Process-wide state shared by the provider, the tool, the hook and the commands."""

    def __init__(self) -> None:
        self.settings: dict[str, Any] = {}
        self.data_dir: Optional[Path] = None
        self.target: Optional[str] = None          # machine chosen with the hands tool or /hands use; None = default
        self.envs: "list[HandsEnvironment]" = []
        self.lock = threading.RLock()

    # -- hub ------------------------------------------------------------------------
    @property
    def ctl(self) -> Path:
        return lh_core.control_socket_path(self.data_dir)

    def status(self, autostart: bool = False, explicit: bool = False) -> Optional[dict]:
        """Hub status, or None when the hub is not running (and was not started).

        ``autostart`` is only passed by the paths that genuinely need a listening hub: the
        ``hands`` backend creating an environment (unless ``autostart_hub`` is off), and
        ``hermes hands up`` / ``pair``, which the user ran on purpose (``explicit``). Reading
        the status (the ``hands`` tool, ``/hands status``, the prompt hook) never starts it."""
        try:
            return lh_core.rpc(self.ctl, {"op": "status"}, timeout=2.0)
        except lh_core.HubUnavailable:
            if not (autostart and (explicit or self.settings.get("autostart_hub", True))):
                return None
        try:
            return lh_core.spawn_hub(self.data_dir, bind=str(self.settings.get("bind") or "0.0.0.0"),
                                     port=int(self.settings.get("port") or lh_core.DEFAULT_PORT),
                                     brain_name=str(self.settings.get("brain_name") or ""))
        except lh_core.HubUnavailable as exc:
            logger.warning("local-hands hub could not be started: %s", exc)
            return None

    def machines(self, autostart: bool = False) -> list[dict]:
        status = self.status(autostart)
        return list(status.get("machines", [])) if status else []

    def has_paired_machine(self) -> bool:
        """Cheap (one small file read): used by is_available(), which runs during UI paints."""
        return bool(lh_core.read_json(self.data_dir / "devices.json", {})) if self.data_dir else False

    # -- targets --------------------------------------------------------------------
    def brain_allowed(self) -> bool:
        return bool(self.settings.get("brain_target", True))

    def default_target(self, machines: list[dict]) -> Optional[str]:
        wanted = str(self.settings.get("default_machine") or "")
        names = [m["name"] for m in machines]
        if wanted and (wanted in names or (wanted == lh_core.BRAIN and self.brain_allowed())):
            return wanted
        online = [m["name"] for m in machines if m.get("online")]
        return (online or names or [None])[0]

    def chosen_target(self) -> Optional[str]:
        """The machine that was explicitly chosen, if any."""
        with self.lock:
            return self.target

    def current_target(self, machines: Optional[list[dict]] = None) -> Optional[str]:
        chosen = self.chosen_target()
        if chosen:
            return chosen
        return self.default_target(self.machines() if machines is None else machines)

    def use(self, name: str) -> None:
        """Choose where commands run from now on. The choice belongs to this Hermes process:
        Hermes keys terminal environments by conversation scope, which a tool call cannot
        name through public plugin surfaces, so one active machine for everyone is the
        behaviour that can be stated (and shown to every conversation) truthfully."""
        with self.lock:
            self.target = name


RUNTIME = Runtime()


# The only variables a brain command inherits when Hermes' own local backend cannot be used.
_BASE_ENV = ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TERM", "TMPDIR", "TZ")


def minimal_env(environ: Optional[dict] = None) -> dict:
    """An explicit allowlist: nothing Hermes was configured with (provider API keys, tokens)
    reaches the child process."""
    environ = os.environ if environ is None else environ
    env = {k: v for k, v in environ.items() if k in _BASE_ENV or k.startswith("LC_")}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    return env


def _core_local_environment(timeout: int):
    """Hermes' own local backend, which owns the rules for what a host command may inherit
    (it strips provider credentials). None when it cannot be built."""
    try:
        from tools.environments.local import LocalEnvironment
        return LocalEnvironment(cwd=os.path.expanduser("~"), timeout=timeout)
    except Exception:
        logger.warning("local-hands: Hermes' LocalEnvironment is unavailable; brain commands "
                       "run with a minimal environment instead", exc_info=True)
        return None


class _ProbeEnvironment:
    """Answers Hermes' prompt-time ``uname`` probe from what the daemon reported when it
    connected, so building the system prompt never raises an approval prompt on the machine."""

    cwd = "~"

    def __init__(self, machine: dict):
        self._machine = machine

    def execute(self, command: str, *args, **kwargs) -> dict:
        m = self._machine
        return {"output": f"os={m.get('os') or 'unknown'}\nkernel={m.get('release') or 'unknown'}\n", "returncode": 0}

    def cleanup(self) -> None:
        pass


class HandsEnvironment(BaseEnvironment):
    _passwordless_sudo_probe_supported = True
    # The first command of a shell session may wait for the user to approve it on their
    # machine (daemon default: 120 s), so the snapshot bootstrap must outlast that.
    _snapshot_timeout = 130

    def __init__(self, runtime: Runtime, target: str, machines: list[dict], timeout: int, task_id: str,
                 config_cwd: str = ""):
        self._rt = runtime
        self._task = task_id
        # terminal.cwd is a path on the Hermes host. Each machine starts in the folder its user
        # launched the daemon in instead, so that configured path is never cd'ed into here.
        self._config_cwd = config_cwd if config_cwd not in ("", "~", ".") else ""
        # What the machine's approval prompt calls a "session": this Hermes conversation, so the
        # user is asked once per conversation and not again each time Hermes recycles an idle
        # environment.
        self._approval_session = hashlib.sha256(str(task_id).encode("utf-8", "replace")).hexdigest()[:12]
        self._state: dict[str, dict] = {}       # per-target shell state while it is not the active one
        self._seen: dict[str, set] = {}         # cwds each target has actually reported
        self._swap = threading.RLock()
        self._local: Any = None                 # Hermes' LocalEnvironment, built on first brain command
        self._local_lock = threading.Lock()
        self._tl = threading.local()
        self._target = target
        self._init_target = target
        super().__init__(cwd=self._home_of(target, machines), timeout=timeout)
        self.init_session()
        with runtime.lock:
            runtime.envs.append(self)

    # ---- targets --------------------------------------------------------------------

    def _home_of(self, target: str, machines: Optional[list[dict]] = None) -> str:
        if target == lh_core.BRAIN:
            return os.path.expanduser("~")
        for machine in (self._rt.machines() if machines is None else machines):
            if machine["name"] == target and str(machine.get("workspace", "")).startswith("/"):
                return machine["workspace"]
        return "~"

    def _activate(self, target: str) -> None:
        """Make *target* the machine this environment's shell state describes."""
        with self._swap:
            if target == self._target:
                return
            self._state[self._target] = {"cwd": self.cwd, "ready": self._snapshot_ready,
                                         "nonlogin": self._prefer_nonlogin,
                                         "files": (self._snapshot_path, self._cwd_file)}
            saved = self._state.pop(target, None)
            self._target = target
            if saved is not None and "files" in saved:
                self.cwd, self._snapshot_ready, self._prefer_nonlogin = saved["cwd"], saved["ready"], saved["nonlogin"]
                self._snapshot_path, self._cwd_file = saved["files"]
                return
            # First visit: this target gets its own shell-state files, so two targets that happen
            # to share a filesystem (the brain and a daemon on the same host) never mix them up.
            tag = uuid.uuid4().hex[:12]
            temp_dir = self.get_temp_dir().rstrip("/") or "/"
            self._snapshot_path = f"{temp_dir}/hermes-snap-{tag}.sh"
            self._cwd_file = f"{temp_dir}/hermes-cwd-{tag}.txt"
            self.cwd = saved["cwd"] if saved and saved.get("cwd") else self._home_of(target)
            self._snapshot_ready, self._prefer_nonlogin = False, False
            self._init_target = target
            self.init_session()

    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        target = self._rt.chosen_target() or self._target
        with self._swap:
            self._activate(target)
            self._tl.target = target
            # Hermes passes each conversation's last recorded cwd (or terminal.cwd). Right after
            # a switch that path belongs to the previous machine, and terminal.cwd belongs to the
            # Hermes host: drop either unless this machine has reported that directory itself.
            if cwd and cwd != self.cwd and cwd not in self._seen.get(target, ()) and (
                    cwd == self._config_cwd
                    or any(cwd in seen for name, seen in self._seen.items() if name != target)):
                cwd = ""
            # "~" is this backend's declared default, which Hermes passes until a conversation
            # has a directory of its own. Here the default is the machine's workspace (where the
            # shell already is), not the user's home directory.
            if cwd in ("~", "~/"):
                cwd = ""
        result = super().execute(command, cwd, **kwargs)
        if result.get("cwd_observed") and result.get("cwd"):
            seen = self._seen.setdefault(target, set())
            if len(seen) > 2000:
                seen.clear()
            seen.add(result["cwd"])
        return result

    def _update_cwd(self, result: dict) -> None:
        ran_on = getattr(self._tl, "target", None)
        with self._swap:
            if ran_on is None or ran_on == self._target:
                super()._update_cwd(result)
                return
            # The target changed while this command was running: its cwd belongs to the
            # machine it ran on, not to the one that is active now.
            keep = self.cwd
            super()._update_cwd(result)
            self._state.setdefault(ran_on, {"ready": False, "nonlogin": False})["cwd"] = self.cwd
            self.cwd = keep

    # ---- spawning -------------------------------------------------------------------

    def _wrap_command(self, command: str, *args, **kwargs) -> str:
        wrapped = super()._wrap_command(command, *args, **kwargs)
        meta = {"target": getattr(self._tl, "target", None) or self._target, "display": command[:500]}
        return _MARK + base64.b64encode(json.dumps(meta).encode()).decode() + "\n" + wrapped

    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: Optional[str] = None):
        target, display = self._init_target, SETUP_DISPLAY
        if cmd_string.startswith(_MARK):
            head, _, cmd_string = cmd_string.partition("\n")
            try:
                meta = json.loads(base64.b64decode(head[len(_MARK):]))
                target, display = meta.get("target") or target, meta.get("display") or ""
            except ValueError:
                pass
        stdin = subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL
        common = dict(stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                      encoding="utf-8", errors="replace")
        if target == lh_core.BRAIN:
            # Never a bare Popen here: it would hand the whole Hermes environment (provider API
            # keys included) to the command. Hermes' local backend spawns it with its own
            # credential-stripped environment; failing that, an explicit allowlist does.
            local = self._brain_local()
            if local is not None:
                proc = local._run_bash(cmd_string, login=login, timeout=timeout, stdin_data=stdin_data)
                proc._lh_local = local
                return proc
            argv = ["bash"] + (["-l"] if login else []) + ["-c", cmd_string]
            proc = subprocess.Popen(argv, start_new_session=True, env=minimal_env(), **common)
            proc._lh_group = True
        else:
            read_fd, write_fd = os.pipe()
            argv = lh_core.exec_argv(self._rt.ctl, target, session=self._approval_session, label=self._task[:64],
                                     login=login, display=display, script_fd=read_fd)
            try:
                proc = subprocess.Popen(argv, pass_fds=(read_fd,), **common)
            finally:
                os.close(read_fd)
            threading.Thread(target=_write_all, args=(write_fd, cmd_string.encode("utf-8")), daemon=True).start()
        if stdin_data is not None:
            writer = threading.Thread(target=_feed_text, args=(proc, stdin_data), daemon=True)
            proc._hermes_stdin_thread = writer   # BaseEnvironment joins it before reading results
            writer.start()
        return proc

    def _brain_local(self):
        with self._local_lock:
            if self._local is None:
                self._local = _core_local_environment(self.timeout) or False
            return self._local or None

    def _kill_process(self, proc) -> None:
        # Brain commands run in their own process group; for a machine, killing the exec client
        # closes its socket and the hub tells the daemon to stop the remote process group.
        local = getattr(proc, "_lh_local", None)
        if local is not None:
            local._kill_process(proc)
            return
        try:
            if getattr(proc, "_lh_group", False):
                os.killpg(proc.pid, 15)
                time.sleep(0.2)
                if proc.poll() is None:
                    os.killpg(proc.pid, 9)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def _force_kill_process(self, proc) -> None:
        local = getattr(proc, "_lh_local", None)
        if local is not None:
            local._force_kill_process(proc)
        else:
            self._kill_process(proc)

    def cleanup(self) -> None:
        with self._rt.lock:
            if self in self._rt.envs:
                self._rt.envs.remove(self)
        local, self._local = self._local, None
        if local:
            try:
                local.cleanup()
            except Exception:
                logger.debug("local-hands: LocalEnvironment cleanup failed", exc_info=True)


def _write_all(fd: int, data: bytes) -> None:
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError:
        pass


def _feed_text(proc, text: str) -> None:
    try:
        proc.stdin.write(text)
    except (OSError, ValueError):
        pass
    finally:
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass


class HandsProvider(TerminalEnvironmentProvider):
    name = "hands"
    display_name = "Local Hands"
    is_remote = True        # commands do not run on the Hermes host
    # "Container" in Hermes' vocabulary means "a filesystem that is not the Hermes host's": host
    # paths (terminal.cwd, a Desktop session's folder) are never cd'ed into or written through, and
    # relative file paths are anchored on the machine's workspace. It does NOT relax anything:
    # skip_container_guards below stays False, so dangerous-command approvals remain on.
    is_container = True
    supports_streams = False

    @property
    def description(self) -> str:
        return "Run terminal and file tools on your own computer(s) through an outbound, pinned-TLS hands daemon."

    @property
    def skip_container_guards(self) -> bool:
        return False

    @property
    def default_cwd(self) -> Optional[str]:
        return "~"   # resolved per machine to the daemon's workspace

    @property
    def env_description(self) -> str:
        try:
            machines = RUNTIME.machines()
            target = RUNTIME.current_target(machines)
            for machine in machines:
                if machine["name"] == target:
                    return f"the user's own computer {describe_machine(machine)}, reached through Local Hands"
        except Exception:
            pass
        return "one of the user's own computers, reached through Local Hands"

    def is_available(self) -> bool:
        # Nothing to install: the backend is usable as soon as a machine is paired, and
        # create_environment() explains how to pair one when none is.
        return True

    def probe(self) -> tuple[str, str]:
        if not RUNTIME.has_paired_machine():
            return "needs_setup", "No machine is paired yet. Run: hermes hands pair"
        machines = RUNTIME.machines()
        online = [m["name"] for m in machines if m.get("online")]
        if online:
            return "ready", "online: " + ", ".join(online)
        return "ready", "paired, but no machine is connected right now (python3 hands.py up)"

    def setup_instructions(self) -> list[str]:
        return ["Pair the computer Hermes should act on:",
                "  1. here:            hermes hands pair",
                "  2. on that machine: run the two commands it prints",
                "Then check with:      hermes hands status"]

    def doctor_checks(self) -> list[tuple[bool, str, str]]:
        status = RUNTIME.status()
        machines = status.get("machines", []) if status else []
        online = [m["name"] for m in machines if m.get("online")]
        return [(status is not None, "Local Hands hub", f"(port {status['port']})" if status else "(not running: hermes hands up)"),
                (bool(online), "Local Hands machines", f"({', '.join(online)} online)" if online else
                 ("(none connected)" if machines else "(none paired: hermes hands pair)"))]

    def create_environment(self, *, cwd: str, timeout: int, task_id: str = "default", image: Optional[str] = None,
                           container_config: Optional[dict] = None, **kwargs: Any):
        from tools.environments.base import EnvironmentConnectionError

        if task_id == PROBE_TASK_ID:
            machines = RUNTIME.machines()
            target = RUNTIME.current_target(machines)
            for machine in machines:
                if machine["name"] == target and machine.get("online"):
                    return _ProbeEnvironment(machine)
            raise EnvironmentConnectionError("no hands machine is connected")
        # Hermes only calls this when terminal.backend is "hands": the one place, with
        # `hermes hands up` and `pair`, where the hub is started.
        machines = RUNTIME.machines(autostart=True)
        target = RUNTIME.current_target(machines)
        by_name = {m["name"]: m for m in machines}
        if target == lh_core.BRAIN and not RUNTIME.brain_allowed():
            target = RUNTIME.default_target(machines)
        if target is None:
            raise EnvironmentConnectionError(
                "Local Hands has no paired machine.",
                retry_hint="Ask the user to run `hermes hands pair` on the Hermes host and follow the two steps it prints.")
        if target != lh_core.BRAIN and not by_name.get(target, {}).get("online"):
            raise EnvironmentConnectionError(
                f"The user's machine '{target}' is not connected to Local Hands.",
                retry_hint=f"Ask the user to start the daemon on {target} (python3 hands.py up), then retry. "
                           "Nothing ran.")
        return HandsEnvironment(RUNTIME, target, machines, timeout, str(task_id or "default"), config_cwd=str(cwd or ""))
