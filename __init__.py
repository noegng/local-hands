"""local-hands: remote brain, local hands.

Hermes runs on a server; its terminal and file tools run on the computers you pair.

Registers:
  * terminal backend ``hands``            (provider.py)
  * tool ``hands``                        list machines / choose where commands run
  * hook ``pre_llm_call``                 tells the model where it is acting, only when that changes
  * slash command ``/hands``              status, pair, use, log, doctor
  * CLI ``hermes hands ...``              pair, status, up, down, revoke, log, doctor, join
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from pathlib import Path

from . import lh_core
from .provider import RUNTIME, HandsProvider, describe_machine

logger = logging.getLogger(__name__)

PLUGIN = "local-hands"
SETTINGS = {"port": lh_core.DEFAULT_PORT, "bind": "0.0.0.0", "public_host": "", "brain_name": "",
            "default_machine": "", "brain_target": True, "autostart_hub": True}

HANDS_SCHEMA = {
    "name": "hands",
    "description": (
        "Choose which of the user's computers your terminal and file tools act on (Local Hands). "
        "terminal, read_file, write_file, patch, search_files and execute_code run on one of the user's own "
        "paired computers, not on the server Hermes lives on. Use action='status' to "
        "see the paired machines, which one is active and whether it is online. Use action='use' with a "
        "machine name to choose where the next commands run ('brain' is the Hermes server itself). "
        "Each machine keeps its own working directory. If a command comes back with "
        "'[local-hands] ... refused', the user declined it on their machine: do not retry, ask them."),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["status", "use"]},
            "machine": {"type": "string", "description": "Machine name for action='use'."},
        },
        "required": ["action"],
    },
}


# --------------------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------------------

def _targets(machines: list) -> list:
    names = [m["name"] for m in machines]
    return names + ([lh_core.BRAIN] if RUNTIME.brain_allowed() else [])


def _overview(machines: list) -> dict:
    active = RUNTIME.current_target(machines)
    return {"active": active, "machines": [
        {"name": m["name"], "online": bool(m.get("online")), "os": m.get("os"), "user": m.get("user"),
         "workspace": m.get("workspace"), "approval_on_machine": m.get("approve")} for m in machines],
        "brain_target_enabled": RUNTIME.brain_allowed()}


def _use(name: str, machines: list) -> tuple[bool, str]:
    name = (name or "").strip()
    if name not in _targets(machines):
        return False, f"unknown machine '{name}'. Known: {', '.join(_targets(machines)) or 'none paired'}"
    if name != lh_core.BRAIN and not next(m for m in machines if m["name"] == name).get("online"):
        return False, f"'{name}' is paired but offline: its user has to run `python3 hands.py up` there"
    RUNTIME.use(name)
    return True, f"terminal and file tools now run on {name}"


def _tool_hands(args: dict, **kwargs) -> str:
    try:
        machines = RUNTIME.machines(autostart=True)
        if args.get("action") == "use":
            ok, message = _use(str(args.get("machine") or ""), machines)
            return json.dumps({"ok": ok, "message": message, **_overview(machines)})
        return json.dumps({"ok": True, **_overview(machines)})
    except Exception as exc:  # a tool handler must never raise
        return json.dumps({"ok": False, "error": str(exc)})


# --------------------------------------------------------------------------------------
# pre_llm_call: say where the hands are, once, and again only when it changes
# --------------------------------------------------------------------------------------

_last_note: dict = {}


def _backend_is_hands() -> bool:
    env = os.environ.get("TERMINAL_ENV")
    if env:
        return env.strip().lower() == "hands"
    try:
        from hermes_cli.config import load_config_readonly
        return str((load_config_readonly().get("terminal") or {}).get("backend") or "").lower() == "hands"
    except Exception:
        return False


def _note(machines: list) -> str:
    active = RUNTIME.current_target(machines)
    if active is None:
        return ("[Local Hands] No computer is paired yet, so terminal and file tools cannot run. "
                "The user has to run `hermes hands pair` on the Hermes host.")
    others = [t for t in _targets(machines) if t != active]
    if active == lh_core.BRAIN:
        where = "the Hermes server itself ('brain')"
    else:
        machine = next((m for m in machines if m["name"] == active), None)
        if machine is None or not machine.get("online"):
            return (f"[Local Hands] The user's machine '{active}' is OFFLINE, so terminal and file tools will fail "
                    f"until they run `python3 hands.py up` on it."
                    + (f" Other targets: {', '.join(others)} (hands tool)." if others else ""))
        where = f"the user's own computer {describe_machine(machine)}, not the server Hermes runs on"
    return (f"[Local Hands] Terminal and file tools currently run on {where}."
            + (f" Other targets: {', '.join(others)}; switch with the `hands` tool "
               "(action='use', machine='<name>')." if others else ""))


def _pre_llm_call(session_id: str = "", **kwargs):
    try:
        if not _backend_is_hands():
            return None
        note = _note(RUNTIME.machines())
        if _last_note.get(session_id) == note:
            return None
        if len(_last_note) > 500:
            _last_note.clear()
        _last_note[session_id] = note
        return {"context": note}
    except Exception:
        logger.debug("local-hands pre_llm_call failed", exc_info=True)
        return None


# --------------------------------------------------------------------------------------
# text views shared by /hands and `hermes hands`
# --------------------------------------------------------------------------------------

def _ago(ts) -> str:
    if not ts:
        return "never"
    delta = max(0, int(time.time() - int(ts)))
    for size, unit in ((86400, "d"), (3600, "h"), (60, "min")):
        if delta >= size:
            return f"{delta // size} {unit} ago"
    return "just now"


def _guess_host() -> str:
    host = str(RUNTIME.settings.get("public_host") or "").strip()
    if host:
        return host
    bind = str(RUNTIME.settings.get("bind") or "")
    if bind and bind not in ("0.0.0.0", "::"):
        return bind   # the hub listens on one address only: that is the one to dial
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))   # no packet is sent; this only picks the outbound interface
            return probe.getsockname()[0]
    except OSError:
        return socket.gethostname()


def render_status() -> str:
    status = RUNTIME.status()
    if status is None:
        return "Local Hands hub is not running. Start it with: hermes hands up"
    machines = status["machines"]
    active = RUNTIME.current_target(machines)
    lines = [f"Local Hands · brain \"{status['brain']}\" · port {status['port']} · {len(machines)} machine(s)"]
    for m in machines:
        dot = "●" if m.get("online") else "○"
        state = "online" if m.get("online") else f"offline (seen {_ago(m.get('last_seen'))})"
        mark = "  ← active" if m["name"] == active else ""
        lines.append(f"  {dot} {m['name']:<14} {state:<24} {m.get('os') or '?':<7} {m.get('user') or '?'}@"
                     f"{m.get('hostname') or '?'}  {m.get('workspace') or ''}  approve={m.get('approve') or '?'}{mark}")
    if RUNTIME.brain_allowed():
        lines.append(f"  ● {lh_core.BRAIN:<14} this Hermes host{'  ← active' if active == lh_core.BRAIN else ''}")
    if not machines:
        lines.append("  no machine paired yet: hermes hands pair")
    return "\n".join(lines)


def render_pair(name: str = "", host: str = "") -> str:
    status = RUNTIME.status(autostart=True)
    if status is None:
        return "Could not start the Local Hands hub (see plugin-data/local-hands/hub.log)."
    reply = lh_core.rpc(RUNTIME.ctl, {"op": "invite", "name": name})
    if not reply.get("ok"):
        return f"Cannot create an invite: {reply.get('error')}"
    host = host or _guess_host()
    invite = lh_core.make_invite(host, reply["port"], reply["code"], reply["pin"])
    url_host = f"[{host}]" if ":" in host else host
    return "\n".join([
        f"Pair a computer with this Hermes host (\"{reply['brain']}\"). The invite works once, for 10 minutes.",
        "",
        "On the computer Hermes should act on, in the folder it should work in:",
        "",
        f"  curl -fsSk --pinnedpubkey 'sha256//{reply['pin']}' https://{url_host}:{reply['port']}/hands.py -o hands.py",
        f"  python3 hands.py join '{invite}'",
        "",
        f"That machine must be able to reach {host}:{reply['port']} (open the port, or use your VPN/Tailscale",
        "address with --host). Then: hermes config set terminal.backend hands",
    ])


def render_log(n: int = 15) -> str:
    try:
        entries = lh_core.rpc(RUNTIME.ctl, {"op": "log", "n": n}).get("entries", [])
    except lh_core.HubUnavailable:
        return "Local Hands hub is not running."
    if not entries:
        return "No command has run through Local Hands yet."
    return "\n".join(f"{time.strftime('%H:%M:%S', time.localtime(e.get('ts', 0)))}  {e.get('machine', '?'):<12} "
                     f"exit {e.get('exit')}  {str(e.get('command') or '(session setup)')[:90]}" for e in entries)


def render_doctor() -> str:
    """Checks a user can act on, most basic first."""
    lines = []

    def check(ok: bool, text: str, fix: str = "") -> bool:
        lines.append(f"  {'✓' if ok else '✗'} {text}" + (f"\n      → {fix}" if fix and not ok else ""))
        return ok

    status = RUNTIME.status()
    if not check(status is not None, "hub is running", "hermes hands up   (log: plugin-data/local-hands/hub.log)"):
        return "\n".join(["Local Hands doctor"] + lines)
    port, bind = int(status["port"]), str(status.get("bind") or "")
    check(True, f"listening on {bind}:{port} (TLS, key pin sha256//{status['pin']})")
    host = _guess_host()
    reachable = False
    try:
        with socket.create_connection((host, port), timeout=3):
            reachable = True
    except OSError:
        pass
    check(reachable, f"port {port} answers on {host} (the address printed in invites)",
          "open the port in this host's firewall, or set public_host / use `hermes hands pair --host <address>`")
    machines = status["machines"]
    check(bool(machines), f"{len(machines)} machine(s) paired", "hermes hands pair")
    online = [m["name"] for m in machines if m.get("online")]
    if machines:
        check(bool(online), "connected now: " + (", ".join(online) or "none"), "on the machine: python3 hands.py up")
    check(_backend_is_hands(), "terminal.backend is 'hands'", "hermes config set terminal.backend hands")
    for m in machines:
        if m.get("online") and m.get("approve") == "auto":
            lines.append(f"  · {m['name']} runs commands without asking (--approve auto)")
    return "\n".join(["Local Hands doctor"] + lines)


def _slash(raw_args: str = "", **kwargs) -> str:
    parts = (raw_args or "").split()
    sub = parts[0].lower() if parts else "status"
    if sub == "status":
        return render_status()
    if sub == "use" and len(parts) > 1:
        return _use(parts[1], RUNTIME.machines(autostart=True))[1]
    if sub == "pair":
        return render_pair(parts[1] if len(parts) > 1 else "")
    if sub == "log":
        return render_log()
    if sub == "doctor":
        return render_doctor()
    return "Usage: /hands [status | use <machine> | pair [name] | log | doctor]"


# --------------------------------------------------------------------------------------
# hermes hands ...
# --------------------------------------------------------------------------------------

def _cli_setup(subparser) -> None:
    subs = subparser.add_subparsers(dest="hands_cmd")
    pair = subs.add_parser("pair", help="create a one-time invite for a computer")
    pair.add_argument("name", nargs="?", default="", help="name for the machine (default: its hostname)")
    pair.add_argument("--host", default="", help="address of this host as the other machine reaches it")
    subs.add_parser("status", help="paired machines and which one is active")
    subs.add_parser("up", help="start the hub")
    subs.add_parser("down", help="stop the hub")
    revoke = subs.add_parser("revoke", help="unpair a machine")
    revoke.add_argument("name")
    log = subs.add_parser("log", help="recent commands and where they ran")
    log.add_argument("-n", type=int, default=15)
    subs.add_parser("doctor", help="check the hub, the port, the machines and the backend setting")
    join = subs.add_parser("join", help="make THIS computer a pair of hands for another Hermes host")
    join.add_argument("rest", nargs="...")
    subparser.set_defaults(func=_cli)


def _cli(args) -> None:
    cmd = getattr(args, "hands_cmd", None) or "status"
    if cmd == "pair":
        print(render_pair(args.name, args.host))
    elif cmd == "status":
        print(render_status())
    elif cmd == "up":
        status = RUNTIME.status(autostart=True)
        print(f"Local Hands hub is running on port {status['port']}." if status else "The hub did not start (hub.log).")
    elif cmd == "down":
        try:
            lh_core.rpc(RUNTIME.ctl, {"op": "stop"})
            print("Local Hands hub stopped.")
        except lh_core.HubUnavailable:
            print("The hub was not running.")
    elif cmd == "revoke":
        try:
            reply = lh_core.rpc(RUNTIME.ctl, {"op": "revoke", "name": args.name})
        except lh_core.HubUnavailable:
            reply = {"ok": False, "error": "the hub is not running (hermes hands up)"}
        print(f"Unpaired {args.name}." if reply.get("ok") else f"Could not unpair: {reply.get('error')}")
    elif cmd == "log":
        print(render_log(args.n))
    elif cmd == "doctor":
        print(render_doctor())
    elif cmd == "join":
        from . import hands as daemon
        raise SystemExit(daemon.main(["join", *args.rest]))


# --------------------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------------------

def register(ctx) -> None:
    from plugins.plugin_storage import plugin_data_dir

    RUNTIME.data_dir = Path(plugin_data_dir(PLUGIN))
    RUNTIME.settings = {key: ctx.get_config(key, default) for key, default in SETTINGS.items()}

    ctx.register_terminal_environment_provider(HandsProvider())
    ctx.register_tool(name="hands", toolset="local_hands", schema=HANDS_SCHEMA, handler=_tool_hands)
    ctx.register_hook("pre_llm_call", _pre_llm_call)
    ctx.register_command("hands", handler=_slash, description="Local Hands: machines Hermes can act on",
                         args_hint="[status|use <machine>|pair [name]|log|doctor]")
    ctx.register_cli_command(name="hands", help="Pair and manage the computers Hermes acts on (local-hands)",
                             setup_fn=_cli_setup, handler_fn=_cli)
