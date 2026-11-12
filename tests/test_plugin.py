"""The Hermes-facing layer (provider.py, __init__.py), loaded against stand-ins for the two
Hermes classes it subclasses, so these run without Hermes installed.

They pin down two properties: a command on the ``brain`` target never inherits Hermes' own
environment, and reading the hub's state never starts the hub.
"""

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
PKG = "lh_plugin_under_test"


def load_plugin():
    if PKG in sys.modules:
        return sys.modules[PKG]

    def stub(name, **attrs):
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        sys.modules.setdefault(name, module)

    class BaseEnvironment:
        def __init__(self, cwd, timeout, env=None, persist_env=True):
            self.cwd, self.timeout = cwd, timeout
            self._snapshot_ready = self._prefer_nonlogin = False
            self._snapshot_path = self._cwd_file = ""

        def init_session(self):
            pass

    stub("agent")
    stub("agent.terminal_env_provider", TerminalEnvironmentProvider=type("TerminalEnvironmentProvider", (), {}))
    stub("tools")
    stub("tools.environments")
    stub("tools.environments.base", BaseEnvironment=BaseEnvironment,
         EnvironmentConnectionError=type("EnvironmentConnectionError", (Exception,), {}))
    spec = importlib.util.spec_from_file_location(PKG, str(ROOT / "__init__.py"),
                                                  submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[PKG] = module
    spec.loader.exec_module(module)
    return module


class PluginCase(unittest.TestCase):
    def setUp(self):
        self.plugin = load_plugin()
        self.provider = sys.modules[PKG + ".provider"]
        self.lh_core = sys.modules[PKG + ".lh_core"]
        self.rt = self.provider.RUNTIME
        self.tmp = tempfile.TemporaryDirectory(prefix="lh-")
        self.addCleanup(self.tmp.cleanup)
        saved = (self.rt.data_dir, dict(self.rt.settings), self.rt.target)
        self.addCleanup(lambda: (setattr(self.rt, "data_dir", saved[0]), setattr(self.rt, "settings", saved[1]),
                                 setattr(self.rt, "target", saved[2])))
        self.rt.data_dir, self.rt.settings, self.rt.target = Path(self.tmp.name), dict(self.plugin.SETTINGS), None


class HubIsNotStartedByReads(PluginCase):
    def spawn_guard(self):
        return mock.patch.object(self.lh_core, "spawn_hub", side_effect=AssertionError("hub was started"))

    def test_hands_tool_reports_hub_not_running_and_starts_nothing(self):
        with self.spawn_guard():
            status = json.loads(self.plugin._tool_hands({"action": "status"}))
            use = json.loads(self.plugin._tool_hands({"action": "use", "machine": "laptop"}))
        self.assertEqual(status["hub"], "not running")
        self.assertIn("hermes hands up", status["note"])
        self.assertEqual(status["machines"], [])
        self.assertFalse(use["ok"])
        self.assertIn("hub not running", use["message"])
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_slash_status_use_hook_and_doctor_start_nothing(self):
        with self.spawn_guard():
            self.assertIn("not running", self.plugin._slash("status"))
            self.assertIn("not running", self.plugin._slash("use laptop"))
            self.plugin._slash("log")
            self.plugin._slash("doctor")
            with mock.patch.object(self.plugin, "_backend_is_hands", return_value=True):
                self.plugin._pre_llm_call(session_id="s")
            self.provider.HandsProvider().probe()
            self.provider.HandsProvider().doctor_checks()

    def test_only_explicit_paths_ask_for_a_start(self):
        with mock.patch.object(self.lh_core, "spawn_hub", return_value=None) as spawn:
            self.rt.status()
            self.assertEqual(spawn.call_count, 0)
            self.rt.settings["autostart_hub"] = False
            self.rt.status(autostart=True)                      # the backend, autostart disabled
            self.assertEqual(spawn.call_count, 0)
            self.rt.status(autostart=True, explicit=True)       # hermes hands up / pair
            self.assertEqual(spawn.call_count, 1)
            self.rt.settings["autostart_hub"] = True
            self.rt.status(autostart=True)                      # the backend
            self.assertEqual(spawn.call_count, 2)


class BrainCommandsDoNotInheritHermesEnvironment(PluginCase):
    SECRETS = {"OPENROUTER_API_KEY": "sk-or-test", "ANTHROPIC_API_KEY": "sk-ant-test",
               "TELEGRAM_BOT_TOKEN": "123:abc", "LH_UNRELATED_SECRET": "hunter2"}

    def environment(self):
        return self.provider.HandsEnvironment(self.rt, self.lh_core.BRAIN, [], 30, "task")

    def test_minimal_env_is_an_allowlist(self):
        env = self.provider.minimal_env(dict(self.SECRETS, PATH="/bin", HOME="/h", LC_ALL="C", PYTHONPATH="/x"))
        self.assertEqual(env, {"PATH": "/bin", "HOME": "/h", "LC_ALL": "C"})
        self.assertIn("PATH", self.provider.minimal_env({}))

    def test_fallback_spawn_passes_no_secret(self):
        # No tools.environments.local here, as on a Hermes whose local backend cannot be built.
        with mock.patch.dict(os.environ, self.SECRETS), self.assertLogs(PKG + ".provider", "WARNING"):
            env = self.environment()
            proc = env._run_bash("env; echo HOME_IS=$HOME")
            out = proc.stdout.read()
            proc.stdout.close()
            proc.wait()
        self.assertEqual(proc.returncode, 0)
        for name, value in self.SECRETS.items():
            self.assertNotIn(name, out)
            self.assertNotIn(value, out)
        self.assertIn("HOME_IS=" + os.environ.get("HOME", ""), out)
        self.assertTrue(proc._lh_group)

    def test_core_local_environment_is_used_when_hermes_provides_it(self):
        calls = []

        class LocalEnvironment:
            def __init__(self, cwd="", timeout=60):
                calls.append(("init", cwd, timeout))

            def _run_bash(self, cmd, *, login=False, timeout=120, stdin_data=None):
                calls.append(("run", cmd, login, timeout, stdin_data))
                return types.SimpleNamespace(pid=0)

            def _kill_process(self, proc):
                calls.append(("kill", proc))

            def _force_kill_process(self, proc):
                calls.append(("force", proc))

            def cleanup(self):
                calls.append(("cleanup",))

        local = types.ModuleType("tools.environments.local")
        local.LocalEnvironment = LocalEnvironment
        with mock.patch.dict(sys.modules, {"tools.environments.local": local}), \
                mock.patch.object(self.provider.subprocess, "Popen", side_effect=AssertionError("bare Popen")):
            env = self.environment()
            proc = env._run_bash("echo hi", login=True, timeout=7, stdin_data="x")
            env._run_bash("echo again")
            env._kill_process(proc)
            env._force_kill_process(proc)
            env.cleanup()
        self.assertEqual(calls, [("init", os.path.expanduser("~"), 30), ("run", "echo hi", True, 7, "x"),
                                 ("run", "echo again", False, 120, None), ("kill", proc), ("force", proc),
                                 ("cleanup",)])


if __name__ == "__main__":
    unittest.main()
