"""The approval prompt on the user's machine, driven through a pseudo-terminal."""

import os
import subprocess
import time
import unittest

from harness import PtyDaemon, Rig, lh_core


class Approval(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()
        self.ttys = []

    def tearDown(self):
        for tty in self.ttys:
            tty.close()
        self.rig.close()

    def daemon(self, **kwargs):
        tty = PtyDaemon(self.rig, **kwargs)
        self.ttys.append(tty)
        tty.expect("Ctrl-C stops the daemon")
        return tty

    # ---- --approve session (default) ---------------------------------------------------

    def test_session_yes_covers_the_session_and_only_it(self):
        tty = self.daemon(approve="session")
        proc = self.rig.popen("echo one", session="alpha", display="echo one")
        tty.expect('brain "test-brain" wants to run commands here')
        tty.expect("first command: echo one")
        tty.answer("y\n")
        self.assertEqual(proc.communicate(timeout=10)[0], b"one\n")
        # same session: no question
        self.assertEqual(self.rig.run("echo two", session="alpha", timeout=10), (0, b"two\n"))
        # another session: asked again
        proc = self.rig.popen("echo three", session="beta", display="echo three")
        tty.expect("wants to run commands here")
        tty.answer("y\n")
        self.assertEqual(proc.communicate(timeout=10)[0], b"three\n")

    def test_no_refuses_with_126_and_tells_the_model_not_to_retry(self):
        tty = self.daemon(approve="session")
        marker = self.rig.tmp / "must-not-exist"
        proc = self.rig.popen("touch %s" % marker, session="alpha", display="touch it")
        tty.expect("wants to run commands here")
        tty.answer("n\n")
        out, _ = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, lh_core.EXIT_REFUSED)
        self.assertIn(b"[local-hands] the user refused this on their machine 'mac'", out)
        self.assertIn(b"Do not retry", out)
        self.assertFalse(marker.exists())
        tty.expect("refused")
        # an immediate retry is refused without asking again
        code, out = self.rig.run("touch %s" % marker, session="alpha", timeout=10)
        self.assertEqual(code, lh_core.EXIT_REFUSED)
        self.assertFalse(marker.exists())
        self.assertNotIn("wants to run", tty.read(0.3))

    def test_always_stops_asking_and_the_brain_is_told(self):
        tty = self.daemon(approve="session")
        proc = self.rig.popen("echo one", session="alpha")
        tty.expect("wants to run commands here")
        tty.answer("a\n")
        self.assertEqual(proc.communicate(timeout=10)[0], b"one\n")
        self.assertEqual(self.rig.run("echo two", session="other", timeout=10), (0, b"two\n"))
        self.assertEqual(self.rig.machine("mac")["approve"], "auto")

    def test_unknown_answer_asks_again(self):
        tty = self.daemon(approve="session")
        proc = self.rig.popen("echo one", session="alpha")
        tty.expect("wants to run commands here")
        tty.answer("maybe\n")
        tty.expect("answer with one of the letters shown")
        self.assertIsNone(proc.poll())
        tty.answer("\n")
        tty.expect("answer with one of the letters shown")
        tty.answer("Y\n")
        self.assertEqual(proc.communicate(timeout=10)[0], b"one\n")

    def test_keys_typed_before_the_question_do_not_answer_it(self):
        tty = self.daemon(approve="session")
        tty.type("y\ny\n")
        time.sleep(0.4)
        proc = self.rig.popen("echo one", session="alpha")
        tty.expect("wants to run commands here")
        time.sleep(0.6)
        self.assertIsNone(proc.poll(), "typeahead approved a command")
        tty.answer("n\n")
        proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, lh_core.EXIT_REFUSED)

    def test_no_answer_times_out_cleanly(self):
        tty = self.daemon(approve="session", timeout=2)
        started = time.time()
        code, out = self.rig.run("echo one", session="alpha", timeout=15)
        self.assertEqual(code, lh_core.EXIT_REFUSED)
        self.assertIn(b"nobody answered the approval prompt", out)
        self.assertLess(time.time() - started, 8)
        tty.expect("no answer - refused")

    def test_brain_withdrawing_the_request_clears_the_prompt(self):
        tty = self.daemon(approve="session")
        marker = self.rig.tmp / "must-not-exist"
        proc = self.rig.popen("touch %s" % marker, session="alpha")
        tty.expect("wants to run commands here")
        proc.kill()
        proc.wait()
        tty.expect("the brain withdrew the request")
        # the next request gets a fresh prompt, and a late answer never runs the old command
        proc = self.rig.popen("echo next", session="alpha")
        tty.expect("wants to run commands here")
        tty.answer("y\n")
        self.assertEqual(proc.communicate(timeout=10)[0], b"next\n")
        self.assertFalse(marker.exists())

    def test_questions_come_one_at_a_time(self):
        tty = self.daemon(approve="session")
        first = self.rig.popen("echo a", session="alpha")
        second = self.rig.popen("echo b", session="beta")
        tty.expect("wants to run commands here")
        self.assertNotIn("wants to run commands here", tty.read(0.5))
        tty.answer("y\n")
        tty.expect("wants to run commands here")
        tty.answer("n\n")
        codes = sorted((first.wait(10), second.wait(10)))
        self.assertEqual(codes, [0, lh_core.EXIT_REFUSED])
        first.stdout.close()
        second.stdout.close()

    # ---- --approve every ---------------------------------------------------------------

    def test_every_asks_each_time_and_can_show_the_script(self):
        tty = self.daemon(approve="every")
        proc = self.rig.popen("echo hidden-part\necho shown", session="alpha", display="echo shown")
        tty.expect("? echo shown")
        tty.expect("[v] view script")
        tty.answer("v\n")
        tty.expect("| echo hidden-part")
        tty.answer("y\n")
        self.assertEqual(proc.communicate(timeout=10)[0], b"hidden-part\nshown\n")
        proc = self.rig.popen("echo again", session="alpha", display="echo again")
        tty.expect("? echo again")
        tty.answer("s\n")
        self.assertEqual(proc.communicate(timeout=10)[0], b"again\n")
        self.assertEqual(self.rig.run("echo free", session="alpha", timeout=10), (0, b"free\n"))

    def test_hostile_display_text_cannot_rewrite_the_prompt(self):
        tty = self.daemon(approve="every")
        proc = self.rig.popen("echo x", session="alpha", display="ls\x1b[2K\x1b[1A\rharmless")
        tty.expect("[y] run")
        self.assertNotIn("\x1b[2K", tty.seen + tty.read(0.2))
        tty.answer("n\n")
        proc.communicate(timeout=10)

    # ---- no terminal --------------------------------------------------------------------

    def test_without_a_terminal_everything_is_refused_at_once(self):
        self.rig.join("mac", approve="session")
        marker = self.rig.tmp / "must-not-exist"
        started = time.time()
        code, out = self.rig.run("touch %s" % marker, timeout=10)
        self.assertEqual(code, lh_core.EXIT_REFUSED)
        self.assertIn(b"has no terminal to ask its user on", out)
        self.assertLess(time.time() - started, 5)
        self.assertFalse(marker.exists())
        self.assertIn("no terminal attached", self.rig.daemon_log("mac"))


if __name__ == "__main__":
    unittest.main()
