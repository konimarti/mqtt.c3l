#!/usr/bin/env python3
"""Checks of the peer runner that need no broker: python3 tools/test_peer.py (needs build/itest)."""
import os, signal, subprocess, sys, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PEER = [sys.executable, os.path.join(ROOT, "tools", "peer.py")]
ITEST = os.path.join(ROOT, "build", "itest")
PAHO = os.path.join(ROOT, ".work", "peer", "paho", "interoperability", "startbroker.py")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


@unittest.skipUnless(os.path.exists(ITEST), "build/itest is missing")
class PeerRunner(unittest.TestCase):
    def test_missing_broker_is_a_skip_not_a_failure(self):
        r = run(PEER + ["--kind", "paho", "--version", "5"], env=dict(os.environ, MQTT_PEER_CMD="no-such-broker {config}"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("SKIP paho broker not available", r.stdout)

    def test_itest_without_a_broker_skips_once(self):
        r = run([ITEST, "--group", "basic"], env=dict(os.environ, MQTT_PEER="127.0.0.1:1"))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.count("SKIP"), 1)
        self.assertNotIn("FAIL", r.stdout)

    def test_itest_rejects_what_it_does_not_know(self):
        for args in (["--group", "typo"], ["--version", "4"], ["--name", "nothing"], ["--bogus"]):
            self.assertEqual(run([ITEST] + args).returncode, 99, args)

    @unittest.skipUnless(os.path.exists(PAHO) and os.name != "nt", "needs the Paho broker checkout and POSIX signals")
    def test_sigterm_stops_broker_and_scenarios(self):
        p = subprocess.Popen(PEER + ["--kind", "paho", "--version", "5", "--group", "basic"], stdout=subprocess.DEVNULL)
        time.sleep(4)
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=30)
        time.sleep(1)
        left = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
        self.assertNotIn("startbroker.py -c", left)
        self.assertNotIn("build/itest --version", left)


if __name__ == "__main__":
    unittest.main()
