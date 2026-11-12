#!/usr/bin/env python3
"""Runs build/itest against a broker started for the run (stdlib only).

  python3 tools/peer.py --kind paho --version 3.1.1 [--group basic|limits|sessions|restart|all]

Every group gets its own broker with the limits that group needs. The group `restart` stops the broker and starts it
again between two parts of a scenario. The broker command comes from the kind or from the environment: MQTT_PEER_CMD (a
command line with {config} and {port}) and MQTT_PEER_PORT (a fixed port; default: a free one).
The broker is stopped at the end, on Ctrl-C, on SIGTERM and on a timeout. A broker that is not installed gives one line
`SKIP <kind> broker not available: ...` and exit code 0 (nothing ran). Exit code otherwise: 0 when no scenario failed, 1 otherwise.
"""
import argparse, os, shlex, shutil, signal, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAHO_DIR = os.path.join(ROOT, ".work", "peer", "paho", "interoperability")
POSIX = os.name != "nt"

# limits of each group, as the broker has to announce them
GROUPS = {
    "basic": {"receive_maximum": 20, "maximum_packet_size": 1000000, "topic_alias_maximum": 5},
    "sessions": {"receive_maximum": 20, "maximum_packet_size": 1000000, "topic_alias_maximum": 5},
    "limits": {"receive_maximum": 2, "maximum_packet_size": 200, "topic_alias_maximum": 5,
               "maximum_qos": 1, "retain_available": "false"},
    "restart": {"receive_maximum": 20, "maximum_packet_size": 1000000, "topic_alias_maximum": 5},
}


class Unavailable(Exception):
    pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def paho_config(port, limits, tmp, persistent):
    lines = ["%s %s" % (k, v) for k, v in limits.items()]
    lines.append("listener %d" % port)       # listeners last: the options above apply to all of them
    return "\n".join(lines) + "\n"


# mosquitto 2.x names for the same limits; untested until a mosquitto is installed (CI installs it)
MOSQUITTO_NAMES = {"receive_maximum": "max_inflight_messages", "maximum_packet_size": "max_packet_size",
                   "topic_alias_maximum": "max_topic_alias", "maximum_qos": "max_qos", "retain_available": "retain_available"}


def mosquitto_config(port, limits, tmp, persistent):
    lines = ["listener %d 127.0.0.1" % port, "allow_anonymous true"]
    if persistent:
        lines += ["persistence true", "persistence_location %s/" % tmp, "autosave_interval 1"]
    else:
        lines.append("persistence false")
    lines += ["%s %s" % (MOSQUITTO_NAMES[k], v) for k, v in limits.items()]
    return "\n".join(lines) + "\n"


def broker_command(kind, config_path, port):
    env_cmd = os.environ.get("MQTT_PEER_CMD")
    if env_cmd:
        cmd = shlex.split(env_cmd.format(config=config_path, port=port))
        if shutil.which(cmd[0]) is None:
            raise Unavailable("%s is not on the PATH" % cmd[0])
        return cmd, None
    if kind == "paho":
        if not os.path.exists(os.path.join(PAHO_DIR, "startbroker.py")):
            raise Unavailable("the Paho interoperability broker is not checked out at %s "
                              "(clone eclipse/paho.mqtt.testing there, or set MQTT_PEER_CMD)" % PAHO_DIR)
        return [sys.executable, "startbroker.py", "-c", config_path], PAHO_DIR
    if kind == "mosquitto":
        if shutil.which("mosquitto") is None:
            raise Unavailable("mosquitto is not on the PATH")
        return ["mosquitto", "-c", config_path], None
    raise Unavailable("no broker command for kind %r (set MQTT_PEER_CMD)" % kind)


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_for_port(port, proc, seconds=15):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            return False
        if port_open(port):
            time.sleep(0.2)
            return proc.poll() is None          # a listener of someone else must not be taken for ours
        time.sleep(0.1)
    return False


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        if POSIX:
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            if POSIX:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass


class Broker:
    def __init__(self, args, group, tmp):
        self.port = int(os.environ.get("MQTT_PEER_PORT") or free_port())
        self.args, self.group, self.tmp = args, group, tmp
        self.config = os.path.join(tmp, "broker.conf")
        write = mosquitto_config if args.kind == "mosquitto" else paho_config
        with open(self.config, "w") as f:
            f.write(write(self.port, GROUPS[group], tmp, group == "restart"))
        self.cmd, self.cwd = broker_command(args.kind, self.config, self.port)
        self.proc = None
        self.log = open(os.path.join(tmp, "broker.log"), "a")

    def start(self):
        if port_open(self.port):
            print("FAIL %s-broker port %d is already in use" % (self.group, self.port))
            return False
        kw = {"start_new_session": True} if POSIX else {}
        try:
            self.proc = subprocess.Popen(self.cmd, cwd=self.cwd, stdout=self.log, stderr=subprocess.STDOUT, **kw)
        except OSError as e:
            print("FAIL %s-broker cannot start %s: %s" % (self.group, self.cmd[0], e))
            return False
        if not wait_for_port(self.port, self.proc):
            print("FAIL %s-broker the broker did not start; its log:" % self.group)
            self.log.flush()
            print(open(os.path.join(self.tmp, "broker.log")).read())
            return False
        return True

    def stop(self):
        stop(self.proc)
        self.proc = None

    def close(self):
        self.stop()
        self.log.close()


CHILDREN = []


def run_itest(args, broker, *extra):
    env = dict(os.environ, MQTT_PEER="127.0.0.1:%d" % broker.port, MQTT_PEER_KIND=args.kind,
               MQTT_PEER_RUN=str(os.getpid()))
    cmd = [os.path.join(ROOT, "build", "itest"), "--version", args.version] + list(extra)
    kw = {"start_new_session": True} if POSIX else {}
    p = subprocess.Popen(cmd, env=env, cwd=ROOT, **kw)
    CHILDREN.append(p)
    try:
        return p.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        stop(p)
        print("FAIL %s-timeout the scenarios took longer than %d s" % (args.group_now, args.timeout))
        return 1
    finally:
        CHILDREN.remove(p)


def run_group(args, group):
    args.group_now = group
    with tempfile.TemporaryDirectory(prefix="mqtt-peer-") as tmp:
        broker = Broker(args, group, tmp)
        try:
            if not broker.start():
                return 1
            if group != "restart":
                return run_itest(args, broker, "--group", group)
            rc = run_itest(args, broker, "--name", "restart_prepare")
            if rc != 0:
                return rc
            broker.stop()
            if not broker.start():
                return 1
            return run_itest(args, broker, "--name", "restart_check")
        finally:
            broker.close()


def on_term(signum, frame):
    for p in list(CHILDREN):
        stop(p)
    raise KeyboardInterrupt()          # unwinds through the finally clauses: the broker is stopped, the temp dir removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", default=os.environ.get("MQTT_PEER_KIND", "paho"))
    ap.add_argument("--version", default="5", choices=["3.1.1", "5"])
    ap.add_argument("--group", default="all", choices=["all"] + list(GROUPS))
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()
    if not os.path.exists(os.path.join(ROOT, "build", "itest")) and not os.path.exists(os.path.join(ROOT, "build", "itest.exe")):
        sys.exit("peer.py: build/itest is missing; run `c3c build itest` first")
    signal.signal(signal.SIGTERM, on_term)
    groups = list(GROUPS) if args.group == "all" else [args.group]
    failed = 0
    try:
        for g in groups:
            failed += run_group(args, g)
    except Unavailable as e:
        print("SKIP %s broker not available: %s" % (args.kind, e))
        return 0
    except KeyboardInterrupt:
        print("interrupted")
        return 130
    print("RESULT %s version %s: %s" % (args.kind, args.version, "no FAIL" if failed == 0 else "%d group(s) with FAIL" % failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
