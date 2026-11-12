#!/usr/bin/env python3
"""Runs build/itest against a broker started for the run (stdlib only).

  python3 tools/peer.py --kind paho --version 3.1.1 [--group basic|limits|sessions|all]

Every group gets its own broker with the limits that group needs. The broker command comes from the kind or from the
environment: MQTT_PEER_CMD (a command line with {config} and {port}) and MQTT_PEER_PORT (a fixed port; default: a free one).
The broker is stopped at the end, on Ctrl-C and on a timeout. Exit code: 0 when no scenario failed, 1 otherwise.
"""
import argparse, os, shlex, signal, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAHO_DIR = os.path.join(ROOT, ".work", "peer", "paho", "interoperability")

# limits of each group, as the broker has to announce them
GROUPS = {
    "basic": {"receive_maximum": 20, "maximum_packet_size": 1000000, "topic_alias_maximum": 5},
    "sessions": {"receive_maximum": 20, "maximum_packet_size": 1000000, "topic_alias_maximum": 5},
    "limits": {"receive_maximum": 2, "maximum_packet_size": 200, "topic_alias_maximum": 5,
               "maximum_qos": 1, "retain_available": "false"},
}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def paho_config(port, limits):
    lines = ["%s %s" % (k, v) for k, v in limits.items()]
    lines.append("listener %d" % port)       # listeners last: the options above apply to all of them
    return "\n".join(lines) + "\n"


# mosquitto 2.x names for the same limits; untested until a mosquitto is installed (CI installs it)
MOSQUITTO_NAMES = {"receive_maximum": "max_inflight_messages", "maximum_packet_size": "max_packet_size",
                   "topic_alias_maximum": "max_topic_alias", "maximum_qos": "max_qos", "retain_available": "retain_available"}


def mosquitto_config(port, limits):
    lines = ["listener %d 127.0.0.1" % port, "allow_anonymous true", "persistence false"]
    lines += ["%s %s" % (MOSQUITTO_NAMES[k], v) for k, v in limits.items()]
    return "\n".join(lines) + "\n"


def broker_command(kind, config_path, port):
    env_cmd = os.environ.get("MQTT_PEER_CMD")
    if env_cmd:
        return shlex.split(env_cmd.format(config=config_path, port=port)), None
    if kind == "paho":
        return [sys.executable, "startbroker.py", "-c", config_path], PAHO_DIR
    if kind == "mosquitto":
        return ["mosquitto", "-c", config_path], None
    sys.exit("peer.py: no broker command for kind %r (set MQTT_PEER_CMD)" % kind)


def wait_for_port(port, proc, seconds=15):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_group(args, group):
    port = int(os.environ.get("MQTT_PEER_PORT") or free_port())
    with tempfile.TemporaryDirectory(prefix="mqtt-peer-") as tmp:
        config_path = os.path.join(tmp, "broker.conf")
        with open(config_path, "w") as f:
            f.write((mosquitto_config if args.kind == "mosquitto" else paho_config)(port, GROUPS[group]))
        cmd, cwd = broker_command(args.kind, config_path, port)
        log = open(os.path.join(tmp, "broker.log"), "w")
        try:
            proc = subprocess.Popen(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as e:
            print("FAIL %s-broker cannot start %s: %s" % (group, cmd[0], e))
            return 1, 0
        try:
            if not wait_for_port(port, proc):
                print("FAIL %s-broker the broker did not start; see below" % group)
                log.flush()
                print(open(os.path.join(tmp, "broker.log")).read())
                return 1, 0
            env = dict(os.environ, MQTT_PEER="127.0.0.1:%d" % port, MQTT_PEER_KIND=args.kind)
            itest = [os.path.join(ROOT, "build", "itest"), "--version", args.version, "--group", group]
            try:
                r = subprocess.run(itest, env=env, timeout=args.timeout, cwd=ROOT)
            except subprocess.TimeoutExpired:
                print("FAIL %s-timeout the scenarios took longer than %d s" % (group, args.timeout))
                return 1, 0
            return r.returncode, 0
        finally:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
            log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", default=os.environ.get("MQTT_PEER_KIND", "paho"))
    ap.add_argument("--version", default="5", choices=["3.1.1", "5"])
    ap.add_argument("--group", default="all", choices=["all"] + list(GROUPS))
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()
    if not os.path.exists(os.path.join(ROOT, "build", "itest")):
        sys.exit("peer.py: build/itest is missing; run `c3c build itest` first")
    groups = list(GROUPS) if args.group == "all" else [args.group]
    failed = 0
    try:
        for g in groups:
            rc, _ = run_group(args, g)
            failed += rc
    except KeyboardInterrupt:
        print("interrupted")
        return 130
    print("RESULT %s version %s: %s" % (args.kind, args.version, "no FAIL" if failed == 0 else "%d group(s) with FAIL" % failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
