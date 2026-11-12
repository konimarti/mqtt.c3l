# mqtt.c3l

MQTT 3.1.1 and 5.0 client for C3. One library, the protocol level is chosen when you connect.

- A sans-IO core (`mqtt::core`): packets in, bytes out, time passed in. It does no I/O and never reads a clock.
- A blocking client on top (`mqtt::client`) over a `Transport` (`read` and `write` with a timeout, `close`), with a TCP transport (`mqtt::tcp`).
- The codec (`mqtt::packet`, `mqtt::props`, `mqtt::wire`), topic validation and matching (`mqtt::topic`).

## Client

```c3
import mqtt, mqtt::client, mqtt::core, mqtt::tcp, mqtt::transport;
import std::io, std::time;

fn int run()
{
	TcpTransport t = tcp::connect("localhost", 1883, time::sec(5))!!;
	defer (void)t.close();
	Config config = core::default_config(Version.V5, "sensor-1");
	Client c;
	defer c.close();
	c.open(mem, (Transport)&t, &config, time::sec(5))!!;

	OutMessage m = { .topic = "plant/line1/temp", .payload = (char[])"21.5", .qos = QoS.AT_LEAST_ONCE };
	ReasonCode r = c.publish_wait(&m, time::sec(5))!!;
	io::printfn("done: %s", r.describe());

	SubEntry[1] entries = { { .filter = "plant/#", .qos = QoS.AT_LEAST_ONCE } };
	char[1] codes;
	c.subscribe(entries[..], codes[..], time::sec(5))!!;
	Event ev;
	while (c.next(&ev, time::sec(30))!!)
	{
		if (ev.kind == EventKind.CLOSED) break;
		if (ev.kind == EventKind.MESSAGE) io::printfn("%s: %s", ev.message.topic, (String)ev.message.payload);
	}
	return 0;
}
```

Every blocking call takes a timeout (a `Duration`); the reads and writes inside it get what is left of it. A write that fails
may have left half a packet on the wire, so the client closes the transport and the call returns `TIMEOUT` or `CLOSED`.
`next` returns `false` when nothing arrived within the timeout (idle); the connection is closed when it returns a `CLOSED` event. `next` also keeps the connection alive: the keep-alive PINGREQ is written while it waits.

### Events borrow the core's buffer

The topic and payload of a `MESSAGE` event (and the other data in an `Event`) point into the core's input buffer. They stay
valid until the next call that reads from the transport. Calls that only write leave them alone: `publish` (QoS 0, or QoS 1/2
while the server's window has room) and `disconnect`. Calls that read end their life: `next`, `subscribe`, `unsubscribe`,
`wait_done`, `publish_wait`, and `publish` when the window is full and it has to wait. Copy what you need to keep first.

The waiting calls take only the answer they wait for. Everything else that arrives meanwhile stays queued for `next`. If the
server floods the client while it waits, the input buffer fills up and the waiting call returns `QUEUE_FULL`: call `next` to
take the events.

### Keep alive

The PINGREQ is written, and a missing PINGRESP noticed, only while a call of the client is running (mostly `next`). Between
calls nothing is serviced: call `next` regularly. A connection that went silent is found out after up to 1.75 times the keep
alive (the PINGREQ goes out after 75 % of it, the reply may take one more keep alive).

### Time

Every blocking call takes a `Duration`. There is no "forever" constant: pass a very large one (`(Duration)long::max` works).
A zero timeout polls once. `Client.reconnect` connects again on a new transport and keeps the session (messages that were not
finished are sent again); `open` starts a new one.

## Notes

- Subscriptions are not tracked: after a session was lost (`session_present` is false) subscribe again.
- Messages of QoS 1 and 2 that were not finished are kept across reconnects and sent again (5.0: while the session lives);
  without a stored session they are reported with `PUBLISH_DONE` and an error reason.
- Large retained messages need a bigger `max_packet_size` in the `Config` (default 256 KiB).

## mqttc

A small command line client over the library (`c3c build mqttc`, binary in `build/`).

```sh
build/mqttc pub -h localhost -t plant/line1/temp -m 21.5 -q 1
build/mqttc sub -h localhost -t 'plant/#' -q 1 -c 10
```

`--v311` selects MQTT 3.1.1 (5.0 is the default), `--follow-redirect` follows a server redirect (at most 3 hops), `-v` reports
progress on stderr. The client id is `mqttc-<random>` unless `-i` is given. The password is read from `--password-file FILE`
or the environment variable `MQTT_PASSWORD`; `-P` works but warns, because the command line is visible to other users. It is
never printed. A retained message with an empty payload deletes the retained message and is refused unless
`--allow-clear-retained` is given. `build/mqttc` without arguments prints the usage.
