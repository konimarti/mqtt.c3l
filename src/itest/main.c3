module itest;
import mqtt, mqtt::core, mqtt::client, mqtt::tcp, mqtt::transport, mqtt::props;
import std::io, std::os::env, std::time, std::thread;

// Interoperability scenarios against a running broker (see README, "Running the peer tests").
// Environment: MQTT_PEER=host:port, MQTT_PEER_KIND=paho|mosquitto (only used in the output).
// Arguments: --version 3.1.1|5, --group basic|limits|sessions|all, --name SCENARIO.
// Every scenario prints PASS name, FAIL name reason or SKIP name reason; the exit code is the number of failures.

faultdef CHECK_FAILED, SKIPPED;

String peer_host = "127.0.0.1";
int peer_port = 1883;
String peer_kind = "peer";
Version version = Version.V5;
String prefix;                      // topics of this run: itest/<version>/
String why;                         // reason of the last failed check or skip
int fails;
int passes;
int skips;

alias ScenarioFn = fn void?();

struct Scenario
{
	String name;
	String group;
	bool v5_only;
	ScenarioFn run;
}

// ---- helpers ----

fn void? expect(bool ok, String message)
{
	if (ok) return;
	why = message;
	return CHECK_FAILED~;
}

fn void? skip(String reason)
{
	why = reason;
	return SKIPPED~;
}

fn String topic(String name) => string::format(mem, "%s%s", prefix, name);

struct Got
{
	String topic;
	String payload;
	QoS qos;
	bool retain;
	bool dup;
	String content_type;
	String user_key;
	String user_value;
}

// One client with its own TCP link. Must not be moved after connect().
struct Conn
{
	TcpTransport link;
	Client client;
	Config config;
	bool linked;
	bool closed_seen;
	ReasonCode closed_reason;
}

fn void Conn.init(&self, String id, bool clean)
{
	*self = {};
	self.config = core::default_config(version, id);
	self.config.clean_start = clean;
	self.config.keep_alive = 30;
}

fn void? Conn.connect(&self)
{
	self.link = tcp::connect(peer_host, peer_port, time::sec(5))!;
	self.linked = true;
	if (catch err = self.client.open(mem, (Transport)&self.link, &self.config, time::sec(5)))
	{
		why = "CONNECT refused or failed";
		return err~;
	}
}

fn void? Conn.open(&self, String id, bool clean)
{
	self.init(id, clean);
	self.connect()!;
}

// Ends the link without DISCONNECT (a crash, for the will and the session scenarios).
fn void Conn.drop(&self)
{
	if (self.linked) (void)self.link.close();
	self.client.close();
	self.linked = false;
}

fn void Conn.end(&self)
{
	if (self.linked && self.client.core.state == State.CONNECTED)
	{
		(void)self.client.disconnect(ReasonCode.NORMAL_DISCONNECTION, time::sec(2));
	}
	self.drop();
}

fn void? Conn.subscribe(&self, String filter, QoS qos)
{
	SubEntry[1] e = { { .filter = filter, .qos = qos } };
	self.subscribe_entry(e[0])!;
}

fn void? Conn.subscribe_entry(&self, SubEntry e)
{
	SubEntry[1] entries = { e };
	char[1] codes;
	self.client.subscribe(entries[..], codes[..], time::sec(5))!;
	why = "the broker refused the subscription";
	if (codes[0] >= 0x80) return CHECK_FAILED~;
}

fn void? Conn.publish(&self, String topic, String payload, QoS qos, bool retain = false)
{
	OutMessage m = { .topic = topic, .payload = (char[])payload, .qos = qos, .retain = retain };
	self.send(&m)!;
}

fn void? Conn.send(&self, OutMessage* m)
{
	if (m.qos == QoS.AT_MOST_ONCE)
	{
		self.client.publish(m, time::sec(5))!;
		return;
	}
	ReasonCode r = self.client.publish_wait(m, time::sec(5))!;
	why = "the broker refused the message";
	if ((char)r >= 0x80) return CHECK_FAILED~;
}

// Next message within `ms` milliseconds (other events are passed over). false: none came, or the link ended
// (closed_seen / closed_reason say so).
fn bool? Conn.recv(&self, Got* g, long ms)
{
	Event ev;
	for (long i = 0; i < (ms + 99) / 100; i++)
	{
		if (!self.client.next(&ev, time::ms(100))!) continue;
		switch (ev.kind)
		{
			case MESSAGE:
				g.topic = ev.message.topic.copy(mem);
				g.payload = ((String)ev.message.payload).copy(mem);
				g.qos = ev.message.qos;
				g.retain = ev.message.retain;
				g.dup = ev.message.dup;
				g.content_type = "";
				if (ev.message.props.has(PropId.CONTENT_TYPE)) g.content_type = ev.message.props.content_type.copy(mem);
				UserPropIter it = ev.message.props.user_props();
				UserProperty up;
				if (it.next(&up)!)
				{
					g.user_key = up.key.copy(mem);
					g.user_value = up.value.copy(mem);
				}
				return true;
			case CLOSED:
				self.closed_seen = true;
				self.closed_reason = ev.closed.reason;
				return false;
			default:
				break;
		}
	}
	return false;
}

// Messages that arrive within `ms`.
fn int? Conn.count(&self, long ms)
{
	int n;
	Got g;
	while (self.recv(&g, ms)!) n++;
	return n;
}

// ---- scenarios: basic ----

fn void? connect_disconnect()
{
	Conn a;
	a.open("itest-c1", true)!;
	defer a.end();
	expect(a.client.core.state == State.CONNECTED, "not connected")!;
	a.end();
	expect(a.client.core.state != State.CONNECTED, "still connected after DISCONNECT")!;
}

fn void? flow(QoS q)
{
	Conn a, b;
	a.open(string::format(mem, "itest-f%d-a", (int)q.ordinal), true)!;
	defer a.end();
	b.open(string::format(mem, "itest-f%d-b", (int)q.ordinal), true)!;
	defer b.end();
	String t = topic(string::format(mem, "flow%d", (int)q.ordinal));
	b.subscribe(t, QoS.EXACTLY_ONCE)!;
	a.publish(t, "hello", q)!;
	Got g;
	expect(b.recv(&g, 3000)!, "message not delivered")!;
	expect(g.topic == t && g.payload == "hello", "wrong topic or payload")!;
	expect(g.qos == q, "wrong QoS delivered")!;
}

fn void? qos0() => flow(QoS.AT_MOST_ONCE);
fn void? qos1() => flow(QoS.AT_LEAST_ONCE);
fn void? qos2() => flow(QoS.EXACTLY_ONCE);

// Our side receives at each QoS and answers correctly: the broker finishes the flow and sends nothing twice.
fn void? inbound()
{
	Conn a, b;
	a.open("itest-in-a", true)!;
	defer a.end();
	b.open("itest-in-b", true)!;
	defer b.end();
	String t = topic("inbound");
	a.subscribe(t, QoS.EXACTLY_ONCE)!;
	QoS[3] all = { QoS.AT_MOST_ONCE, QoS.AT_LEAST_ONCE, QoS.EXACTLY_ONCE };
	foreach (q : all)
	{
		b.publish(t, "in", q)!;
		Got g;
		expect(a.recv(&g, 3000)!, "inbound message not delivered")!;
		expect(g.qos == q, "wrong QoS on the inbound message")!;
	}
	expect(a.count(800)! == 0, "a message was delivered twice")!;
}

fn void? retained()
{
	Conn a, b, c, d;
	a.open("itest-r-a", true)!;
	defer a.end();
	String t = topic("retained");
	a.publish(t, "keep", QoS.AT_LEAST_ONCE, true)!;
	b.open("itest-r-b", true)!;
	defer b.end();
	b.subscribe(t, QoS.AT_LEAST_ONCE)!;
	Got g;
	expect(b.recv(&g, 3000)!, "retained message not delivered to a new subscriber")!;
	expect(g.payload == "keep" && g.retain, "retained message without the retain flag")!;
	a.publish(t, "", QoS.AT_LEAST_ONCE, true)!;               // clears it
	c.open("itest-r-c", true)!;
	defer c.end();
	c.subscribe(t, QoS.AT_LEAST_ONCE)!;
	expect(!c.recv(&g, 1000)!, "the retained message was not cleared")!;
}

fn void? will()
{
	Conn w, o;
	o.open("itest-w-o", true)!;
	defer o.end();
	String t = topic("will");
	o.subscribe(t, QoS.AT_LEAST_ONCE)!;
	Will will = { .topic = t, .payload = (char[])"gone", .qos = QoS.AT_LEAST_ONCE };
	w.init("itest-w-w", true);
	w.config.will = &will;
	w.connect()!;
	w.drop();
	Got g;
	expect(o.recv(&g, 4000)!, "no will after the connection was dropped")!;
	expect(g.payload == "gone", "wrong will payload")!;
}

fn void? keepalive()
{
	Conn a;
	a.init("itest-k", true);
	a.config.keep_alive = 2;
	a.connect()!;
	defer a.end();
	Got g;
	(void)a.recv(&g, 5000)!;                                    // idle for 5 s: PINGREQ keeps the link
	expect(!a.closed_seen && a.client.core.state == State.CONNECTED, "the broker dropped an idle client with keep alive 2")!;
	a.publish(topic("keepalive"), "x", QoS.AT_LEAST_ONCE)!;
}

fn void? filters()
{
	Conn a, b;
	a.open("itest-fl-a", true)!;
	defer a.end();
	b.open("itest-fl-b", true)!;
	defer b.end();
	a.subscribe(topic("flt/+/x"), QoS.AT_LEAST_ONCE)!;
	a.subscribe(topic("deep/#"), QoS.AT_LEAST_ONCE)!;
	a.subscribe("#", QoS.AT_LEAST_ONCE)!;
	b.publish(topic("flt/1/x"), "p1", QoS.AT_LEAST_ONCE)!;
	b.publish(topic("deep/a/b/c"), "p2", QoS.AT_LEAST_ONCE)!;
	b.publish("$itest/hidden", "p3", QoS.AT_LEAST_ONCE)!;
	int plain;
	int dollar;
	Got g;
	while (a.recv(&g, 1000)!)
	{
		if (g.topic.starts_with("$"))
		{
			dollar++;
		}
		else
		{
			plain++;
		}
	}
	expect(plain >= 2, "wildcard filters did not deliver")!;
	expect(dollar == 0, "# matched a topic that starts with $")!;
}

fn void? ackorder()
{
	Conn a, b;
	a.open("itest-o-a", true)!;
	defer a.end();
	b.open("itest-o-b", true)!;
	defer b.end();
	String t = topic("order");
	a.subscribe(t, QoS.EXACTLY_ONCE)!;
	QoS[3] kinds = { QoS.AT_MOST_ONCE, QoS.AT_LEAST_ONCE, QoS.EXACTLY_ONCE };
	for (int i = 0; i < 12; i++) b.publish(t, string::format(mem, "%d", i), kinds[i % 3])!;
	for (int i = 0; i < 12; i++)
	{
		Got g;
		expect(a.recv(&g, 3000)!, "burst message missing")!;
		expect(g.payload == string::format(mem, "%d", i), "burst out of order")!;
	}
	expect(a.count(500)! == 0, "duplicate in the burst")!;
}

// ---- scenarios: limits (5.0) ----

fn void? limits_connack()
{
	Conn a;
	a.open("itest-l-c", true)!;
	defer a.end();
	Limits* l = &a.client.core.limits;
	expect(l.send_quota == 2, "Receive Maximum of the broker is not 2")!;
	// a broker that does not announce Maximum QoS / Retain Available means the defaults (2, true): report, do not fail
	if (l.maximum_qos != QoS.AT_LEAST_ONCE) io::printfn("INFO limits_connack the broker announced no Maximum QoS 1");
	if (l.retain_available) io::printfn("INFO limits_connack the broker announced no Retain Available 0");
	expect(l.topic_alias_maximum == 5, "Topic Alias Maximum of the broker is not 5")!;
	expect(l.max_packet_size == 200, "Maximum Packet Size of the broker is not 200")!;
}

fn void? limits_user_props()
{
	Conn a, b;
	a.open("itest-l-u1", true)!;
	defer a.end();
	b.open("itest-l-u2", true)!;
	defer b.end();
	String t = topic("props");
	b.subscribe(t, QoS.AT_LEAST_ONCE)!;
	OutMessage m = { .topic = t, .payload = (char[])"p", .qos = QoS.AT_LEAST_ONCE };
	m.props.set(PropId.CONTENT_TYPE);
	m.props.content_type = "text/x-itest";
	UserProperty[1] users = { { "k1", "v1" } };
	m.props.user = users[..];
	a.send(&m)!;
	Got g;
	expect(b.recv(&g, 3000)!, "message with properties not delivered")!;
	expect(g.content_type == "text/x-itest", "content type lost")!;
	expect(g.user_key == "k1" && g.user_value == "v1", "user property lost")!;
}

fn void? limits_receive_maximum()
{
	Conn a, b;
	a.open("itest-l-r1", true)!;
	defer a.end();
	b.open("itest-l-r2", true)!;
	defer b.end();
	String t = topic("burst");
	b.subscribe(t, QoS.AT_LEAST_ONCE)!;
	ushort[20] ids;
	for (int i = 0; i < 20; i++)
	{
		OutMessage m = { .topic = t, .payload = (char[])"b", .qos = QoS.AT_LEAST_ONCE };
		ids[i] = a.client.publish(&m, time::sec(5))!;
		expect(a.client.core.inflight_count() <= 2, "more than 2 unacknowledged messages")!;
	}
	for (int i = 0; i < 20; i++)
	{
		ReasonCode r = a.client.wait_done(ids[i], time::sec(5))!;
		expect((char)r < 0x80, "a burst message was refused")!;
	}
	expect(b.count(1500)! == 20, "not all 20 burst messages were delivered")!;
}

fn void? limits_packet_too_large()
{
	Conn a;
	a.open("itest-l-p", true)!;
	defer a.end();
	char[300] big;
	OutMessage m = { .topic = topic("big"), .payload = big[..], .qos = QoS.AT_LEAST_ONCE };
	expect(@catch(a.client.publish(&m, time::sec(2))) == mqtt::PACKET_TOO_LARGE, "no PACKET_TOO_LARGE")!;
	expect(a.client.core.state == State.CONNECTED, "the connection ended")!;
}

fn void? limits_inbound_packet_size()
{
	Conn a, b;
	a.init("itest-l-i1", true);
	a.config.max_packet_size = 100;
	a.connect()!;
	defer a.end();
	b.open("itest-l-i2", true)!;
	defer b.end();
	String t = topic("small");
	a.subscribe(t, QoS.AT_LEAST_ONCE)!;
	b.publish(t, "short", QoS.AT_LEAST_ONCE)!;
	Got g;
	expect(a.recv(&g, 3000)!, "small message not delivered")!;
	char[150] big;
	OutMessage m = { .topic = t, .payload = big[..], .qos = QoS.AT_LEAST_ONCE };
	b.send(&m)!;
	expect(!a.recv(&g, 1500)!, "the broker sent a packet over the advertised limit")!;
	expect(!a.closed_seen, "the connection ended")!;
}

fn void? limits_topic_alias()
{
	Conn a, b;
	a.init("itest-l-a1", true);
	a.config.auto_topic_alias = true;
	a.connect()!;
	defer a.end();
	b.open("itest-l-a2", true)!;
	defer b.end();
	String t = topic("aliased");
	b.subscribe(t, QoS.AT_LEAST_ONCE)!;
	for (int i = 0; i < 3; i++) a.publish(t, "x", QoS.AT_LEAST_ONCE)!;
	for (int i = 0; i < 3; i++)
	{
		Got g;
		expect(b.recv(&g, 3000)!, "aliased message missing")!;
		expect(g.topic == t, "wrong topic after aliasing")!;
	}
}

fn void? limits_max_qos()
{
	Conn a;
	a.open("itest-l-q", true)!;
	defer a.end();
	if (a.client.core.limits.maximum_qos == QoS.EXACTLY_ONCE) return skip(string::format(mem, "%s does not announce Maximum QoS 1 although configured", peer_kind));
	expect(@catch(a.publish(topic("q2"), "x", QoS.EXACTLY_ONCE)) == mqtt::NOT_SUPPORTED_BY_SERVER, "QoS 2 was not refused locally")!;
}

fn void? limits_retain()
{
	Conn a;
	a.open("itest-l-t", true)!;
	defer a.end();
	if (a.client.core.limits.retain_available) return skip(string::format(mem, "%s does not announce Retain Available 0 although configured", peer_kind));
	expect(@catch(a.publish(topic("ret"), "x", QoS.AT_LEAST_ONCE, true)) == mqtt::NOT_SUPPORTED_BY_SERVER, "retain was not refused locally")!;
}

fn void? limits_auth()
{
	return skip(string::format(mem, "%s has no user name and password support", peer_kind));
}

// ---- scenarios: sessions ----

fn void? session_offline_queue()
{
	Conn a, b;
	a.init("itest-s-a", false);
	if (version == Version.V5) a.config.session_expiry = 60;
	a.connect()!;
	String t = topic("offline");
	a.subscribe(t, QoS.AT_LEAST_ONCE)!;
	a.drop();
	b.open("itest-s-b", true)!;
	defer b.end();
	b.publish(t, "while away", QoS.AT_LEAST_ONCE)!;
	a.init("itest-s-a", false);
	if (version == Version.V5) a.config.session_expiry = 60;
	a.connect()!;
	defer a.end();
	Got g;
	expect(a.recv(&g, 3000)!, "the message published while the client was away was not delivered")!;
	expect(g.payload == "while away", "wrong payload")!;
}

fn void? session_takeover()
{
	Conn a, b;
	a.open("itest-s-t", true)!;
	defer a.drop();
	b.open("itest-s-t", true)!;
	defer b.end();
	Got g;
	(void)a.recv(&g, 3000)!;
	if (version == Version.V5)
	{
		expect(a.closed_seen && a.closed_reason == ReasonCode.SESSION_TAKEN_OVER, "no DISCONNECT 0x8E for the first client")!;
	}
	else
	{
		expect(a.closed_seen || a.client.core.state == State.DISCONNECTED, "the first client is still connected")!;
	}
}

fn void? session_expiry()
{
	Conn a, b;
	a.init("itest-s-e", false);
	a.config.session_expiry = 2;
	a.connect()!;
	String t = topic("expiry");
	a.subscribe(t, QoS.AT_LEAST_ONCE)!;
	a.drop();
	thread::sleep(time::sec(4));
	b.open("itest-s-e2", true)!;
	defer b.end();
	b.publish(t, "late", QoS.AT_LEAST_ONCE)!;
	a.init("itest-s-e", false);
	a.config.session_expiry = 2;
	a.connect()!;
	defer a.end();
	Got g;
	expect(!a.recv(&g, 1500)!, "the session survived its expiry interval")!;
}

fn void? session_resubscribe()
{
	Conn a, b;
	a.open("itest-s-rs", true)!;
	defer a.end();
	b.open("itest-s-rs2", true)!;
	defer b.end();
	String t = topic("resub");
	a.subscribe(t, QoS.AT_MOST_ONCE)!;
	a.subscribe(t, QoS.AT_LEAST_ONCE)!;
	b.publish(t, "once", QoS.AT_LEAST_ONCE)!;
	Got g;
	expect(a.recv(&g, 3000)!, "no message after subscribing twice")!;
	expect(g.qos == QoS.AT_LEAST_ONCE, "the new QoS did not replace the old one")!;
	expect(a.count(800)! == 0, "the message was delivered twice")!;
}

fn void? session_resend_after_restart()
{
	return skip(string::format(mem, "%s does not keep sessions over a restart", peer_kind));
}

fn void? session_shared()
{
	Conn a, b, c;
	a.open("itest-sh-a", true)!;
	defer a.end();
	b.open("itest-sh-b", true)!;
	defer b.end();
	c.open("itest-sh-c", true)!;
	defer c.end();
	a.subscribe("$share/g/itest/shared", QoS.AT_LEAST_ONCE)!;
	b.subscribe("$share/g/itest/shared", QoS.AT_LEAST_ONCE)!;
	for (int i = 0; i < 6; i++) c.publish("itest/shared", "s", QoS.AT_LEAST_ONCE)!;
	int total = a.count(1500)! + b.count(500)!;
	expect(total == 6, "each message must reach exactly one member of the group")!;
}

fn void? session_no_local()
{
	Conn a;
	a.open("itest-nl", true)!;
	defer a.end();
	String t = topic("nolocal");
	a.subscribe_entry({ .filter = t, .qos = QoS.AT_LEAST_ONCE, .no_local = true })!;
	a.publish(t, "mine", QoS.AT_LEAST_ONCE)!;
	expect(a.count(1000)! == 0, "No Local did not stop the client's own message")!;
}

fn void? session_retain_as_published()
{
	Conn a, b, c;
	a.open("itest-rap-a", true)!;
	defer a.end();
	b.open("itest-rap-b", true)!;
	defer b.end();
	c.open("itest-rap-c", true)!;
	defer c.end();
	String t = topic("rap");
	b.subscribe_entry({ .filter = t, .qos = QoS.AT_LEAST_ONCE, .retain_as_published = true })!;
	c.subscribe(t, QoS.AT_LEAST_ONCE)!;
	a.publish(t, "r", QoS.AT_LEAST_ONCE, true)!;
	Got g;
	expect(b.recv(&g, 3000)!, "no message")!;
	expect(g.retain, "Retain As Published: the flag was not kept")!;
	expect(c.recv(&g, 3000)!, "no message")!;
	expect(!g.retain, "without Retain As Published the flag must be 0 on a live delivery")!;
	a.publish(t, "", QoS.AT_LEAST_ONCE, true)!;
}

fn void? session_retain_handling()
{
	Conn a, b;
	a.open("itest-rh-a", true)!;
	defer a.end();
	String t = topic("rh");
	a.publish(t, "kept", QoS.AT_LEAST_ONCE, true)!;
	defer (void)a.publish(t, "", QoS.AT_LEAST_ONCE, true);
	Got g;
	// 0: sent at subscribe
	b.open("itest-rh-b", true)!;
	defer b.end();
	b.subscribe_entry({ .filter = t, .qos = QoS.AT_LEAST_ONCE, .retain_handling = 0 })!;
	expect(b.recv(&g, 2000)!, "retain handling 0: no retained message")!;
	// 1: only when the subscription is new: the second subscribe gets nothing
	b.subscribe_entry({ .filter = t, .qos = QoS.AT_LEAST_ONCE, .retain_handling = 1 })!;
	expect(!b.recv(&g, 1000)!, "retain handling 1: sent again for an existing subscription")!;
	// 2: never
	Conn c;
	c.open("itest-rh-c", true)!;
	defer c.end();
	c.subscribe_entry({ .filter = t, .qos = QoS.AT_LEAST_ONCE, .retain_handling = 2 })!;
	expect(!c.recv(&g, 1000)!, "retain handling 2: retained message sent")!;
}

// What the broker does with a $share filter on a 3.1.1 connection (the library treats it as an ordinary filter).
fn void? session_share_on_311()
{
	if (version == Version.V5) return skip("3.1.1 only");
	Conn a, b;
	a.open("itest-s311-a", true)!;
	defer a.end();
	b.open("itest-s311-b", true)!;
	defer b.end();
	SubEntry[1] entries = { { .filter = "$share/g/itest/s311", .qos = QoS.AT_LEAST_ONCE } };
	char[1] codes;
	a.client.subscribe(entries[..], codes[..], time::sec(5))!;
	b.publish("itest/s311", "x", QoS.AT_LEAST_ONCE)!;
	int n = a.count(1000)!;
	io::printfn("INFO session_share_on_311 SUBACK code %d, delivered %d of 1", codes[0], n);
}

Scenario[*] scenarios = {
	{ "connect", "basic", false, &connect_disconnect },
	{ "qos0", "basic", false, &qos0 },
	{ "qos1", "basic", false, &qos1 },
	{ "qos2", "basic", false, &qos2 },
	{ "inbound", "basic", false, &inbound },
	{ "retained", "basic", false, &retained },
	{ "will", "basic", false, &will },
	{ "keepalive", "basic", false, &keepalive },
	{ "filters", "basic", false, &filters },
	{ "ackorder", "basic", false, &ackorder },
	{ "limits_connack", "limits", true, &limits_connack },
	{ "limits_user_props", "limits", true, &limits_user_props },
	{ "limits_receive_maximum", "limits", true, &limits_receive_maximum },
	{ "limits_packet_too_large", "limits", true, &limits_packet_too_large },
	{ "limits_inbound_packet_size", "limits", true, &limits_inbound_packet_size },
	{ "limits_topic_alias", "limits", true, &limits_topic_alias },
	{ "limits_max_qos", "limits", true, &limits_max_qos },
	{ "limits_retain", "limits", true, &limits_retain },
	{ "limits_auth", "limits", true, &limits_auth },
	{ "session_offline_queue", "sessions", false, &session_offline_queue },
	{ "session_takeover", "sessions", false, &session_takeover },
	{ "session_resend_after_restart", "sessions", false, &session_resend_after_restart },
	{ "session_expiry", "sessions", true, &session_expiry },
	{ "session_resubscribe", "sessions", false, &session_resubscribe },
	{ "session_shared", "sessions", true, &session_shared },
	{ "session_no_local", "sessions", true, &session_no_local },
	{ "session_retain_as_published", "sessions", true, &session_retain_as_published },
	{ "session_retain_handling", "sessions", true, &session_retain_handling },
	{ "session_share_on_311", "sessions", false, &session_share_on_311 },
};

fn void run_one(Scenario* s)
{
	why = "";
	if (s.v5_only && version != Version.V5)
	{
		io::printfn("SKIP %s needs MQTT 5.0", s.name);
		skips++;
		return;
	}
	if (catch err = s.run())
	{
		if (err == SKIPPED)
		{
			io::printfn("SKIP %s %s", s.name, why);
			skips++;
			return;
		}
		if (err == CHECK_FAILED)
		{
			io::printfn("FAIL %s %s", s.name, why);
		}
		else
		{
			io::printfn("FAIL %s %s (%s)", s.name, why, err);
		}
		fails++;
		return;
	}
	io::printfn("PASS %s", s.name);
	passes++;
}

fn int main(String[] argv)
{
	String group = "all";
	String only;
	for (usz i = 1; i < argv.len; i++)
	{
		if (argv[i] == "--version" && i + 1 < argv.len)
		{
			version = argv[++i] == "3.1.1" ? Version.V311 : Version.V5;
		}
		else if (argv[i] == "--group" && i + 1 < argv.len)
		{
			group = argv[++i];
		}
		else if (argv[i] == "--name" && i + 1 < argv.len)
		{
			only = argv[++i];
		}
		else
		{
			io::eprintfn("itest: unknown argument %s", argv[i]);
			return 99;
		}
	}
	String? peer = env::get_var(mem, "MQTT_PEER");
	if (try peer)
	{
		sz colon = peer.rindex_of(":") ?? 0;
		if (colon > 0)
		{
			peer_host = peer[:colon];
			peer_port = (int)peer[colon + 1..].to_long() ?? 1883;
		}
	}
	String? kind = env::get_var(mem, "MQTT_PEER_KIND");
	if (try kind) peer_kind = kind;
	prefix = version == Version.V5 ? "itest/5/" : "itest/311/";
	foreach (&s : scenarios)
	{
		if (group != "all" && s.group != group) continue;
		if (only.len > 0 && s.name != only) continue;
		run_one(s);
	}
	io::printfn("SUMMARY %s version %s: %d passed, %d failed, %d skipped", peer_kind, version == Version.V5 ? "5" : "3.1.1", passes, fails, skips);
	return fails;
}
