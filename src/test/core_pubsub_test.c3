module mqtt::core_pubsub_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::props, mqtt::testutil, std::time;

const String CONNACK_311 = "20 02 00 00";
const String CONNACK_5 = "20 03 00 00 00";

fn Config cfg(Version v)
{
	Config c = core::default_config(v, "a");
	return c;
}

fn OutMessage msg(String topic, String payload_hex, bool retain = false)
{
	return { .topic = topic, .payload = testutil::hex(payload_hex), .retain = retain };
}

// ---- publishing at QoS 0 ----

fn void qos0_publish_bytes() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	OutMessage m = msg("a/b", "68 69");
	assert(s.core.publish(s.clock.now, &m)!! == 0, "QoS 0 has no packet id");
	harness::expect_out(&s.core, "30 07 00 03 61 2F 62 68 69");
	OutMessage r = msg("a/b", "", true);
	s.core.publish(s.clock.now, &r)!!;
	harness::expect_out(&s.core, "31 05 00 03 61 2F 62");
	s.close();

	Session t;
	Config d = cfg(Version.V5);
	t.open(&d, CONNACK_5);
	OutMessage m5 = msg("a/b", "68 69");
	t.core.publish(t.clock.now, &m5)!!;
	harness::expect_out(&t.core, "30 08 00 03 61 2F 62 00 68 69");
	// 5.0 properties travel with the message
	OutMessage p5 = msg("a/b", "68 69");
	p5.props.set(PropId.CONTENT_TYPE);
	p5.props.content_type = "a";
	t.core.publish(t.clock.now, &p5)!!;
	harness::expect_out(&t.core, "30 0C 00 03 61 2F 62 04 03 00 01 61 68 69");
	t.close();
}

// ---- subscribe and unsubscribe ----

fn void subscribe_unsubscribe_bytes() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	SubEntry[2] entries = { { .filter = "a/b", .qos = QoS.AT_MOST_ONCE }, { .filter = "c/+", .qos = QoS.EXACTLY_ONCE } };
	assert(s.core.subscribe(s.clock.now, entries[..], null)!! == 1, "the first packet id is 1");
	harness::expect_out(&s.core, "82 0E 00 01 00 03 61 2F 62 00 00 03 63 2F 2B 02");
	harness::feed(&s.core, &s.clock, "90 04 00 01 00 80");
	Event ev = s.take();
	assert(ev.kind == EventKind.SUBSCRIBED && ev.suback.packet_id == 1 && ev.suback.codes == testutil::hex("00 80"));
	String[1] filters = { "a/#" };
	assert(s.core.unsubscribe(s.clock.now, filters[..], null)!! == 2);
	harness::expect_out(&s.core, "A2 07 00 02 00 03 61 2F 23");
	harness::feed(&s.core, &s.clock, "B0 02 00 02");
	ev = s.take();
	assert(ev.kind == EventKind.UNSUBSCRIBED && ev.suback.packet_id == 2 && ev.suback.codes.len == 0);
	s.close();

	Session t;
	Config d = cfg(Version.V5);
	t.open(&d, CONNACK_5);
	SubEntry[1] one = { { .filter = "a/#", .qos = QoS.AT_LEAST_ONCE } };
	t.core.subscribe(t.clock.now, one[..], null)!!;
	harness::expect_out(&t.core, "82 09 00 01 00 00 03 61 2F 23 01");
	harness::feed(&t.core, &t.clock, "90 04 00 01 00 01");
	ev = t.take();
	assert(ev.kind == EventKind.SUBSCRIBED && ev.suback.codes == testutil::hex("01"));
	t.core.unsubscribe(t.clock.now, filters[..], null)!!;
	harness::expect_out(&t.core, "A2 08 00 02 00 00 03 61 2F 23");
	harness::feed(&t.core, &t.clock, "B0 04 00 02 00 00");
	ev = t.take();
	assert(ev.kind == EventKind.UNSUBSCRIBED && ev.suback.codes == testutil::hex("00"));
	t.close();
}

fn void suback_count_mismatch() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	SubEntry[2] entries = { { .filter = "a" }, { .filter = "b" } };
	s.core.subscribe(s.clock.now, entries[..], null)!!;
	s.core.output_done(s.core.pending_output().len);
	char[] frame = testutil::hex("90 04 00 01 00 00");          // one code for two filters
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&s.core, "E0 01 82");
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::PROTOCOL_ERROR);
	s.close();
}

fn void suback_for_an_unknown_id_is_ignored() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "90 03 00 09 01");
	assert(harness::drain(&s.core).len == 0);
	assert(s.core.state == State.CONNECTED);
	s.close();
}

// ---- inbound messages ----

fn void inbound_qos0() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "31 07 00 03 61 2F 62 68 69");
	harness::expect_no_out(&s.core);
	Event ev = s.take();
	MessageInfo* m = &ev.message;
	assert(ev.kind == EventKind.MESSAGE && m.topic == "a/b" && m.payload == testutil::hex("68 69"));
	assert(m.qos == QoS.AT_MOST_ONCE && m.retain && !m.dup && m.packet_id == 0);
	s.close();
}

fn void inbound_qos1_ack_in_input() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	// the acknowledgement is queued by input(), the application has not polled anything
	harness::feed(&s.core, &s.clock, "32 09 00 03 61 2F 62 00 0A 68 69");
	harness::expect_out(&s.core, "40 02 00 0A");
	Event ev = s.take();
	MessageInfo* m = &ev.message;
	assert(m.qos == QoS.AT_LEAST_ONCE && m.packet_id == 10 && m.topic == "a/b" && !m.retain);
	// a re-delivery (DUP) is delivered again and acknowledged again
	harness::feed(&s.core, &s.clock, "3A 09 00 03 61 2F 62 00 0A 68 69");
	harness::expect_out(&s.core, "40 02 00 0A");
	ev = s.take();
	assert(ev.message.dup && ev.message.packet_id == 10);
	s.close();

	Session t;
	Config d = cfg(Version.V5);
	t.open(&d, CONNACK_5);
	harness::feed(&t.core, &t.clock, "32 07 00 01 61 00 01 00 78");
	harness::expect_out(&t.core, "40 02 00 01");
	ev = t.take();
	assert(ev.message.topic == "a" && ev.message.payload == testutil::hex("78"));
	t.close();
}

fn void ack_order_qos2_qos1_qos0() @test
{
	// all three frames in one input() call, nothing polled in between: PUBREC, then PUBACK, nothing for QoS 0
	{
		Session s;
		Config c = cfg(Version.V311);
		s.open(&c, CONNACK_311);
		harness::feed(&s.core, &s.clock, "34 06 00 01 61 00 07 78 32 09 00 03 61 2F 62 00 0A 68 69 30 07 00 03 61 2F 62 68 69");
		harness::expect_out(&s.core, "50 02 00 07 40 02 00 0A");
		EventKind[] kinds = harness::drain(&s.core);
		assert(kinds.len == 3 && kinds[0] == EventKind.MESSAGE && kinds[1] == EventKind.MESSAGE && kinds[2] == EventKind.MESSAGE);
		s.close();
	}
	// the other order, and the same bytes one at a time
	{
		Session s;
		Config c = cfg(Version.V311);
		s.open(&c, CONNACK_311);
		harness::feed(&s.core, &s.clock, "32 09 00 03 61 2F 62 00 0A 68 69 34 06 00 01 61 00 07 78", 1);
		harness::expect_out(&s.core, "40 02 00 0A 50 02 00 07");
		s.close();
	}
	// frames arriving in separate calls keep their order as well, whether or not events are taken
	{
		Session s;
		Config c = cfg(Version.V5);
		s.open(&c, CONNACK_5);
		harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 07 00 78");
		harness::feed(&s.core, &s.clock, "32 0A 00 03 61 2F 62 00 0A 00 68 69");
		s.take();
		harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 08 00 78");
		harness::expect_out(&s.core, "50 02 00 07 40 02 00 0A 50 02 00 08");
		s.close();
	}
}

fn void inbound_qos2_duplicate_is_delivered_once() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "34 06 00 01 61 00 07 78");
	harness::feed(&s.core, &s.clock, "3C 06 00 01 61 00 07 78");
	harness::expect_out(&s.core, "50 02 00 07 50 02 00 07");
	assert(harness::drain(&s.core).len == 1, "one delivery for the repeated PUBLISH");
	s.close();
}

fn void inbound_publish_with_alias_is_refused() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	char[] frame = testutil::hex("32 09 00 00 00 01 03 23 00 01 78");     // empty topic, Topic Alias 1: none was agreed
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&s.core, "E0 01 82");
	s.close();
}

fn void event_valid_after_second_input() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "30 07 00 03 61 2F 62 68 69");
	harness::feed(&s.core, &s.clock, "30 07 00 03 63 2F 64 6A 6B");          // a second packet before the first was taken
	Event first = s.take();
	assert(first.message.topic == "a/b" && first.message.payload == testutil::hex("68 69"));
	// a third input while an event is still undelivered does not disturb the one in hand
	harness::feed(&s.core, &s.clock, "30 07 00 03 65 2F 66 6C 6D");
	assert(first.message.topic == "a/b" && first.message.payload == testutil::hex("68 69"), "data is still intact");
	Event second = s.take();
	assert(second.message.topic == "c/d" && second.message.payload == testutil::hex("6A 6B"));
	Event third = s.take();
	assert(third.message.topic == "e/f");
	s.close();
}

// ---- closing, ids ----

fn void pending_ack_cleared_on_close() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	SubEntry[1] entries = { { .filter = "a" } };
	assert(s.core.subscribe(s.clock.now, entries[..], null)!! == 1);
	s.core.transport_closed(s.clock.now);
	harness::drain(&s.core);
	// a new connection does not repeat the SUBSCRIBE and ignores a late reply for it
	s.core.connect(s.clock.now)!!;
	harness::expect_out(&s.core, "10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61");
	harness::feed(&s.core, &s.clock, CONNACK_311);
	harness::drain(&s.core);
	harness::feed(&s.core, &s.clock, "90 03 00 01 00");
	assert(harness::drain(&s.core).len == 0, "no event for a request of the old connection");
	assert(s.core.pending_output().len == 0);
	s.close();
}

fn void id_wrap_never_zero() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	SubEntry[1] entries = { { .filter = "t" } };
	// id 1 stays unanswered the whole time and must never be handed out again
	assert(s.core.subscribe(s.clock.now, entries[..], null)!! == 1);
	int wrapped;
	ushort previous = 1;
	for (int i = 0; i < 70_000; i++)
	{
		ushort id = s.core.subscribe(s.clock.now, entries[..], null)!!;
		assert(id != 0 && id != 1, "never 0, never an id that is still pending");
		if (id < previous) wrapped++;
		previous = id;
		s.core.output_done(s.core.pending_output().len);
		char[5] reply = { 0x90, 0x03, (char)(id >> 8), (char)(id & 0xFF), 0x00 };
		s.core.input(s.clock.now, reply[..])!!;
		Event ev;
		assert(s.core.poll_event(&ev) && ev.kind == EventKind.SUBSCRIBED && ev.suback.packet_id == id);
	}
	assert(wrapped == 1, "the counter went round once");
	s.close();
}

// ---- refusals ----

fn void refusals_not_connected() @test
{
	Core core;
	Config c = cfg(Version.V311);
	core.init(mem, &c)!!;
	defer core.free();
	OutMessage m = msg("a", "");
	SubEntry[1] entries = { { .filter = "a" } };
	String[1] filters = { "a" };
	Duration t;
	assert(@catch(core.publish(t, &m)) == mqtt::NOT_CONNECTED);
	assert(@catch(core.subscribe(t, entries[..], null)) == mqtt::NOT_CONNECTED);
	assert(@catch(core.unsubscribe(t, filters[..], null)) == mqtt::NOT_CONNECTED);
}

fn void refusals_invalid_arguments() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	Duration t = s.clock.now;
	OutMessage bad = msg("a/+", "");
	assert(@catch(s.core.publish(t, &bad)) == mqtt::INVALID_TOPIC_NAME);
	OutMessage empty = msg("", "");
	assert(@catch(s.core.publish(t, &empty)) == mqtt::INVALID_TOPIC_NAME);
	SubEntry[1] entries = { { .filter = "a/#/b" } };
	assert(@catch(s.core.subscribe(t, entries[..], null)) == mqtt::INVALID_TOPIC_FILTER);
	SubEntry[] none = {};
	assert(@catch(s.core.subscribe(t, none, null)) == mqtt::INVALID_ARGUMENT);
	String[] no_filters = {};
	assert(@catch(s.core.unsubscribe(t, no_filters, null)) == mqtt::INVALID_ARGUMENT);
	String[1] bad_filter = { "#a" };
	assert(@catch(s.core.unsubscribe(t, bad_filter[..], null)) == mqtt::INVALID_TOPIC_FILTER);
	SubEntry[1] nl = { { .filter = "$share/g/t", .no_local = true } };
	assert(@catch(s.core.subscribe(t, nl[..], null)) == mqtt::INVALID_ARGUMENT, "No Local on a shared subscription");
	assert(s.core.pending_output().len == 0, "a refused request queues nothing");
	// a topic alias is not agreed with the server
	OutMessage al = msg("a", "");
	al.props.set(PropId.TOPIC_ALIAS);
	al.props.topic_alias = 1;
	assert(@catch(s.core.publish(t, &al)) == mqtt::NOT_SUPPORTED_BY_SERVER);
	s.close();
}

fn void refusals_v5_limits() @test
{
	Session s;
	Config c = cfg(Version.V5);
	// the server: Maximum QoS 1, no retain, no wildcards, no subscription identifiers, no shared subscriptions
	s.open(&c, "20 0D 00 00 0A 24 01 25 00 28 00 29 00 2A 00");
	Duration t = s.clock.now;
	OutMessage q2 = msg("a", "");
	q2.qos = QoS.EXACTLY_ONCE;
	assert(@catch(s.core.publish(t, &q2)) == mqtt::NOT_SUPPORTED_BY_SERVER, "QoS above the server's maximum");
	OutMessage rt = msg("a", "", true);
	assert(@catch(s.core.publish(t, &rt)) == mqtt::NOT_SUPPORTED_BY_SERVER, "retain not available");
	SubEntry[1] wild = { { .filter = "a/#" } };
	assert(@catch(s.core.subscribe(t, wild[..], null)) == mqtt::NOT_SUPPORTED_BY_SERVER);
	SubEntry[1] plus = { { .filter = "a/+" } };
	assert(@catch(s.core.subscribe(t, plus[..], null)) == mqtt::NOT_SUPPORTED_BY_SERVER);
	SubEntry[1] shared = { { .filter = "$share/g/a" } };
	assert(@catch(s.core.subscribe(t, shared[..], null)) == mqtt::NOT_SUPPORTED_BY_SERVER);
	SubEntry[1] plain = { { .filter = "a/b" } };
	uint[1] ids = { 5 };
	Properties with_id;
	with_id.subscription_ids = ids[..];
	assert(@catch(s.core.subscribe(t, plain[..], &with_id)) == mqtt::NOT_SUPPORTED_BY_SERVER, "subscription identifiers not available");
	assert(s.core.pending_output().len == 0);
	// what the server does allow still works
	OutMessage ok = msg("a", "01");
	s.core.publish(t, &ok)!!;
	s.core.subscribe(t, plain[..], null)!!;
	s.close();

	// 3.1.1 has no such limits and treats `$share/...` as an ordinary filter
	Session u;
	Config d = cfg(Version.V311);
	u.open(&d, CONNACK_311);
	SubEntry[1] sh = { { .filter = "$share/g/a" } };
	u.core.subscribe(u.clock.now, sh[..], null)!!;
	u.close();
}

fn void refusals_server_packet_limit() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, "20 08 00 00 05 27 00 00 00 14");              // the server accepts packets up to 20 bytes
	Duration t = s.clock.now;
	OutMessage fits = msg("a/b", "01 02 03 04 05 06 07 08 09 0A 0B");       // 1 + 1 + 2 + 3 + 1 + 11 = 19
	s.core.publish(t, &fits)!!;
	harness::expect_out(&s.core, "30 11 00 03 61 2F 62 00 01 02 03 04 05 06 07 08 09 0A 0B");
	OutMessage big = msg("a/b", "01 02 03 04 05 06 07 08 09 0A 0B 0C 0D");
	assert(@catch(s.core.publish(t, &big)) == mqtt::PACKET_TOO_LARGE);
	assert(s.core.pending_output().len == 0, "nothing was queued");
	s.close();
}
