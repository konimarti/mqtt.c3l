module mqtt::core_limits_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::props, mqtt::testutil;

const String CONNACK_311 = "20 02 00 00";
const String CONNACK_5 = "20 03 00 00 00";

fn Config cfg(Version v)
{
	return core::default_config(v, "a");
}

fn OutMessage msg(QoS qos, String payload_hex)
{
	return { .topic = "t", .payload = testutil::hex(payload_hex), .qos = qos };
}

// ---- the server's limits ----

fn void seq_9_6() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, "20 06 00 00 03 21 00 02");                      // Receive Maximum 2
	OutMessage a = msg(QoS.AT_LEAST_ONCE, "01");
	OutMessage b = msg(QoS.AT_LEAST_ONCE, "02");
	OutMessage d = msg(QoS.AT_LEAST_ONCE, "03");
	assert(s.core.publish(s.clock.now, &a)!! == 1);
	assert(s.core.publish(s.clock.now, &b)!! == 2);
	assert(s.core.publish(s.clock.now, &d)!! == 0, "the third waits");
	// QoS 0 and a SUBSCRIBE are not held back by the window
	OutMessage zero = msg(QoS.AT_MOST_ONCE, "09");
	s.core.publish(s.clock.now, &zero)!!;
	SubEntry[1] entries = { { .filter = "a" } };
	assert(s.core.subscribe(s.clock.now, entries[..], null)!! == 3);
	harness::expect_out(&s.core, "32 07 00 01 74 00 01 00 01 32 07 00 01 74 00 02 00 02 30 05 00 01 74 00 09 82 07 00 03 00 00 01 61 00");
	// a PUBACK frees a slot: the third message goes out (the id 3 is taken by the SUBSCRIBE)
	harness::feed(&s.core, &s.clock, "40 03 00 01 00");
	harness::expect_out(&s.core, "32 07 00 01 74 00 04 00 03");
	assert(s.core.queued_count() == 0 && s.core.inflight_count() == 2);
	s.close();
}

fn void seq_9_8() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, "20 08 00 00 05 27 00 00 00 14");               // the server takes 20 bytes at most
	OutMessage fits = msg(QoS.AT_MOST_ONCE, "01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E");      // 6 + 14 = 20
	s.core.publish(s.clock.now, &fits)!!;
	assert(s.core.pending_output().len == 20);
	s.core.output_done(20);
	OutMessage over = msg(QoS.AT_MOST_ONCE, "01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");   // 21
	assert(@catch(s.core.publish(s.clock.now, &over)) == mqtt::PACKET_TOO_LARGE);
	OutMessage over1 = msg(QoS.AT_LEAST_ONCE, "01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E");     // 22 with the id
	assert(@catch(s.core.publish(s.clock.now, &over1)) == mqtt::PACKET_TOO_LARGE);
	assert(s.core.pending_output().len == 0 && s.core.inflight_count() == 0 && s.core.queued_count() == 0, "nothing was queued or kept");
	SubEntry[1] entries = { { .filter = "a/b/c/d/e/f/g/h/i/j/k/l" } };
	assert(@catch(s.core.subscribe(s.clock.now, entries[..], null)) == mqtt::PACKET_TOO_LARGE);
	// the refused request gave its packet id back
	assert(!s.core.id_in_use(1));
	SubEntry[1] small = { { .filter = "a" } };
	assert(s.core.subscribe(s.clock.now, small[..], null)!! == 2);
	s.close();
}

fn void drop_reason_string_when_too_large() @test
{
	Properties p;
	p.set(PropId.REASON_STRING);
	p.reason_string = "this reason does not fit";
	UserProperty[1] users = { { "key", "value" } };
	p.user = users[..];
	// the server takes 20 bytes at most: reason string and user properties are left out, the packet is still sent
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, "20 08 00 00 05 27 00 00 00 14");
	s.core.disconnect(s.clock.now, ReasonCode.DISCONNECT_WITH_WILL, &p)!!;
	harness::expect_out(&s.core, "E0 01 04");
	s.close();
	// with room for them they are sent
	Session t;
	Config d = cfg(Version.V5);
	t.open(&d, "20 08 00 00 05 27 00 00 01 00");
	t.core.disconnect(t.clock.now, ReasonCode.DISCONNECT_WITH_WILL, &p)!!;
	char[] out = t.core.pending_output();
	assert(out.len > 20 && out[0] == 0xE0);
	t.core.output_done(out.len);
	t.close();
}

// ---- our own limits ----

fn void connect_advertises_max_packet_size() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.max_packet_size = 1024;
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	harness::expect_out(&s.core, "10 13 00 04 4D 51 54 54 05 02 00 3C 05 27 00 00 04 00 00 01 61");
	s.close();
	Session t;
	Config d = cfg(Version.V5);
	t.mem_track.init(mem);
	t.core.init(&t.mem_track, &d)!!;
	t.core.connect(t.clock.now)!!;
	harness::expect_out(&t.core, "10 13 00 04 4D 51 54 54 05 02 00 3C 05 27 00 04 00 00 00 01 61");        // the 256 KiB default
	t.close();
}

fn void vec_V_FR_N10_core() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.max_packet_size = 100;
	s.open(&c, CONNACK_5);
	// byte by byte: the first two bytes of `30 E8 07` are only the start of a header
	char[] hdr = testutil::hex("30 E8 07");
	s.core.input(s.clock.now, hdr[:1])!!;
	s.core.input(s.clock.now, hdr[1:1])!!;
	assert(@catch(s.core.input(s.clock.now, hdr[2:1])) == mqtt::PACKET_TOO_LARGE, "rejected on the third byte, the body is not awaited");
	harness::expect_out(&s.core, "E0 01 95");
	s.close();
}

fn void inbound_limit_v5_disconnect_0x95() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.max_packet_size = 100;
	s.open(&c, CONNACK_5);
	char[] big = mem::temp_array(char, 1003);
	big[..] = 0x61;
	big[0] = 0x30;
	big[1] = 0xE8;
	big[2] = 0x07;
	assert(@catch(s.core.input(s.clock.now, big)) == mqtt::PACKET_TOO_LARGE);
	harness::expect_out(&s.core, "E0 01 95");
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::PACKET_TOO_LARGE && ev.closed.reason == ReasonCode.PACKET_TOO_LARGE && !ev.closed.by_server);
	s.close();
}

fn void inbound_limit_311_closed() @test
{
	Session s;
	Config c = cfg(Version.V311);
	c.max_packet_size = 100;
	s.open(&c, CONNACK_311);
	char[] hdr = testutil::hex("30 E8 07");
	assert(@catch(s.core.input(s.clock.now, hdr)) == mqtt::PACKET_TOO_LARGE);
	harness::expect_no_out(&s.core);
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::PACKET_TOO_LARGE);
	assert(s.core.state == State.DISCONNECTED);
	s.close();
}

fn void inbound_receive_maximum_0x93() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.receive_maximum = 2;
	s.open(&c, CONNACK_5);
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 01 00 78");
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 02 00 78");
	harness::feed(&s.core, &s.clock, "3C 07 00 01 61 00 02 00 78");          // a repeat is not a new message
	harness::expect_out(&s.core, "50 02 00 01 50 02 00 02 50 02 00 02");
	harness::drain(&s.core);
	// finishing one frees a slot
	harness::feed(&s.core, &s.clock, "62 02 00 01");
	harness::expect_out(&s.core, "70 02 00 01");
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 03 00 78");
	harness::expect_out(&s.core, "50 02 00 03");
	// a fourth unfinished message is one too many
	char[] over = testutil::hex("34 07 00 01 61 00 04 00 78");
	assert(@catch(s.core.input(s.clock.now, over)) == mqtt::RECEIVE_MAXIMUM_EXCEEDED);
	harness::expect_out(&s.core, "E0 01 93");
	s.close();
}

fn void payload_utf8_0x99() @test
{
	// asked for: text announced by the Payload Format Indicator must be UTF-8
	{
		Session s;
		Config c = cfg(Version.V5);
		c.validate_payload_utf8 = true;
		s.open(&c, CONNACK_5);
		harness::feed(&s.core, &s.clock, "30 08 00 01 61 02 01 01 C3 A9");                  // "é"
		assert(s.take().kind == EventKind.MESSAGE);
		char[] frame = testutil::hex("30 08 00 01 61 02 01 01 C0 80");
		assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::PAYLOAD_FORMAT_INVALID);
		harness::expect_out(&s.core, "E0 01 99");
		s.close();
	}
	// bytes that are not announced as text, and the default of not checking
	{
		Session s;
		Config c = cfg(Version.V5);
		c.validate_payload_utf8 = true;
		s.open(&c, CONNACK_5);
		harness::feed(&s.core, &s.clock, "30 08 00 01 61 02 01 00 C0 80");
		assert(s.take().kind == EventKind.MESSAGE);
		harness::feed(&s.core, &s.clock, "30 06 00 01 61 00 C0 80");
		assert(s.take().kind == EventKind.MESSAGE);
		s.close();
	}
	{
		Session s;
		Config c = cfg(Version.V5);
		s.open(&c, CONNACK_5);
		harness::feed(&s.core, &s.clock, "30 08 00 01 61 02 01 01 C0 80");
		Event ev = s.take();
		assert(ev.kind == EventKind.MESSAGE && ev.message.props.payload_format == 1, "the indicator is visible to the application");
		s.close();
	}
}

fn void max_in_buffer_queue_full() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.max_packet_size = 100;
	c.max_in_buffer = 150;
	s.open(&c, CONNACK_5);
	String frame = "30 3F 00 01 61 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B";
	harness::feed(&s.core, &s.clock, frame);
	harness::feed(&s.core, &s.clock, frame);
	char[] third = testutil::hex(frame);
	assert(@catch(s.core.input(s.clock.now, third)) == mqtt::QUEUE_FULL, "too much is waiting for the application");
	assert(s.core.state == State.CONNECTED, "nothing was consumed and nothing broke");
	// the application takes its events; the same bytes are accepted now
	assert(harness::drain(&s.core).len == 2);
	s.core.input(s.clock.now, third)!!;
	assert(harness::drain(&s.core).len == 1);
	s.close();
}

fn void max_out_buffer_queue_full() @test
{
	Session s;
	Config c = cfg(Version.V311);
	c.max_out_buffer = 20;
	s.open(&c, CONNACK_311);
	OutMessage m = msg(QoS.AT_MOST_ONCE, "01 02 03 04");           // 9 bytes
	s.core.publish(s.clock.now, &m)!!;
	s.core.publish(s.clock.now, &m)!!;
	assert(@catch(s.core.publish(s.clock.now, &m)) == mqtt::QUEUE_FULL);
	assert(s.core.pending_output().len == 18, "the refused message left nothing behind");
	s.core.output_done(9);
	s.core.publish(s.clock.now, &m)!!;
	assert(s.core.pending_output().len == 18);
	s.core.output_done(18);
	s.close();
}

// ---- the DISCONNECT reasons the core sends ----

// the server sends `input`: the core fails with `expected` and sends `disconnect` (nothing: "")
fn void expect_failure(Version v, Config* c, String connack, String input, fault expected, String disconnect)
{
	Session s;
	s.open(c, connack);
	char[] bytes = testutil::hex(input);
	assert(@catch(s.core.input(s.clock.now, bytes)) == expected, "wrong fault");
	if (disconnect.len > 0)
	{
		harness::expect_out(&s.core, disconnect);
	}
	else
	{
		harness::expect_no_out(&s.core);
	}
	// the close is reported after whatever was delivered before it
	Event ev;
	Event last;
	while (s.core.poll_event(&ev)) last = ev;
	assert(last.kind == EventKind.CLOSED && last.closed.cause == expected && !last.closed.by_server);
	assert(s.core.state == State.DISCONNECTED);
	s.close();
}

fn void disconnect_reasons_table() @test
{
	Config c5 = cfg(Version.V5);
	c5.receive_maximum = 1;
	c5.max_packet_size = 100;
	c5.validate_payload_utf8 = true;
	// 5.0: a DISCONNECT with the matching reason
	expect_failure(Version.V5, &c5, CONNACK_5, "00 00", mqtt::MALFORMED_PACKET, "E0 01 81");
	expect_failure(Version.V5, &c5, CONNACK_5, "20 03 00 00 00", mqtt::PROTOCOL_ERROR, "E0 01 82");
	expect_failure(Version.V5, &c5, CONNACK_5, "30 06 00 03 61 2F 23 00", mqtt::INVALID_TOPIC_NAME, "E0 01 90");
	expect_failure(Version.V5, &c5, CONNACK_5, "34 07 00 01 61 00 01 00 78 34 07 00 01 61 00 02 00 78", mqtt::RECEIVE_MAXIMUM_EXCEEDED, "50 02 00 01 E0 01 93");
	expect_failure(Version.V5, &c5, CONNACK_5, "30 E8 07", mqtt::PACKET_TOO_LARGE, "E0 01 95");
	expect_failure(Version.V5, &c5, CONNACK_5, "30 08 00 01 61 02 01 01 C0 80", mqtt::PAYLOAD_FORMAT_INVALID, "E0 01 99");
	// 3.1.1 has no DISCONNECT from the client for a fault: the connection is just ended
	Config c3 = cfg(Version.V311);
	c3.max_packet_size = 100;
	expect_failure(Version.V311, &c3, CONNACK_311, "00 00", mqtt::MALFORMED_PACKET, "");
	expect_failure(Version.V311, &c3, CONNACK_311, "20 02 00 00", mqtt::PROTOCOL_ERROR, "");
	expect_failure(Version.V311, &c3, CONNACK_311, "30 E8 07", mqtt::PACKET_TOO_LARGE, "");
}
