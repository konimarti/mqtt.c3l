module mqtt::core_qos_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::packet, mqtt::props, mqtt::testutil, std::time;

const String CONNACK_311 = "20 02 00 00";
const String CONNACK_5 = "20 03 00 00 00";
const String CONNACK_5_WINDOW_1 = "20 06 00 00 03 21 00 01";       // Receive Maximum 1
const String CONNACK_5_WINDOW_3 = "20 06 00 00 03 21 00 03";       // Receive Maximum 3

fn Config cfg(Version v)
{
	Config c = core::default_config(v, "a");
	return c;
}

fn OutMessage msg(String topic, QoS qos, String payload_hex = "")
{
	return { .topic = topic, .payload = testutil::hex(payload_hex), .qos = qos };
}

// "40 02 00 01" for id 1: PUBACK, PUBREC (50), PUBCOMP (70) in the short form
fn char[] ack_frame(char type, ushort id)
{
	char[] f = mem::temp_array(char, 4);
	f[0] = type;
	f[1] = 2;
	f[2] = (char)(id >> 8);
	f[3] = (char)(id & 0xFF);
	return f;
}

// the packet ids of the PUBLISH frames in a block of output
fn ushort[] publish_ids(char[] output)
{
	ushort[] ids = mem::temp_array(ushort, 70_000);
	usz n;
	char[] rest = output;
	while (rest.len > 0)
	{
		usz len = packet::frame_length(rest, 0)!!;
		assert(len > 0 && len <= rest.len);
		if (rest[0] >> 4 == 3)
		{
			Packet p = packet::decode(Version.V311, rest[:len])!!;
			ids[n++] = p.publish.packet_id;
		}
		rest = rest[len..];
	}
	return ids[:n];
}

// ---- outbound QoS 1 and 2 ----

fn void seq_9_2() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	OutMessage m = msg("a/b", QoS.AT_LEAST_ONCE, "68 69");
	assert(s.core.publish(s.clock.now, &m)!! == 1, "the first id is 1");
	harness::expect_out(&s.core, "32 09 00 03 61 2F 62 00 01 68 69");
	assert(s.core.inflight_count() == 1);
	harness::feed(&s.core, &s.clock, "40 02 00 01");
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 1 && ev.done.reason == ReasonCode.SUCCESS);
	assert(s.core.inflight_count() == 0);
	// id 1 is free again, the next message uses id 2
	assert(s.core.publish(s.clock.now, &m)!! == 2);
	harness::expect_out(&s.core, "32 09 00 03 61 2F 62 00 02 68 69");
	s.close();
}

fn void seq_9_3() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	OutMessage m = msg("a", QoS.EXACTLY_ONCE, "78");
	assert(s.core.publish(s.clock.now, &m)!! == 1);
	harness::expect_out(&s.core, "34 06 00 01 61 00 01 78");
	harness::feed(&s.core, &s.clock, "50 02 00 01");
	harness::expect_out(&s.core, "62 02 00 01");
	assert(harness::drain(&s.core).len == 0, "not finished before PUBCOMP");
	assert(s.core.inflight_count() == 1);
	harness::feed(&s.core, &s.clock, "70 02 00 01");
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 1);
	assert(s.core.inflight_count() == 0);
	harness::expect_no_out(&s.core);
	s.close();
}

fn void seq_9_4() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "34 06 00 01 61 00 09 78");
	harness::expect_out(&s.core, "50 02 00 09");
	Event ev = s.take();
	assert(ev.kind == EventKind.MESSAGE && ev.message.payload == testutil::hex("78") && ev.message.packet_id == 9);
	// the server repeats the PUBLISH (DUP): no second delivery, the PUBREC again
	harness::feed(&s.core, &s.clock, "3C 06 00 01 61 00 09 78");
	harness::expect_out(&s.core, "50 02 00 09");
	assert(harness::drain(&s.core).len == 0);
	harness::feed(&s.core, &s.clock, "62 02 00 09");
	harness::expect_out(&s.core, "70 02 00 09");
	// a PUBREL for an id no longer known still gets its PUBCOMP
	harness::feed(&s.core, &s.clock, "62 02 00 09");
	harness::expect_out(&s.core, "70 02 00 09");
	s.close();

	Session t;
	Config d = cfg(Version.V5);
	t.open(&d, CONNACK_5);
	harness::feed(&t.core, &t.clock, "62 02 00 09");
	harness::expect_out(&t.core, "70 03 00 09 92");
	t.close();
}

fn void seq_9_5() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	OutMessage m = msg("t", QoS.AT_LEAST_ONCE);
	assert(s.core.publish(s.clock.now, &m)!! == 1);                // id 1 stays in flight
	s.core.output_done(s.core.pending_output().len);
	s.core.next_id = 65_534;
	ushort[3] seen;
	for (int i = 0; i < 3; i++)
	{
		seen[i] = s.core.publish(s.clock.now, &m)!!;
		s.core.output_done(s.core.pending_output().len);
	}
	assert(seen[0] == 65_534 && seen[1] == 65_535 && seen[2] == 2, "wraps to 1, which is busy, so 2");
	s.close();
}

fn void qos1_error_reason_frees_quota() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5_WINDOW_1);
	OutMessage a = msg("a", QoS.AT_LEAST_ONCE, "01");
	OutMessage b = msg("b", QoS.AT_LEAST_ONCE, "02");
	assert(s.core.publish(s.clock.now, &a)!! == 1);
	assert(s.core.publish(s.clock.now, &b)!! == 0, "the window is full: queued");
	assert(s.core.queued_count() == 1);
	harness::expect_out(&s.core, "32 07 00 01 61 00 01 00 01");
	// the server refuses the first message (0x87 Not authorized): the flow ends, the id and the window are free
	harness::feed(&s.core, &s.clock, "40 04 00 01 87 00");
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 1 && ev.done.reason == ReasonCode.NOT_AUTHORIZED);
	harness::expect_out(&s.core, "32 07 00 01 62 00 02 00 02");
	assert(s.core.queued_count() == 0 && s.core.inflight_count() == 1);
	// 0x10 No matching subscribers is a success
	harness::feed(&s.core, &s.clock, "40 04 00 02 10 00");
	ev = s.take();
	assert(ev.done.packet_id == 2 && ev.done.reason == ReasonCode.NO_MATCHING_SUBSCRIBERS);
	s.close();
}

fn void qos2_pubrec_error_ends_flow() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	OutMessage m = msg("a", QoS.EXACTLY_ONCE, "01");
	assert(s.core.publish(s.clock.now, &m)!! == 1);
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 04 00 01 97 00");          // 0x97 Quota exceeded
	harness::expect_no_out(&s.core);
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.reason == ReasonCode.QUOTA_EXCEEDED);
	assert(s.core.inflight_count() == 0);
	assert(s.core.publish(s.clock.now, &m)!! == 2, "the id was released, the counter moves on");
	s.close();
}

fn void qos2_duplicate_pubrec() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	OutMessage m = msg("a", QoS.EXACTLY_ONCE, "78");
	s.core.publish(s.clock.now, &m)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 02 00 01");
	harness::expect_out(&s.core, "62 02 00 01");
	harness::feed(&s.core, &s.clock, "50 02 00 01");                 // the PUBREC again: PUBREL again, never the PUBLISH
	harness::expect_out(&s.core, "62 02 00 01");
	assert(s.core.inflight_count() == 1);
	s.close();
}

fn void ack_unknown_id_ignored() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "40 02 00 09");               // PUBACK for nothing we sent
	harness::feed(&s.core, &s.clock, "70 02 00 09");               // PUBCOMP too
	harness::expect_no_out(&s.core);
	assert(harness::drain(&s.core).len == 0 && s.core.state == State.CONNECTED);
	// A PUBREC for an unknown id is answered with PUBREL so the server can finish its side
	// (5.0 3.6.2.1: reason 0x92 says the id is not known; 3.1.1 has no reason code).
	harness::feed(&s.core, &s.clock, "50 02 00 09");
	harness::expect_out(&s.core, "62 02 00 09");
	s.close();

	Session t;
	Config d = cfg(Version.V5);
	t.open(&d, CONNACK_5);
	harness::feed(&t.core, &t.clock, "50 02 00 09");
	harness::expect_out(&t.core, "62 03 00 09 92");
	t.close();
}

fn void ack_type_mismatch_closes() @test
{
	// a PUBACK for a QoS 2 message
	{
		Session s;
		Config c = cfg(Version.V5);
		s.open(&c, CONNACK_5);
		OutMessage m = msg("a", QoS.EXACTLY_ONCE);
		s.core.publish(s.clock.now, &m)!!;
		s.core.output_done(s.core.pending_output().len);
		char[] f = ack_frame(0x40, 1);
		assert(@catch(s.core.input(s.clock.now, f)) == mqtt::PROTOCOL_ERROR);
		harness::expect_out(&s.core, "E0 01 82");
		Event ev = s.take();
		assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::PROTOCOL_ERROR);
		s.close();
	}
	// a PUBCOMP while waiting for the PUBREC
	{
		Session s;
		Config c = cfg(Version.V311);
		s.open(&c, CONNACK_311);
		OutMessage m = msg("a", QoS.EXACTLY_ONCE);
		s.core.publish(s.clock.now, &m)!!;
		s.core.output_done(s.core.pending_output().len);
		char[] f = ack_frame(0x70, 1);
		assert(@catch(s.core.input(s.clock.now, f)) == mqtt::PROTOCOL_ERROR);
		assert(s.core.pending_output().len == 0, "3.1.1 sends nothing for a fault");
		s.close();
	}
	// a PUBREC for a QoS 1 message
	{
		Session s;
		Config c = cfg(Version.V311);
		s.open(&c, CONNACK_311);
		OutMessage m = msg("a", QoS.AT_LEAST_ONCE);
		s.core.publish(s.clock.now, &m)!!;
		s.core.output_done(s.core.pending_output().len);
		char[] f = ack_frame(0x50, 1);
		assert(@catch(s.core.input(s.clock.now, f)) == mqtt::PROTOCOL_ERROR);
		s.close();
	}
}

fn void inbound_qos2_duplicate_publish() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "34 06 00 01 61 00 07 78");
	harness::feed(&s.core, &s.clock, "3C 06 00 01 61 00 07 78");
	harness::feed(&s.core, &s.clock, "3C 06 00 01 61 00 07 78");
	harness::expect_out(&s.core, "50 02 00 07 50 02 00 07 50 02 00 07");
	assert(harness::drain(&s.core).len == 1);
	// after the PUBREL / PUBCOMP exchange the id is free for a new message
	harness::feed(&s.core, &s.clock, "62 02 00 07");
	harness::expect_out(&s.core, "70 02 00 07");
	harness::feed(&s.core, &s.clock, "34 06 00 01 61 00 07 79");
	harness::expect_out(&s.core, "50 02 00 07");
	Event ev = s.take();
	assert(ev.message.payload == testutil::hex("79"));
	s.close();
}

fn void inbound_pubrel_unknown_id() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	harness::feed(&s.core, &s.clock, "62 02 00 33");
	harness::expect_out(&s.core, "70 02 00 33");
	s.close();
	Session t;
	Config d = cfg(Version.V5);
	t.open(&d, CONNACK_5);
	harness::feed(&t.core, &t.clock, "62 02 00 33");
	harness::expect_out(&t.core, "70 03 00 33 92");
	t.close();
}

// the acknowledgement vectors, driven through the core with real packet ids
fn void ack_vectors_through_the_core() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	OutMessage m = msg("t", QoS.AT_LEAST_ONCE);
	OutMessage q = msg("t", QoS.EXACTLY_ONCE);
	String[4] puback = { "40 02 00 01", "40 03 00 02 00", "40 04 00 03 10 00", "40 04 00 04 87 00" };
	ReasonCode[4] expected = { ReasonCode.SUCCESS, ReasonCode.SUCCESS, ReasonCode.NO_MATCHING_SUBSCRIBERS, ReasonCode.NOT_AUTHORIZED };
	for (int i = 0; i < 4; i++)
	{
		s.core.publish(s.clock.now, &m)!!;
		s.core.output_done(s.core.pending_output().len);
		harness::feed(&s.core, &s.clock, puback[i]);
		Event ev = s.take();
		assert(ev.done.packet_id == (ushort)(i + 1) && ev.done.reason == expected[i]);
	}
	// PUBREC with an error, PUBCOMP with 0x92
	s.core.publish(s.clock.now, &q)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 04 00 05 97 00");
	assert(s.take().done.reason == ReasonCode.QUOTA_EXCEEDED);
	s.core.publish(s.clock.now, &q)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 02 00 06");
	harness::expect_out(&s.core, "62 02 00 06");
	harness::feed(&s.core, &s.clock, "70 03 00 06 92");
	assert(s.take().done.reason == ReasonCode.PACKET_IDENTIFIER_NOT_FOUND);
	// a PUBREL from the server in the short form for a message that is being received, and in the
	// long form for an id that is no longer known
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 0A 00 78");
	harness::expect_out(&s.core, "50 02 00 0A");
	s.take();
	harness::feed(&s.core, &s.clock, "62 02 00 0A");
	harness::expect_out(&s.core, "70 02 00 0A");
	harness::feed(&s.core, &s.clock, "62 03 00 0A 92");
	harness::expect_out(&s.core, "70 03 00 0A 92");
	s.close();
}

// ---- send window and queue ----

fn void quota_never_exceeded_100_msgs() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5_WINDOW_3);
	OutMessage m = msg("t", QoS.AT_LEAST_ONCE);
	for (int i = 0; i < 100; i++) s.core.publish(s.clock.now, &m)!!;
	assert(s.core.inflight_count() == 3 && s.core.queued_count() == 97);
	ushort[100] order;
	usz sent;
	ushort[3] window;                                       // ids on the wire without an acknowledgement
	usz outstanding;
	int done;
	while (done < 100)
	{
		// take what the core wants to write: never more than 3 PUBLISH frames are unacknowledged
		char[] out = s.core.pending_output();
		ushort[] ids = publish_ids5(out);
		s.core.output_done(out.len);
		foreach (id : ids)
		{
			assert(outstanding < 3, "more than three unacknowledged PUBLISH frames");
			window[outstanding++] = id;
			order[sent++] = id;
		}
		assert(outstanding > 0, "something is in flight until every message is done");
		// acknowledge the oldest
		ushort id = window[0];
		for (usz k = 1; k < outstanding; k++) window[k - 1] = window[k];
		outstanding--;
		char[] f = ack_frame(0x40, id);
		s.core.input(s.clock.now, f)!!;
		Event ev = s.take();
		assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == id);
		done++;
	}
	assert(sent == 100 && s.core.queued_count() == 0 && s.core.inflight_count() == 0);
	for (usz i = 0; i < 100; i++) assert(order[i] == (ushort)(i + 1), "sent in the order published, ids in sequence");
	s.close();
}

// the PUBLISH ids in 5.0 output
fn ushort[] publish_ids5(char[] output)
{
	ushort[] ids = mem::temp_array(ushort, 16);
	usz n;
	char[] rest = output;
	while (rest.len > 0)
	{
		usz len = packet::frame_length(rest, 0)!!;
		if (rest[0] >> 4 == 3)
		{
			Packet p = packet::decode(Version.V5, rest[:len])!!;
			ids[n++] = p.publish.packet_id;
		}
		rest = rest[len..];
	}
	return ids[:n];
}

fn void queue_full() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.max_queued = 2;
	s.open(&c, CONNACK_5_WINDOW_1);
	OutMessage m = msg("t", QoS.AT_LEAST_ONCE);
	assert(s.core.publish(s.clock.now, &m)!! == 1);
	assert(s.core.publish(s.clock.now, &m)!! == 0);
	assert(s.core.publish(s.clock.now, &m)!! == 0);
	assert(@catch(s.core.publish(s.clock.now, &m)) == mqtt::QUEUE_FULL);
	assert(s.core.queued_count() == 2 && s.core.inflight_count() == 1);
	s.close();                                                  // queued and inflight messages are freed
}

fn void id_exhaustion_via_subscribe() @test
{
	Session s;
	Config c = cfg(Version.V311);
	c.max_inflight = 65_535;
	s.open(&c, CONNACK_311);
	OutMessage m = msg("t", QoS.AT_LEAST_ONCE);
	for (int i = 0; i < 65_535; i++)
	{
		assert(s.core.publish(s.clock.now, &m)!! == (ushort)(i + 1));
		if (i % 1000 == 0) s.core.output_done(s.core.pending_output().len);
	}
	s.core.output_done(s.core.pending_output().len);
	assert(s.core.inflight_count() == 65_535);
	// every id is taken: a SUBSCRIBE has none left (the id space is shared), a PUBLISH waits in the queue
	SubEntry[1] entries = { { .filter = "a" } };
	assert(@catch(s.core.subscribe(s.clock.now, entries[..], null)) == mqtt::PACKET_ID_EXHAUSTED);
	assert(s.core.pending_output().len == 0, "the refused SUBSCRIBE queued nothing");
	assert(s.core.publish(s.clock.now, &m)!! == 0);
	assert(s.core.queued_count() == 1);
	// one acknowledgement frees an id and the window: the queued message goes out with it
	char[] f = ack_frame(0x40, 17);
	s.core.input(s.clock.now, f)!!;
	Event ev = s.take();
	assert(ev.done.packet_id == 17);
	assert(s.core.queued_count() == 0 && s.core.inflight_count() == 65_535);
	char[] out = s.core.pending_output();
	ushort[] ids = publish_ids(out);
	assert(ids.len == 1 && ids[0] == 17, "the next free id is the one just released");
	s.close();
}

// ---- 5.0 properties and message expiry ----

fn void properties_survive_in_the_record() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	OutMessage m = msg("a/b", QoS.AT_LEAST_ONCE, "68 69");
	m.props.set(PropId.CONTENT_TYPE);
	m.props.content_type = "a";
	UserProperty[1] users = { { "k", "v" } };
	m.props.user = users[..];
	s.core.publish(s.clock.now, &m)!!;
	harness::expect_out(&s.core, "32 15 00 03 61 2F 62 00 01 0B 03 00 01 61 26 00 01 6B 00 01 76 68 69");
	s.close();
}

fn void message_expiry_queued() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5_WINDOW_1);
	OutMessage a = msg("t", QoS.AT_LEAST_ONCE);
	OutMessage b = msg("t", QoS.AT_LEAST_ONCE);
	b.props.set(PropId.MESSAGE_EXPIRY_INTERVAL);
	b.props.message_expiry = 10;
	OutMessage d = msg("t", QoS.AT_LEAST_ONCE);
	d.props.set(PropId.MESSAGE_EXPIRY_INTERVAL);
	d.props.message_expiry = 60;
	assert(s.core.publish(s.clock.now, &a)!! == 1);
	assert(s.core.publish(s.clock.now, &b)!! == 0);
	assert(s.core.publish(s.clock.now, &d)!! == 0);
	s.core.output_done(s.core.pending_output().len);
	s.at(15_000);
	harness::feed(&s.core, &s.clock, "40 03 00 01 00");
	// the first message is done; the one that waited 15 s with a 10 s expiry is dropped; the third goes out
	// with the 45 seconds it has left
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 1);
	ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 0 && ev.done.reason == ReasonCode.UNSPECIFIED_ERROR);
	harness::expect_out(&s.core, "32 0B 00 01 74 00 02 05 02 00 00 00 2D");
	assert(s.core.queued_count() == 0 && s.core.inflight_count() == 1);
	s.close();
}

fn void message_expiry_rounds_up_and_untouched_when_sent_at_once() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5_WINDOW_1);
	OutMessage first = msg("t", QoS.AT_LEAST_ONCE);
	first.props.set(PropId.MESSAGE_EXPIRY_INTERVAL);
	first.props.message_expiry = 60;
	s.core.publish(s.clock.now, &first)!!;
	harness::expect_out(&s.core, "32 0B 00 01 74 00 01 05 02 00 00 00 3C");    // sent at once: unchanged
	OutMessage waiting = msg("t", QoS.AT_LEAST_ONCE);
	waiting.props.set(PropId.MESSAGE_EXPIRY_INTERVAL);
	waiting.props.message_expiry = 2;
	s.core.publish(s.clock.now, &waiting)!!;
	s.at(500);
	harness::feed(&s.core, &s.clock, "40 02 00 01");
	s.take();
	// 0.5 s of 2 s are gone: 1.5 s are left, rounded up to 2
	harness::expect_out(&s.core, "32 0B 00 01 74 00 02 05 02 00 00 00 02");
	s.close();
}

fn void everything_is_released() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5_WINDOW_1);
	OutMessage m = msg("topic", QoS.EXACTLY_ONCE, "01 02 03 04");
	m.props.set(PropId.CONTENT_TYPE);
	m.props.content_type = "text/plain";
	for (int i = 0; i < 5; i++) s.core.publish(s.clock.now, &m)!!;
	assert(s.core.inflight_count() == 1 && s.core.queued_count() == 4);
	s.close();                                                  // the tracking allocator requires zero allocations
}
