module mqtt::core_session_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::packet, mqtt::props, mqtt::testutil, std::time;

const String CONNACK_311 = "20 02 00 00";
const String CONNACK_311_SESSION = "20 02 01 00";
const String CONNACK_5 = "20 03 00 00 00";
const String CONNACK_5_SESSION = "20 03 01 00 00";

fn Config cfg(Version v, bool clean = false)
{
	Config c = core::default_config(v, "a");
	c.clean_start = clean;
	if (v == Version.V5) c.session_expiry = 3600;        // the session outlives a reconnect
	return c;
}

fn OutMessage msg(QoS qos, char payload)
{
	char[] p = mem::temp_array(char, 1);
	p[0] = payload;
	return { .topic = "t", .payload = p, .qos = qos };
}

// the connection ends; the CLOSED event is taken
fn void lose(Session* s)
{
	s.core.transport_closed(s.clock.now);
	EventKind[] kinds = harness::drain(&s.core);
	assert(kinds.len == 1 && kinds[0] == EventKind.CLOSED);
}

// connects again, takes the CONNECT bytes and feeds the CONNACK; the events are left to the test
fn void reconnect(Session* s, String connack_hex)
{
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, connack_hex);
}

fn EventKind[] kinds_of(Session* s) => harness::drain(&s.core);

// ---- resending after a reconnect ----

fn void resend_dup_in_order() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	for (char i = 1; i <= 3; i++)
	{
		OutMessage m = msg(QoS.AT_LEAST_ONCE, i);
		s.core.publish(s.clock.now, &m)!!;
	}
	OutMessage q4 = msg(QoS.EXACTLY_ONCE, 4);
	OutMessage q5 = msg(QoS.EXACTLY_ONCE, 5);
	s.core.publish(s.clock.now, &q4)!!;
	s.core.publish(s.clock.now, &q5)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 02 00 04");              // the QoS 2 message 4 got its PUBREC, 5 did not
	harness::expect_out(&s.core, "62 02 00 04");
	lose(&s);
	assert(s.core.inflight_count() == 5, "the session state is kept");
	reconnect(&s, CONNACK_311_SESSION);
	// original order; PUBLISH with DUP set; the message past its PUBREC is not sent again, only its PUBREL
	harness::expect_out(&s.core, "3A 06 00 01 74 00 01 01 3A 06 00 01 74 00 02 02 3A 06 00 01 74 00 03 03 62 02 00 04 3C 06 00 01 74 00 05 05");
	EventKind[] kinds = kinds_of(&s);
	assert(kinds.len == 1 && kinds[0] == EventKind.CONNECTED);
	// they finish normally
	harness::feed(&s.core, &s.clock, "40 02 00 02");
	harness::feed(&s.core, &s.clock, "70 02 00 04");
	assert(s.core.inflight_count() == 3);
	s.close();
}

fn ushort[] ids_of_publishes(char[] output)
{
	ushort[] ids = mem::temp_array(ushort, 64);
	usz n;
	char[] rest = output;
	while (rest.len > 0)
	{
		usz len = packet::frame_length(rest, 0)!!;
		if (rest[0] >> 4 == 3)
		{
			Packet p = packet::decode(Version.V5, rest[:len])!!;
			assert(p.publish.dup, "a resent PUBLISH has DUP set");
			ids[n++] = p.publish.packet_id;
		}
		rest = rest[len..];
	}
	return ids[:n];
}

fn void resend_paced_by_receive_maximum() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	for (char i = 1; i <= 5; i++)
	{
		OutMessage m = msg(QoS.AT_LEAST_ONCE, i);
		s.core.publish(s.clock.now, &m)!!;
	}
	s.core.output_done(s.core.pending_output().len);
	lose(&s);
	// the new server takes two at a time (Receive Maximum 2)
	reconnect(&s, "20 06 01 00 03 21 00 02");
	ushort[] first = ids_of_publishes(s.core.pending_output());
	assert(first.len == 2 && first[0] == 1 && first[1] == 2, "exactly two are sent again");
	s.core.output_done(s.core.pending_output().len);
	// a new message has to wait behind them
	OutMessage fresh = msg(QoS.AT_LEAST_ONCE, 9);
	assert(s.core.publish(s.clock.now, &fresh)!! == 0);
	harness::feed(&s.core, &s.clock, "40 02 00 01");
	ushort[] next = ids_of_publishes(s.core.pending_output());
	assert(next.len == 1 && next[0] == 3, "the third goes out when the first is acknowledged");
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "40 02 00 02");
	harness::feed(&s.core, &s.clock, "40 02 00 03");
	ushort[] more = ids_of_publishes(s.core.pending_output());
	assert(more.len == 2 && more[0] == 4 && more[1] == 5);
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "40 02 00 04");
	harness::feed(&s.core, &s.clock, "40 02 00 05");
	// then the queued message, as a new one (no DUP), with the next id
	harness::expect_out(&s.core, "32 07 00 01 74 00 06 00 09");
	assert(s.core.queued_count() == 0 && s.core.inflight_count() == 1);
	s.close();
}

fn void resend_too_large_fails() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	OutMessage a = msg(QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &a)!!;
	OutMessage big = { .topic = "t", .payload = testutil::hex("01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14"), .qos = QoS.AT_LEAST_ONCE };
	s.core.publish(s.clock.now, &big)!!;
	OutMessage rel = big;
	rel.qos = QoS.EXACTLY_ONCE;
	s.core.publish(s.clock.now, &rel)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 02 00 03");              // the third got its PUBREC
	s.core.output_done(s.core.pending_output().len);
	lose(&s);
	// the new server accepts packets of 20 bytes at most
	reconnect(&s, "20 08 01 00 05 27 00 00 00 14");
	// the small one is sent again, the big one cannot be, its PUBREL needs no payload and still goes out
	harness::expect_out(&s.core, "3A 07 00 01 74 00 01 00 01 62 02 00 03");
	Event ev = s.take();
	assert(ev.kind == EventKind.CONNECTED);
	ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 2 && ev.done.reason == ReasonCode.PACKET_TOO_LARGE);
	assert(s.core.inflight_count() == 2, "the failed message gave up its id");
	s.close();
}

fn void resend_qos_not_supported() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	OutMessage m1 = msg(QoS.AT_LEAST_ONCE, 1);
	OutMessage m2 = msg(QoS.EXACTLY_ONCE, 2);
	OutMessage m3 = msg(QoS.EXACTLY_ONCE, 3);
	s.core.publish(s.clock.now, &m1)!!;
	s.core.publish(s.clock.now, &m2)!!;
	s.core.publish(s.clock.now, &m3)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 02 00 03");
	s.core.output_done(s.core.pending_output().len);
	lose(&s);
	reconnect(&s, "20 05 01 00 02 24 01");                          // the new server only does QoS 0 and 1
	harness::expect_out(&s.core, "3A 07 00 01 74 00 01 00 01 62 02 00 03");
	Event ev = s.take();
	assert(ev.kind == EventKind.CONNECTED);
	ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 2 && ev.done.reason == ReasonCode.QOS_NOT_SUPPORTED);
	s.close();
}

// ---- state that is gone ----

fn void session_lost_reports_done() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, "20 06 00 00 03 21 00 03");                        // window of 3
	for (char i = 1; i <= 4; i++)
	{
		OutMessage m = msg(QoS.AT_LEAST_ONCE, i);
		s.core.publish(s.clock.now, &m)!!;
	}
	assert(s.core.inflight_count() == 3 && s.core.queued_count() == 1);
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 09 00 78");         // an inbound QoS 2 message that is half done
	s.core.output_done(s.core.pending_output().len);
	harness::drain(&s.core);
	lose(&s);
	reconnect(&s, CONNACK_5);                                    // the server has no session
	Event ev = s.take();
	assert(ev.kind == EventKind.CONNECTED && !ev.connected.session_present);
	for (ushort id = 1; id <= 3; id++)
	{
		ev = s.take();
		assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == id && ev.done.reason == ReasonCode.UNSPECIFIED_ERROR);
	}
	// nothing is sent again; the message that never left goes out as a new one
	harness::expect_out(&s.core, "32 07 00 01 74 00 04 00 04");
	assert(s.core.inflight_count() == 1 && s.core.queued_count() == 0);
	// the half done inbound message is forgotten: the same id is a new message now
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 09 00 78");
	assert(s.take().kind == EventKind.MESSAGE);
	s.close();
}

fn void session_present_nothing_held() @test
{
	Session t;
	Config c = cfg(Version.V311);
	t.mem_track.init(mem);
	t.core.init(&t.mem_track, &c)!!;
	t.core.connect(t.clock.now)!!;
	t.core.output_done(t.core.pending_output().len);
	harness::feed(&t.core, &t.clock, CONNACK_311_SESSION);
	Event ev = t.take();
	assert(ev.kind == EventKind.CONNECTED && ev.connected.session_present, "a stored session on the server is harmless");
	harness::expect_no_out(&t.core);
	t.close();
}

fn void clean_start_discards() @test
{
	Session s;
	Config c = cfg(Version.V5, true);
	s.open(&c, CONNACK_5);
	OutMessage m = msg(QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &m)!!;
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 09 00 78");
	s.core.output_done(s.core.pending_output().len);
	harness::drain(&s.core);
	lose(&s);
	assert(s.core.inflight_count() == 1, "kept until the next connect");
	s.core.connect(s.clock.now)!!;
	assert(s.core.inflight_count() == 0 && s.core.queued_count() == 0, "a clean start drops everything");
	assert(harness::drain(&s.core).len == 0, "silently");
	assert(!s.core.id_in_use(1), "and gives the ids back");
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, CONNACK_5);
	harness::drain(&s.core);
	harness::expect_no_out(&s.core);
	harness::feed(&s.core, &s.clock, "34 07 00 01 61 00 09 00 78");
	assert(s.take().kind == EventKind.MESSAGE, "the inbound id is new again");
	s.close();
}

// ---- 5.0 session expiry ----

// one message in flight, the connection ends at 1 s; reconnect after `offline_ms`
fn void expiry_case(String connack1, long offline_ms, bool expect_discard, uint config_expiry = 60)
{
	Session s;
	Config c = cfg(Version.V5);
	c.session_expiry = config_expiry;
	s.open(&c, connack1);
	OutMessage m = msg(QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &m)!!;
	s.core.output_done(s.core.pending_output().len);
	s.at(1000);
	lose(&s);
	s.at(1000 + offline_ms);
	reconnect(&s, CONNACK_5_SESSION);
	if (expect_discard)
	{
		Event ev = s.take();
		assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 1 && ev.done.reason == ReasonCode.UNSPECIFIED_ERROR);
		assert(s.core.inflight_count() == 0);
	}
	else
	{
		assert(s.core.inflight_count() == 1, "the session is still there");
		harness::expect_out(&s.core, "3A 07 00 01 74 00 01 00 01");
	}
	s.close();
}

fn void session_expiry_boundary() @test
{
	expiry_case(CONNACK_5, 59_999, false);
	expiry_case(CONNACK_5, 60_000, true);
	// the server's Session Expiry Interval overrides ours
	expiry_case("20 08 00 00 05 11 00 00 00 0A", 9_999, false);
	expiry_case("20 08 00 00 05 11 00 00 00 0A", 10_000, true);
	// never
	expiry_case(CONNACK_5, 10L * 24 * 3600 * 1000, false, 0xFFFFFFFF);
	// 0: the session ended with the connection
	expiry_case(CONNACK_5, 0, true, 0);
}

fn void session_expiry_ignores_connections_that_never_got_a_connack() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.session_expiry = 60;
	s.open(&c, CONNACK_5);
	OutMessage m = msg(QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &m)!!;
	s.core.output_done(s.core.pending_output().len);
	lose(&s);                                                    // the last real connection ended at 0
	s.at(10_000);
	s.core.connect(s.clock.now)!!;                               // this one never gets a CONNACK
	s.core.output_done(s.core.pending_output().len);
	assert(s.core.inflight_count() == 1);
	s.at(11_000);
	lose(&s);
	// 65 s after the last real connection ended, only 54 s after the failed attempt: the session is gone
	s.at(65_000);
	s.core.connect(s.clock.now)!!;
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 1);
	s.core.output_done(s.core.pending_output().len);
	s.close();
}

fn void session_in_3_1_1_does_not_expire() @test
{
	Session s;
	Config c = cfg(Version.V311);
	s.open(&c, CONNACK_311);
	OutMessage m = msg(QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &m)!!;
	s.core.output_done(s.core.pending_output().len);
	lose(&s);
	s.at(100L * 24 * 3600 * 1000);
	reconnect(&s, CONNACK_311_SESSION);
	harness::expect_out(&s.core, "3A 06 00 01 74 00 01 01");
	s.close();
}

fn void assigned_id_reused() @test
{
	Session s;
	Config c = core::default_config(Version.V5, "");
	s.open(&c, "20 08 00 00 05 12 00 02 78 79");
	lose(&s);
	s.core.connect(s.clock.now)!!;
	harness::expect_out(&s.core, "10 14 00 04 4D 51 54 54 05 02 00 3C 05 27 00 04 00 00 00 02 78 79");
	harness::feed(&s.core, &s.clock, CONNACK_5);                 // this CONNACK assigns nothing new
	harness::drain(&s.core);
	lose(&s);
	s.core.connect(s.clock.now)!!;
	harness::expect_out(&s.core, "10 14 00 04 4D 51 54 54 05 02 00 3C 05 27 00 04 00 00 00 02 78 79");
	s.close();
}

// ---- will and DISCONNECT ----

fn void will_bytes_311() @test
{
	Session s;
	Config c = cfg(Version.V311, true);
	Will w = { .topic = "w/t", .payload = testutil::hex("6D"), .qos = QoS.EXACTLY_ONCE, .retain = true };
	c.will = &w;
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	harness::expect_out(&s.core, "10 15 00 04 4D 51 54 54 04 36 00 3C 00 01 61 00 03 77 2F 74 00 01 6D");
	s.close();
}

fn void will_bytes_v5() @test
{
	Session s;
	Config c = cfg(Version.V5, true);
	c.session_expiry = 0;
	Will w = { .topic = "w/t", .payload = testutil::hex("6D") };
	w.props.set(PropId.WILL_DELAY_INTERVAL);
	w.props.will_delay = 30;
	w.props.set(PropId.CONTENT_TYPE);
	w.props.content_type = "a";
	c.will = &w;
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	harness::expect_out(&s.core, "10 25 00 04 4D 51 54 54 05 06 00 3C 05 27 00 04 00 00 00 01 61 09 03 00 01 61 18 00 00 00 1E 00 03 77 2F 74 00 01 6D");
	s.close();
}

fn void disconnect_with_will() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	s.core.disconnect(s.clock.now, ReasonCode.DISCONNECT_WITH_WILL, null)!!;
	harness::expect_out(&s.core, "E0 01 04");
	s.close();
	// 3.1.1 has neither reason code nor properties
	Session t;
	Config d = cfg(Version.V311);
	t.open(&d, CONNACK_311);
	Properties p;
	p.set(PropId.REASON_STRING);
	p.reason_string = "x";
	t.core.disconnect(t.clock.now, ReasonCode.DISCONNECT_WITH_WILL, &p)!!;
	harness::expect_out(&t.core, "E0 00");
	t.close();
}

fn void disconnect_expiry_zero_to_nonzero() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.session_expiry = 0;
	s.open(&c, CONNACK_5);
	Properties p;
	p.set(PropId.SESSION_EXPIRY_INTERVAL);
	p.session_expiry = 60;
	assert(@catch(s.core.disconnect(s.clock.now, ReasonCode.NORMAL_DISCONNECTION, &p)) == mqtt::INVALID_ARGUMENT);
	assert(s.core.state == State.CONNECTED && s.core.pending_output().len == 0, "nothing happened");
	s.close();

	Session t;
	Config d = cfg(Version.V5);
	d.session_expiry = 100;
	t.open(&d, CONNACK_5);
	t.core.disconnect(t.clock.now, ReasonCode.NORMAL_DISCONNECTION, &p)!!;
	harness::expect_out(&t.core, "E0 07 00 05 11 00 00 00 3C");
	t.close();
}

// the interval a DISCONNECT sets is the one the offline time is measured against
fn void disconnect_changes_the_expiry_used_offline() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.session_expiry = 100;
	s.open(&c, CONNACK_5);
	OutMessage m = msg(QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &m)!!;
	Properties p;
	p.set(PropId.SESSION_EXPIRY_INTERVAL);
	p.session_expiry = 10;
	s.core.disconnect(s.clock.now, ReasonCode.NORMAL_DISCONNECTION, &p)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::drain(&s.core);
	s.at(10_000);
	s.core.connect(s.clock.now)!!;
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE, "ten seconds offline with an interval of ten");
	s.core.output_done(s.core.pending_output().len);
	s.close();
}

fn void seq_9_10() @test
{
	// 5.0, Session Expiry 0 and no clean start: the session ends with the connection, a reconnect starts a new one
	Session s;
	Config c = cfg(Version.V5);
	c.session_expiry = 0;
	s.open(&c, CONNACK_5);
	OutMessage m = msg(QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &m)!!;
	s.core.output_done(s.core.pending_output().len);
	lose(&s);
	s.core.connect(s.clock.now)!!;
	assert(s.core.inflight_count() == 0, "local state is cleared");
	Event ev = s.take();
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.reason == ReasonCode.UNSPECIFIED_ERROR);
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, CONNACK_5);
	assert(harness::drain(&s.core).len == 1);
	// a DISCONNECT cannot give the session a lifetime it did not have
	Properties p;
	p.set(PropId.SESSION_EXPIRY_INTERVAL);
	p.session_expiry = 60;
	assert(@catch(s.core.disconnect(s.clock.now, ReasonCode.NORMAL_DISCONNECTION, &p)) == mqtt::INVALID_ARGUMENT);
	s.close();
}

// ---- the server ends the connection ----

fn void server_disconnect_closed_event() @test
{
	Session s;
	Config c = cfg(Version.V5);
	c.session_expiry = 60;
	s.open(&c, CONNACK_5);
	char[] frame = testutil::hex("E0 01 8E");                      // 0x8E session taken over
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::SERVER_DISCONNECTED);
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.by_server && ev.closed.reason == ReasonCode.SESSION_TAKEN_OVER);
	assert(ev.closed.session_kept, "the session outlives the connection (expiry 60)");
	assert(s.core.state == State.DISCONNECTED);
	s.close();

	Session t;
	Config d = cfg(Version.V5);
	d.session_expiry = 0;
	t.open(&d, CONNACK_5);
	assert(@catch(t.core.input(t.clock.now, frame)) == mqtt::SERVER_DISCONNECTED);
	assert(!t.take().closed.session_kept);
	t.close();

	Session u;
	Config e = cfg(Version.V311, true);
	u.open(&e, CONNACK_311);
	u.core.transport_closed(u.clock.now);
	assert(!u.take().closed.session_kept, "a clean session does not outlive the connection");
	u.close();
}

fn void closed_event_after_messages() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	// two messages and a DISCONNECT in one piece: the close is reported after both messages
	char[] bytes = testutil::hex("30 07 00 03 61 2F 62 00 68 30 07 00 03 63 2F 64 00 69 E0 01 8B");
	assert(@catch(s.core.input(s.clock.now, bytes)) == mqtt::SERVER_DISCONNECTED);
	EventKind[] kinds = harness::drain(&s.core);
	assert(kinds.len == 3 && kinds[0] == EventKind.MESSAGE && kinds[1] == EventKind.MESSAGE && kinds[2] == EventKind.CLOSED);
	s.close();
}

// ---- memory ----

fn void session_cycles_do_not_leak() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	for (int cycle = 0; cycle < 200; cycle++)
	{
		OutMessage m = msg(QoS.AT_LEAST_ONCE, (char)cycle);
		s.core.publish(s.clock.now, &m)!!;
		OutMessage q = msg(QoS.EXACTLY_ONCE, (char)cycle);
		s.core.publish(s.clock.now, &q)!!;
		s.core.output_done(s.core.pending_output().len);
		s.core.transport_closed(s.clock.now);
		harness::drain(&s.core);
		reconnect(&s, "20 03 01 00 00");                         // session present: both are sent again
		s.core.output_done(s.core.pending_output().len);
		harness::drain(&s.core);
		assert(s.core.inflight_count() == 2);
		ushort id1 = (ushort)(2 * cycle + 1);
		char[4] a1 = { 0x40, 0x02, (char)(id1 >> 8), (char)(id1 & 0xFF) };
		s.core.input(s.clock.now, a1[..])!!;
		char[4] a2 = { 0x50, 0x02, (char)((id1 + 1) >> 8), (char)((id1 + 1) & 0xFF) };
		s.core.input(s.clock.now, a2[..])!!;
		char[4] a3 = { 0x70, 0x02, (char)((id1 + 1) >> 8), (char)((id1 + 1) & 0xFF) };
		s.core.input(s.clock.now, a3[..])!!;
		s.core.output_done(s.core.pending_output().len);
		harness::drain(&s.core);
		assert(s.core.inflight_count() == 0);
	}
	s.close();
}

// ---- a PUBREC for a record that has not been sent again yet ----

fn void pubrel_is_not_sent_twice_for_a_waiting_record() @test
{
	Session s;
	Config c = cfg(Version.V5);
	s.open(&c, CONNACK_5);
	OutMessage a = msg(QoS.EXACTLY_ONCE, 1);
	OutMessage b = msg(QoS.EXACTLY_ONCE, 2);
	s.core.publish(s.clock.now, &a)!!;
	s.core.publish(s.clock.now, &b)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "50 02 00 01");
	harness::feed(&s.core, &s.clock, "50 02 00 02");
	s.core.output_done(s.core.pending_output().len);
	lose(&s);
	// the new server takes one record at a time: PUBREL for the first only
	reconnect(&s, "20 06 01 00 03 21 00 01");
	harness::expect_out(&s.core, "62 02 00 01");
	// the server answers the PUBREC of the second record anyway: it gets its PUBREL once
	harness::feed(&s.core, &s.clock, "50 02 00 02");
	harness::expect_out(&s.core, "62 02 00 02");
	harness::feed(&s.core, &s.clock, "70 02 00 01");
	harness::expect_no_out(&s.core);
	assert(s.core.inflight_count() == 1);
	harness::feed(&s.core, &s.clock, "70 02 00 02");
	assert(s.core.inflight_count() == 0);
	s.close();
}
