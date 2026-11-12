module mqtt::core_alias_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::props, mqtt::testutil;

const String CONNACK_ALIAS_1 = "20 06 00 00 03 22 00 01";            // the server takes one alias
const String CONNACK_ALIAS_2 = "20 06 00 00 03 22 00 02";
const String CONNACK_5 = "20 03 00 00 00";
const String CONNACK_ALIAS_1_SESSION = "20 06 01 00 03 22 00 01";

fn Config cfg()
{
	return core::default_config(Version.V5, "a");
}

fn OutMessage msg(String topic, QoS qos, ushort alias_no)
{
	OutMessage m = { .topic = topic, .payload = testutil::hex("78"), .qos = qos };
	if (alias_no != 0)
	{
		m.props.set(PropId.TOPIC_ALIAS);
		m.props.topic_alias = alias_no;
	}
	return m;
}

fn void lose(Session* s)
{
	s.core.transport_closed(s.clock.now);
	harness::drain(&s.core);
}

fn void reconnect(Session* s, String connack_hex)
{
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, connack_hex);
	harness::drain(&s.core);
}

// ---- outbound ----

fn void seq_9_7() @test
{
	Session s;
	Config c = cfg();
	s.open(&c, CONNACK_ALIAS_1);
	// the first use sends the topic and sets the alias, the next uses leave the topic out
	OutMessage a = msg("a", QoS.AT_LEAST_ONCE, 1);
	assert(s.core.publish(s.clock.now, &a)!! == 1);
	harness::expect_out(&s.core, "32 0A 00 01 61 00 01 03 23 00 01 78");
	assert(s.core.publish(s.clock.now, &a)!! == 2);
	harness::expect_out(&s.core, "32 09 00 00 00 02 03 23 00 01 78");
	// an alias above the server's maximum, or 0, is refused here
	OutMessage two = msg("a", QoS.AT_LEAST_ONCE, 2);
	assert(@catch(s.core.publish(s.clock.now, &two)) == mqtt::NOT_SUPPORTED_BY_SERVER);
	OutMessage zero = msg("a", QoS.AT_LEAST_ONCE, 0);
	zero.props.set(PropId.TOPIC_ALIAS);
	assert(@catch(s.core.publish(s.clock.now, &zero)) == mqtt::INVALID_PROPERTY);
	assert(s.core.pending_output().len == 0 && s.core.inflight_count() == 2);
	// the same alias for another topic rebinds it, and back again
	OutMessage b = msg("b", QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &b)!!;
	harness::expect_out(&s.core, "32 0A 00 01 62 00 03 03 23 00 01 78");
	s.core.publish(s.clock.now, &a)!!;
	harness::expect_out(&s.core, "32 0A 00 01 61 00 04 03 23 00 01 78");
	s.close();
}

fn void alias_out_explicit() @test
{
	Session s;
	Config c = cfg();
	s.open(&c, CONNACK_ALIAS_2);
	OutMessage a1 = msg("a", QoS.AT_MOST_ONCE, 1);
	OutMessage b2 = msg("b", QoS.AT_MOST_ONCE, 2);
	s.core.publish(s.clock.now, &a1)!!;
	s.core.publish(s.clock.now, &b2)!!;
	s.core.publish(s.clock.now, &a1)!!;
	s.core.publish(s.clock.now, &b2)!!;
	harness::expect_out(&s.core, "30 08 00 01 61 03 23 00 01 78 30 08 00 01 62 03 23 00 02 78 30 07 00 00 03 23 00 01 78 30 07 00 00 03 23 00 02 78");
	// a message without an alias is sent as it is, and does not disturb the bindings
	OutMessage plain = msg("a", QoS.AT_MOST_ONCE, 0);
	s.core.publish(s.clock.now, &plain)!!;
	harness::expect_out(&s.core, "30 05 00 01 61 00 78");
	s.core.publish(s.clock.now, &a1)!!;
	harness::expect_out(&s.core, "30 07 00 00 03 23 00 01 78");
	s.close();
}

fn void alias_out_server_max_zero() @test
{
	Session s;
	Config c = cfg();
	c.auto_topic_alias = true;
	s.open(&c, CONNACK_5);                                        // the server offers no aliases
	OutMessage a = msg("a", QoS.AT_MOST_ONCE, 1);
	assert(@catch(s.core.publish(s.clock.now, &a)) == mqtt::NOT_SUPPORTED_BY_SERVER);
	OutMessage plain = msg("a", QoS.AT_MOST_ONCE, 0);
	s.core.publish(s.clock.now, &plain)!!;
	harness::expect_out(&s.core, "30 05 00 01 61 00 78");           // no alias on its own either
	s.close();
}

fn void alias_out_lru() @test
{
	Session s;
	Config c = cfg();
	c.auto_topic_alias = true;
	s.open(&c, CONNACK_ALIAS_2);
	String[6] topics = { "a", "b", "a", "c", "a", "b" };
	String[6] expected = {
		"30 07 00 01 61 03 23 00 01",       // a: new, alias 1
		"30 07 00 01 62 03 23 00 02",       // b: new, alias 2
		"30 06 00 00 03 23 00 01",          // a: bound, only the alias
		"30 07 00 01 63 03 23 00 02",       // c: the table is full, b is the least recently used: alias 2 is reused
		"30 06 00 00 03 23 00 01",          // a: still bound
		"30 07 00 01 62 03 23 00 02",       // b: gone, c (used before a) gives up alias 2
	};
	for (usz i = 0; i < 6; i++)
	{
		s.at((long)i * 1000);
		OutMessage m = { .topic = topics[i], .qos = QoS.AT_MOST_ONCE };
		s.core.publish(s.clock.now, &m)!!;
		harness::expect_out(&s.core, expected[i]);
	}
	s.close();
}

fn void alias_reset_on_reconnect() @test
{
	Session s;
	Config c = cfg();
	c.auto_topic_alias = true;
	s.open(&c, CONNACK_ALIAS_1);
	OutMessage m = { .topic = "a", .qos = QoS.AT_MOST_ONCE };
	s.core.publish(s.clock.now, &m)!!;
	harness::expect_out(&s.core, "30 07 00 01 61 03 23 00 01");
	s.core.publish(s.clock.now, &m)!!;
	harness::expect_out(&s.core, "30 06 00 00 03 23 00 01");
	lose(&s);
	reconnect(&s, CONNACK_ALIAS_1);
	s.core.publish(s.clock.now, &m)!!;
	harness::expect_out(&s.core, "30 07 00 01 61 03 23 00 01");      // the new connection starts without bindings
	s.close();
}

fn void alias_resend_full_topic() @test
{
	Session s;
	Config c = cfg();
	c.clean_start = false;
	c.session_expiry = 3600;
	s.open(&c, CONNACK_ALIAS_1);
	OutMessage a = msg("a", QoS.AT_LEAST_ONCE, 1);
	s.core.publish(s.clock.now, &a)!!;
	s.core.publish(s.clock.now, &a)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "40 02 00 01");              // the first message, which bound the alias, is done
	harness::drain(&s.core);
	lose(&s);
	// the second one was sent with the alias only; on the new connection nothing is bound, so it goes out in full
	reconnect(&s, CONNACK_ALIAS_1_SESSION);
	harness::expect_out(&s.core, "3A 0A 00 01 61 00 02 03 23 00 01 78");
	s.close();
}

// ---- inbound ----

fn void alias_in_rebind_keeps_event_topic() @test
{
	Session s;
	Config c = cfg();
	c.topic_alias_maximum = 2;
	s.open(&c, CONNACK_5);
	// bind, use, rebind, use: all four in one piece, nothing taken in between
	harness::feed(&s.core, &s.clock, "30 09 00 03 61 2F 62 03 23 00 01 30 06 00 00 03 23 00 01 30 09 00 03 63 2F 64 03 23 00 01 30 06 00 00 03 23 00 01");
	String[4] expected = { "a/b", "a/b", "c/d", "c/d" };
	for (usz i = 0; i < 4; i++)
	{
		Event ev = s.take();
		assert(ev.kind == EventKind.MESSAGE && ev.message.topic == expected[i], "the topic the packet had when it arrived");
	}
	s.close();
}

fn void alias_in_qos1_resolved() @test
{
	Session s;
	Config c = cfg();
	c.topic_alias_maximum = 1;
	s.open(&c, CONNACK_5);
	harness::feed(&s.core, &s.clock, "30 09 00 03 61 2F 62 03 23 00 01");
	s.take();
	harness::feed(&s.core, &s.clock, "32 08 00 00 00 05 03 23 00 01");
	harness::expect_out(&s.core, "40 02 00 05");
	Event ev = s.take();
	assert(ev.message.topic == "a/b" && ev.message.packet_id == 5 && ev.message.qos == QoS.AT_LEAST_ONCE);
	s.close();
}

fn void alias_in_zero_0x94() @test
{
	Session s;
	Config c = cfg();
	c.topic_alias_maximum = 2;
	s.open(&c, CONNACK_5);
	char[] frame = testutil::hex("30 07 00 01 61 03 23 00 00");        // Topic Alias 0
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::TOPIC_ALIAS_INVALID);
	harness::expect_out(&s.core, "E0 01 94");
	s.close();
}

fn void alias_in_over_max() @test
{
	Session s;
	Config c = cfg();
	c.topic_alias_maximum = 2;
	s.open(&c, CONNACK_5);
	char[] frame = testutil::hex("30 07 00 01 61 03 23 00 03");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::TOPIC_ALIAS_INVALID);
	harness::expect_out(&s.core, "E0 01 94");
	s.close();
	// we accept none unless we asked for some
	Session t;
	Config d = cfg();
	t.open(&d, CONNACK_5);
	char[] one = testutil::hex("30 07 00 01 61 03 23 00 01");
	assert(@catch(t.core.input(t.clock.now, one)) == mqtt::TOPIC_ALIAS_INVALID);
	t.close();
}

fn void alias_in_empty_topic_no_alias() @test
{
	Session s;
	Config c = cfg();
	c.topic_alias_maximum = 2;
	s.open(&c, CONNACK_5);
	char[] none = testutil::hex("30 03 00 00 00");                       // no topic and no alias
	assert(@catch(s.core.input(s.clock.now, none)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&s.core, "E0 01 82");
	s.close();
	// an alias that was never bound
	Session t;
	t.mem_track.init(mem);
	t.core.init(&t.mem_track, &c)!!;
	t.core.connect(t.clock.now)!!;
	t.core.output_done(t.core.pending_output().len);
	harness::feed(&t.core, &t.clock, CONNACK_5);
	harness::drain(&t.core);
	char[] unknown = testutil::hex("30 06 00 00 03 23 00 01");
	assert(@catch(t.core.input(t.clock.now, unknown)) == mqtt::TOPIC_ALIAS_INVALID);
	harness::expect_out(&t.core, "E0 01 94");
	t.close();
}

fn void alias_in_reset_on_reconnect() @test
{
	Session s;
	Config c = cfg();
	c.topic_alias_maximum = 1;
	s.open(&c, CONNACK_5);
	harness::feed(&s.core, &s.clock, "30 09 00 03 61 2F 62 03 23 00 01");
	harness::drain(&s.core);
	lose(&s);
	reconnect(&s, CONNACK_5);
	char[] only_alias = testutil::hex("30 06 00 00 03 23 00 01");
	assert(@catch(s.core.input(s.clock.now, only_alias)) == mqtt::TOPIC_ALIAS_INVALID, "the binding of the old connection is gone");
	s.close();
}
