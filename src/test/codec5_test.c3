module mqtt::codec5_test;
import mqtt, mqtt::packet, mqtt::props, mqtt::testutil, mqtt::wire;

fn char[] hx(String h) => testutil::hex(h);

fn void check_rl(char[] b)
{
	usz used;
	uint rl = wire::vbi_decode(b[1..], &used)!!;
	assert(b.len == 1 + used + rl, "remaining length matches the frame");
}

fn Packet dec(String h)
{
	char[] b = hx(h);
	check_rl(b);
	assert(packet::frame_length(b, 0)!! == b.len);
	return packet::decode(Version.V5, b)!!;
}

fn char[] enc(Packet* p)
{
	char[] buf = mem::temp_array(char, 512);
	usz n = packet::encode(Version.V5, p, buf)!!;
	assert(packet::encoded_size(Version.V5, p)!! == n, "encoded_size");
	return buf[:n];
}

// Decodes h; encoding the result gives `canonical` (h itself when empty): the encoder always
// writes the shortest form and the properties in ascending order. The canonical form decodes
// and encodes to itself.
fn Packet check5(String h, String canonical = "")
{
	Packet p = dec(h);
	char[] expected = hx(canonical.len > 0 ? canonical : h);
	assert(enc(&p) == expected, "encode(decode(bytes)) is the canonical form");
	Packet q = dec(canonical.len > 0 ? canonical : h);
	assert(enc(&q) == expected, "the canonical form is stable");
	return p;
}

fn void expect_fault(String h, fault expected)
{
	char[] b = hx(h);
	assert(@catch(packet::decode(Version.V5, b)) == expected, "wrong fault");
}

// ---- CONNECT ----

fn void vec_V_5_CONN_1() @test
{
	Packet p = check5("10 0E 00 04 4D 51 54 54 05 02 00 3C 00 00 01 61");
	Connect* c = &p.connect;
	assert(c.clean_start && c.keep_alive == 60 && c.client_id == "a" && c.props.present == 0);
}

fn void vec_V_5_CONN_2() @test
{
	Packet p = check5("10 16 00 04 4D 51 54 54 05 02 00 3C 08 11 00 00 0E 10 21 00 14 00 01 61");
	assert(p.connect.props.session_expiry == 3600 && p.connect.props.receive_maximum == 20);
	assert(p.connect.client_id == "a");

	Packet q = { .type = PacketType.CONNECT };
	q.connect.client_id = "a";
	q.connect.clean_start = true;
	q.connect.keep_alive = 60;
	q.connect.props.set(PropId.RECEIVE_MAXIMUM);
	q.connect.props.receive_maximum = 20;
	q.connect.props.set(PropId.SESSION_EXPIRY_INTERVAL);
	q.connect.props.session_expiry = 3600;
	assert(enc(&q) == hx("10 16 00 04 4D 51 54 54 05 02 00 3C 08 11 00 00 0E 10 21 00 14 00 01 61"));
}

fn void vec_V_5_CONN_3() @test
{
	Packet p = check5("10 15 00 04 4D 51 54 54 05 06 00 0A 00 00 01 63 00 00 01 77 00 01 6D");
	Connect* c = &p.connect;
	assert(c.has_will && c.will.topic == "w" && c.will.payload == hx("6D") && c.will.props.present == 0);
	assert(c.clean_start && c.client_id == "c");
}

fn void vec_V_5_CONN_4() @test
{
	Packet p = check5("10 0D 00 04 4D 51 54 54 05 02 00 3C 00 00 00");
	assert(p.connect.client_id.len == 0 && p.connect.clean_start);
	// 5.0 allows an empty client id without clean start (the server assigns one)
	Packet q = { .type = PacketType.CONNECT };
	char[32] buf;
	usz n = packet::encode(Version.V5, &q, buf[..])!!;
	assert(n == 15);
}

fn void connect_v5_extras() @test
{
	// will properties, user name, password without user name, user properties
	Packet p = { .type = PacketType.CONNECT };
	Connect* c = &p.connect;
	c.client_id = "id";
	c.clean_start = true;
	c.keep_alive = 5;
	c.has_will = true;
	c.will = { .topic = "w/t", .payload = hx("01"), .qos = QoS.EXACTLY_ONCE, .retain = true };
	c.will.props.set(PropId.WILL_DELAY_INTERVAL);
	c.will.props.will_delay = 30;
	c.will.props.set(PropId.CONTENT_TYPE);
	c.will.props.content_type = "text/plain";
	c.has_password = true;
	c.password = hx("AA BB");
	UserProperty[1] users = { { "k", "v" } };
	c.props.user = users[..];
	c.props.set(PropId.REQUEST_PROBLEM_INFORMATION);
	c.props.request_problem_info = 0;
	char[] bytes = enc(&p);
	Packet d = packet::decode(Version.V5, bytes)!!;
	assert(d.connect.has_will && d.connect.will.props.will_delay == 30 && d.connect.will.props.content_type == "text/plain");
	assert(d.connect.will.qos == QoS.EXACTLY_ONCE && d.connect.will.retain);
	assert(!d.connect.has_username && d.connect.has_password && d.connect.password == hx("AA BB"));
	assert(d.connect.props.request_problem_info == 0);
	UserPropIter it = d.connect.props.user_props();
	UserProperty u;
	assert(it.next(&u)!! && u.key == "k" && u.value == "v");
	// decoded struct encodes to the same bytes (user properties come from the raw block)
	assert(enc(&d) == bytes);
}

fn void connect_version_mismatch() @test
{
	assert(@catch(packet::decode(Version.V311, hx("10 0E 00 04 4D 51 54 54 05 02 00 3C 00 00 01 61"))) == mqtt::UNSUPPORTED_VERSION);
	assert(@catch(packet::decode(Version.V5, hx("10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61"))) == mqtt::UNSUPPORTED_VERSION);
}

// ---- CONNACK ----

fn void vec_V_5_CONNACK_1() @test
{
	Packet p = check5("20 03 00 00 00");
	assert(!p.connack.session_present && p.connack.code == 0);
}

fn void vec_V_5_CONNACK_2() @test
{
	Packet p = check5("20 03 01 00 00");
	assert(p.connack.session_present);
}

fn void vec_V_5_CONNACK_3() @test
{
	// properties arrive in any order; the encoder writes them in ascending order
	Packet p = check5("20 09 00 00 06 22 00 0A 13 00 1E", "20 09 00 00 06 13 00 1E 22 00 0A");
	assert(p.connack.props.topic_alias_maximum == 10 && p.connack.props.server_keep_alive == 30);
}

fn void vec_V_5_CONNACK_4() @test
{
	Packet p = check5("20 07 00 9C 04 1C 00 01 62");
	assert(p.connack.code == 0x9C && p.connack.props.server_reference == "b");
}

fn void vec_V_5_CONNACK_5() @test
{
	Packet p = check5("20 03 00 87 00");
	assert(p.connack.code == 0x87);
}

fn void connack_v5_rules() @test
{
	expect_fault("20 02 00 00", mqtt::MALFORMED_PACKET);          // the property length is required
	expect_fault("20 03 01 87 00", mqtt::MALFORMED_PACKET);       // session present with a refusal
	expect_fault("20 03 02 00 00", mqtt::MALFORMED_PACKET);       // reserved flag bits
	expect_fault("20 03 00 8B 00", mqtt::MALFORMED_PACKET);       // 0x8B is not a CONNACK reason
	expect_fault("20 03 00 01 00", mqtt::MALFORMED_PACKET);       // granted QoS is not a CONNACK reason
	expect_fault("20 04 00 00 00 00", mqtt::MALFORMED_PACKET);    // trailing byte
}

// ---- PUBLISH ----

fn void vec_V_5_PUB_1() @test
{
	Packet p = check5("30 08 00 03 61 2F 62 00 68 69");
	assert(p.publish.topic == "a/b" && p.publish.payload == hx("68 69") && p.publish.props.present == 0);
}

fn void vec_V_5_PUB_2() @test
{
	Packet p = check5("32 09 00 00 00 01 03 23 00 01 78");
	assert(p.publish.topic.len == 0 && p.publish.packet_id == 1 && p.publish.props.topic_alias == 1 && p.publish.payload == hx("78"));
}

fn void vec_V_5_PUB_3() @test
{
	Packet p = check5("32 0A 00 01 61 00 01 03 23 00 01 78");
	assert(p.publish.topic == "a" && p.publish.props.topic_alias == 1);
}

fn void vec_V_5_PUB_4() @test
{
	Packet p = check5("30 06 00 01 61 02 0B 05");
	assert(p.publish.payload.len == 0);
	SubIdIter it = p.publish.props.subscription_id_iter();
	uint v;
	assert(it.next(&v)!! && v == 5);
}

fn void publish_v5_encode_rules() @test
{
	char[64] buf;
	Packet p = { .type = PacketType.PUBLISH };
	p.publish = { .topic = "" };
	assert(@catch(packet::encode(Version.V5, &p, buf[..])) == mqtt::INVALID_TOPIC_NAME, "empty topic needs an alias");
	p.publish.props.set(PropId.TOPIC_ALIAS);
	p.publish.props.topic_alias = 4;
	assert(packet::encode(Version.V5, &p, buf[..])!! == 1 + 1 + 2 + 4);
	p.publish = { .topic = "t" };
	p.publish.props.set(PropId.SESSION_EXPIRY_INTERVAL);
	p.publish.props.session_expiry = 1;
	assert(@catch(packet::encode(Version.V5, &p, buf[..])) == mqtt::INVALID_PROPERTY, "not a PUBLISH property");
	p.publish = { .topic = "t" };
	p.publish.props.set(PropId.TOPIC_ALIAS);                               // value 0
	assert(@catch(packet::encode(Version.V5, &p, buf[..])) == mqtt::INVALID_PROPERTY);
}

// publish with user properties, content type and several subscription identifiers re-encodes identically
fn void publish_v5_properties_roundtrip() @test
{
	String h = "30 28 00 01 74 22 01 01 03 00 0A 74 65 78 74 2F 70 6C 61 69 6E 0B 05 0B 80 01 26 00 01 6B 00 01 76 26 00 01 6B 00 01 77 61 62";
	Packet p = check5(h);
	assert(p.publish.props.payload_format == 1 && p.publish.props.content_type == "text/plain");
	assert(p.publish.payload == hx("61 62"));
}

// ---- acknowledgements (short forms) ----

fn void vec_V_5_PUBACK_1() @test
{
	Packet p = check5("40 02 00 0A");
	assert(p.type == PacketType.PUBACK && p.ack.packet_id == 10 && p.ack.reason == 0);
}

fn void vec_V_5_PUBACK_2() @test
{
	Packet p = check5("40 03 00 0A 00", "40 02 00 0A");
	assert(p.ack.reason == 0);
}

fn void vec_V_5_PUBACK_3() @test
{
	Packet p = check5("40 04 00 0A 10 00", "40 03 00 0A 10");
	assert(p.ack.reason == 0x10);
}

fn void vec_V_5_PUBACK_4() @test
{
	Packet p = check5("40 04 00 0A 87 00", "40 03 00 0A 87");
	assert(p.ack.reason == 0x87);
}

fn void vec_V_5_PUBREC_1() @test
{
	Packet p = check5("50 04 00 0A 97 00", "50 03 00 0A 97");
	assert(p.type == PacketType.PUBREC && p.ack.reason == 0x97);
}

fn void vec_V_5_PUBREL_1() @test
{
	Packet p = check5("62 02 00 0A");
	assert(p.type == PacketType.PUBREL && p.ack.reason == 0);
}

fn void vec_V_5_PUBREL_2() @test
{
	Packet p = check5("62 03 00 0A 92");
	assert(p.ack.reason == 0x92);
}

fn void vec_V_5_PUBCOMP_1() @test
{
	Packet p = check5("70 02 00 0A");
	assert(p.type == PacketType.PUBCOMP);
}

fn void vec_V_5_PUBCOMP_2() @test
{
	Packet p = check5("70 03 00 0A 92");
	assert(p.ack.reason == 0x92);
}

fn void ack_with_reason_string_keeps_the_long_form() @test
{
	// a reason string makes the properties part necessary
	Packet p = check5("40 09 00 0A 87 05 1F 00 02 6F 6B");
	assert(p.ack.reason == 0x87 && p.ack.props.reason_string == "ok");
	Packet q = check5("40 09 00 0A 00 05 1F 00 02 6F 6B");
	assert(q.ack.reason == 0 && q.ack.props.reason_string == "ok");
}

fn void ack_reason_tables() @test
{
	expect_fault("40 03 00 0A 92", mqtt::MALFORMED_PACKET);        // 0x92 belongs to PUBREL / PUBCOMP
	expect_fault("62 03 00 0A 10", mqtt::MALFORMED_PACKET);        // 0x10 belongs to PUBACK / PUBREC
	expect_fault("50 03 00 0A 01", mqtt::MALFORMED_PACKET);
	expect_fault("40 02 00 00", mqtt::MALFORMED_PACKET);           // packet id 0
	expect_fault("40 01 00", mqtt::MALFORMED_PACKET);
	char[16] buf;
	Packet p = { .type = PacketType.PUBREL, .ack = { .packet_id = 1, .reason = 0x10 } };
	assert(@catch(packet::encode(Version.V5, &p, buf[..])) == mqtt::INVALID_ARGUMENT);
}

// ---- SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK ----

fn void vec_V_5_SUB_1() @test
{
	Packet p = check5("82 09 00 01 00 00 03 61 2F 23 01");
	usz cursor;
	SubEntry e;
	assert(p.subscribe.next(&cursor, Version.V5, &e)!!);
	assert(e.filter == "a/#" && e.qos == QoS.AT_LEAST_ONCE && !e.no_local && !e.retain_as_published && e.retain_handling == 0);
}

fn void vec_V_5_SUB_2() @test
{
	Packet p = check5("82 0B 00 01 02 0B 05 00 03 61 2F 23 01");
	SubIdIter it = p.subscribe.props.subscription_id_iter();
	uint v;
	assert(it.next(&v)!! && v == 5);
}

fn void vec_V_5_SUB_3() @test
{
	Packet p = check5("82 09 00 01 00 00 03 61 2F 23 2E");
	usz cursor;
	SubEntry e;
	assert(p.subscribe.next(&cursor, Version.V5, &e)!!);
	assert(e.qos == QoS.EXACTLY_ONCE && e.no_local && e.retain_as_published && e.retain_handling == 2);

	Packet q = { .type = PacketType.SUBSCRIBE };
	SubEntry[1] entries = { { .filter = "a/#", .qos = QoS.EXACTLY_ONCE, .no_local = true, .retain_as_published = true, .retain_handling = 2 } };
	q.subscribe = { .packet_id = 1, .entries = entries[..] };
	assert(enc(&q) == hx("82 09 00 01 00 00 03 61 2F 23 2E"));
}

fn void vec_V_5_SUBACK_1() @test
{
	Packet p = check5("90 04 00 01 00 01");
	assert(p.suback.packet_id == 1 && p.suback.codes == hx("01"));
}

fn void vec_V_5_SUBACK_2() @test
{
	Packet p = check5("90 05 00 01 00 02 8F");
	assert(p.suback.codes == hx("02 8F"));
}

fn void vec_V_5_SUBACK_3() @test
{
	Packet p = check5("90 04 00 01 00 9E");
	assert(p.suback.codes == hx("9E"));
}

fn void vec_V_5_UNSUB() @test
{
	Packet p = check5("A2 08 00 02 00 00 03 61 2F 23");
	usz cursor;
	String f;
	assert(p.unsubscribe.next(&cursor, &f)!! && f == "a/#");
}

fn void vec_V_5_UNSUBACK_1() @test
{
	Packet p = check5("B0 04 00 02 00 00");
	assert(p.type == PacketType.UNSUBACK && p.suback.packet_id == 2 && p.suback.codes == hx("00"));
}

fn void vec_V_5_UNSUBACK_2() @test
{
	Packet p = check5("B0 04 00 02 00 11");
	assert(p.suback.codes == hx("11"));
}

fn void sub_unsub_more_rules() @test
{
	expect_fault("90 04 00 01 00 8B", mqtt::MALFORMED_PACKET);          // not a SUBACK reason
	expect_fault("B0 04 00 02 00 01", mqtt::MALFORMED_PACKET);          // granted QoS is not an UNSUBACK reason
	expect_fault("B0 03 00 02 00", mqtt::MALFORMED_PACKET);             // no reason code
	expect_fault("82 02 00 01", mqtt::MALFORMED_PACKET);
	expect_fault("82 03 00 01 00", mqtt::MALFORMED_PACKET);             // no filter
	expect_fault("A2 03 00 02 00", mqtt::MALFORMED_PACKET);
	// the same SUBSCRIBE bytes mean something else in 3.1.1: its option byte has reserved bits set there
	assert(@catch(packet::decode(Version.V311, hx("82 08 00 01 00 03 61 2F 23 2E"))) == mqtt::MALFORMED_PACKET);
	char[16] buf;
	Packet p = { .type = PacketType.SUBSCRIBE };
	SubEntry[1] entries = { { .filter = "a", .retain_handling = 3 } };
	p.subscribe = { .packet_id = 1, .entries = entries[..] };
	assert(@catch(packet::encode(Version.V5, &p, buf[..])) == mqtt::INVALID_ARGUMENT);
}

// ---- DISCONNECT, AUTH, PING ----

fn void vec_V_5_DISC_1() @test
{
	Packet p = check5("E0 00");
	assert(p.type == PacketType.DISCONNECT && p.disconnect.reason == 0);
}

fn void vec_V_5_DISC_2() @test
{
	Packet p = check5("E0 01 04");
	assert(p.disconnect.reason == 0x04);
}

fn void vec_V_5_DISC_3() @test
{
	Packet p = check5("E0 02 04 00", "E0 01 04");
	assert(p.disconnect.reason == 0x04);
}

fn void vec_V_5_DISC_4() @test
{
	Packet p = check5("E0 0B 9C 09 1C 00 06 68 6F 73 74 3A 31");
	assert(p.disconnect.reason == 0x9C && p.disconnect.props.server_reference == "host:1");
}

fn void disconnect_more() @test
{
	// session expiry in DISCONNECT, with reason 0 the properties still need the reason byte
	Packet p = check5("E0 07 00 05 11 00 00 00 3C");
	assert(p.disconnect.reason == 0 && p.disconnect.props.session_expiry == 60);
	expect_fault("E0 01 10", mqtt::MALFORMED_PACKET);           // 0x10 is not a DISCONNECT reason
	expect_fault("E1 00", mqtt::MALFORMED_PACKET);
}

fn void vec_V_5_AUTH_1() @test
{
	Packet p = check5("F0 06 18 04 15 00 01 61");
	assert(p.type == PacketType.AUTH && p.auth.reason == 0x18 && p.auth.props.auth_method == "a");
}

fn void vec_V_5_AUTH_2() @test
{
	Packet p = check5("F0 00");
	assert(p.auth.reason == 0);
}

fn void vec_V_FR_N2_v5_half() @test
{
	// type 15 is AUTH in 5.0 (and reserved in 3.1.1)
	assert(dec("F0 00").type == PacketType.AUTH);
	assert(@catch(packet::decode(Version.V311, hx("F0 00"))) == mqtt::PROTOCOL_ERROR);
	expect_fault("F1 00", mqtt::MALFORMED_PACKET);
	expect_fault("F0 01 05", mqtt::MALFORMED_PACKET);           // 0x05 is not an AUTH reason
	char[8] buf;
	Packet p = { .type = PacketType.AUTH };
	assert(@catch(packet::encode(Version.V311, &p, buf[..])) == mqtt::INVALID_ARGUMENT);
}

fn void vec_V_5_PING() @test
{
	assert(check5("C0 00").type == PacketType.PINGREQ);
	assert(check5("D0 00").type == PacketType.PINGRESP);
}

// ---- malformed 5.0 packets (the property-block faults framed in their packets) ----

fn void vec_V_5_N1() @test { expect_fault("20 0D 00 00 0A 11 00 00 00 0A 11 00 00 00 0B", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N2() @test { expect_fault("20 05 00 00 02 04 00", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N3() @test { expect_fault("20 03 00 00 05", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N4() @test { expect_fault("20 05 00 00 02 0B 01", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N5() @test { expect_fault("20 06 00 00 03 21 00 00", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N6() @test { expect_fault("20 05 00 00 02 24 02", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N7() @test { expect_fault("20 05 00 00 02 25 02", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N8() @test { expect_fault("20 07 00 00 04 1F 00 05 61", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N9() @test { expect_fault("20 07 00 00 80 80 80 80 01", mqtt::MALFORMED_PACKET); }
// the vector says MALFORMED; the cause is reported, as for strings in 3.1.1
fn void vec_V_5_N10() @test { expect_fault("20 07 00 00 04 12 00 01 FF", mqtt::INVALID_UTF8); }
fn void vec_V_5_N11() @test { expect_fault("20 07 00 00 04 13 00 1E 00", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N12() @test { expect_fault("30 07 00 01 61 03 23 00 00", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N13() @test { expect_fault("30 06 00 01 61 02 0B 00", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N14() @test { expect_fault("30 06 00 01 61 02 01 02", mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N15() @test { expect_fault("30 03 00 00 00", mqtt::PROTOCOL_ERROR); }
fn void vec_V_5_N16() @test { expect_fault("30 05 00 01 61 04 01", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N17() @test { expect_fault("40 05 00 0A 00 00 FF", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N18() @test { expect_fault("40 04 00 0A 00 05", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N19() @test { expect_fault("90 03 00 01 00", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N20() @test { expect_fault("90 04 00 01 00 03", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N21() @test { expect_fault("82 09 00 01 00 00 03 61 2F 23 30", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N22() @test { expect_fault("82 09 00 01 00 00 03 61 2F 23 C1", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N23() @test { expect_fault("82 09 00 01 00 00 03 61 2F 23 03", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N24() @test { expect_fault("E0 02 04 80", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N25() @test { expect_fault("F0 02 18 05", mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N27() @test { expect_fault("E0 03 04 01 00", mqtt::MALFORMED_PACKET); }

// ---- every packet type, both directions ----

fn void all_15_types_round_trip() @test
{
	SubEntry[1] entries = { { .filter = "a/b", .qos = QoS.EXACTLY_ONCE, .no_local = true, .retain_handling = 1 } };
	String[1] filters = { "a/b" };
	char[2] sub_codes = { 2, 0x8F };
	char[1] unsub_codes = { 0x11 };
	UserProperty[2] users = { { "k", "v" }, { "k2", "v2" } };
	int seen;
	for (char t = 1; t <= 15; t++)
	{
		Packet p;
		p.type = (PacketType)t;
		switch (t)
		{
			case 1:
				p.connect = { .client_id = "id", .clean_start = true, .keep_alive = 30 };
				p.connect.props.user = users[..];
			case 2:
				p.connack = { .session_present = true, .code = 0 };
				p.connack.props.set(PropId.SERVER_KEEP_ALIVE);
				p.connack.props.server_keep_alive = 15;
			case 3:
				p.publish = { .qos = QoS.AT_LEAST_ONCE, .topic = "t", .packet_id = 9, .payload = hx("01 02") };
				p.publish.props.user = users[..];
			case 4:
			case 5:
			case 6:
			case 7:
				p.ack = { .packet_id = 77 };
				p.ack.props.set(PropId.REASON_STRING);
				p.ack.props.reason_string = "why";
			case 8:
				p.subscribe = { .packet_id = 3, .entries = entries[..] };
				p.subscribe.props.user = users[..];
			case 9:
				p.suback = { .packet_id = 3, .codes = sub_codes[..] };
			case 10:
				p.unsubscribe = { .packet_id = 4, .filters = filters[..] };
			case 11:
				p.suback = { .packet_id = 4, .codes = unsub_codes[..] };
			case 14:
				p.disconnect = { .reason = 0x04 };
				p.disconnect.props.set(PropId.REASON_STRING);
				p.disconnect.props.reason_string = "bye";
			case 15:
				p.auth = { .reason = 0x19 };
				p.auth.props.set(PropId.AUTHENTICATION_METHOD);
				p.auth.props.auth_method = "m";
			default: break;
		}
		char[] a = enc(&p);
		Packet d = packet::decode(Version.V5, a)!!;
		assert(d.type == p.type);
		assert(enc(&d) == a, "decoded packet re-encodes to the same bytes, user properties included");
		seen++;
	}
	assert(seen == 15);
}

// ---- reason code helpers ----

fn void reason_tables_spot_checks() @test
{
	assert(packet::reason_allowed(PacketType.CONNACK, 0x00));
	assert(packet::reason_allowed(PacketType.CONNACK, 0x9F));
	assert(!packet::reason_allowed(PacketType.CONNACK, 0x01));
	assert(packet::reason_allowed(PacketType.PUBACK, 0x10));
	assert(!packet::reason_allowed(PacketType.PUBACK, 0x92));
	assert(packet::reason_allowed(PacketType.PUBCOMP, 0x92));
	assert(packet::reason_allowed(PacketType.SUBACK, 0x02));
	assert(!packet::reason_allowed(PacketType.SUBACK, 0x03));
	assert(packet::reason_allowed(PacketType.UNSUBACK, 0x11));
	assert(packet::reason_allowed(PacketType.DISCONNECT, 0x04));
	assert(packet::reason_allowed(PacketType.DISCONNECT, 0x8E));
	assert(!packet::reason_allowed(PacketType.DISCONNECT, 0x10));
	assert(packet::reason_allowed(PacketType.AUTH, 0x18));
	assert(!packet::reason_allowed(PacketType.AUTH, 0x80));
	assert(!packet::reason_allowed(PacketType.PINGREQ, 0x00));
}

fn void reason_code_names() @test
{
	assert(ReasonCode.SUCCESS.describe() == "Success");
	assert(ReasonCode.NOT_AUTHORIZED.describe() == "Not authorized");
	assert(ReasonCode.USE_ANOTHER_SERVER.describe() == "Use another server");
	assert(ReasonCode.WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED.describe() == "Wildcard Subscriptions not supported");
	assert(((ReasonCode)0x03).describe() == "Unknown reason code");
	assert(((ReasonCode)0xFF).describe() == "Unknown reason code");
	// every code the table of reasons defines has its own name
	char[*] defined = { 0x00, 0x01, 0x02, 0x04, 0x10, 0x11, 0x18, 0x19, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2 };
	foreach (c : defined) assert(((ReasonCode)c).describe() != "Unknown reason code");
}

fn void connack311_mapping() @test
{
	assert(mqtt::connack311_to_reason(ConnAckCode311.ACCEPTED) == ReasonCode.SUCCESS);
	assert(mqtt::connack311_to_reason(ConnAckCode311.UNACCEPTABLE_PROTOCOL_VERSION) == ReasonCode.UNSUPPORTED_PROTOCOL_VERSION);
	assert(mqtt::connack311_to_reason(ConnAckCode311.IDENTIFIER_REJECTED) == ReasonCode.CLIENT_ID_NOT_VALID);
	assert(mqtt::connack311_to_reason(ConnAckCode311.SERVER_UNAVAILABLE) == ReasonCode.SERVER_UNAVAILABLE);
	assert(mqtt::connack311_to_reason(ConnAckCode311.BAD_USER_NAME_OR_PASSWORD) == ReasonCode.BAD_USER_NAME_OR_PASSWORD);
	assert(mqtt::connack311_to_reason(ConnAckCode311.NOT_AUTHORIZED) == ReasonCode.NOT_AUTHORIZED);
}
