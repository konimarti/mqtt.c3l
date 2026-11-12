module mqtt::codec311_test;
import mqtt, mqtt::packet, mqtt::testutil, mqtt::wire;

// ---- helpers ----

fn char[] hx(String h) => testutil::hex(h);

// A complete frame is 1 + (bytes of the remaining length) + remaining length.
fn void check_rl(char[] b)
{
	usz used;
	uint rl = wire::vbi_decode(b[1..], &used)!!;
	assert(b.len == 1 + used + rl, "remaining length matches the frame");
}

fn Packet dec(char[] b)
{
	check_rl(b);
	assert(packet::frame_length(b, 0)!! == b.len, "frame_length equals the frame");
	return packet::decode(Version.V311, b)!!;
}

fn void expect_fault(char[] b, fault expected)
{
	fault f = @catch(packet::decode(Version.V311, b));
	assert(f == expected, "wrong fault");
}

// decode(bytes) re-encodes to the same bytes, and the size function agrees.
fn Packet roundtrip(char[] b)
{
	Packet p = dec(b);
	char[400] buf;
	usz n = packet::encode(Version.V311, &p, buf[..])!!;
	assert(buf[:n] == b, "encode(decode(bytes)) == bytes");
	assert(packet::encoded_size(Version.V311, &p)!! == b.len, "encoded_size");
	return p;
}

fn void expect_encode_fault(Packet* p, fault expected)
{
	char[64] buf;
	fault f = @catch(packet::encode(Version.V311, p, buf[..]));
	assert(f == expected, "wrong encode fault");
}

// ---- framing ----

fn void vec_V_FR_4() @test
{
	assert(packet::frame_length(hx("30"), 0)!! == 0);
	assert(packet::frame_length({}, 0)!! == 0, "empty input needs more");
}

fn void vec_V_FR_5() @test
{
	assert(packet::frame_length(hx("30 07 00 03 61"), 0)!! == 0);
}

fn void vec_V_FR_6() @test
{
	char[] b = hx("30 07 00 03 61 2F 62 68 69 C0 00");
	usz n = packet::frame_length(b, 0)!!;
	assert(n == 9);
	Packet p = packet::decode(Version.V311, b[:n])!!;
	assert(p.type == PacketType.PUBLISH);
	assert(p.publish.topic == "a/b");
	assert(p.publish.payload == hx("68 69"));
	assert(packet::frame_length(b[n..], 0)!! == 2, "the second packet starts right after");
}

fn void vec_V_FR_N1() @test
{
	assert(@catch(packet::frame_length(hx("00 00"), 0)) == mqtt::MALFORMED_PACKET);
	expect_fault(hx("00 00"), mqtt::MALFORMED_PACKET);
}

fn void vec_V_FR_N3() @test { expect_fault(hx("60 02 00 0A"), mqtt::MALFORMED_PACKET); }
fn void vec_V_FR_N6() @test { expect_fault(hx("41 02 00 0A"), mqtt::MALFORMED_PACKET); }

fn void vec_V_FR_N9() @test
{
	assert(@catch(packet::frame_length(hx("30 FF FF FF FF 01"), 0)) == mqtt::MALFORMED_PACKET);
	// the bad length is rejected as soon as the fourth byte still has the continuation bit
	assert(@catch(packet::frame_length(hx("30 FF FF FF FF"), 0)) == mqtt::MALFORMED_PACKET);
	expect_fault(hx("30 FF FF FF FF 01"), mqtt::MALFORMED_PACKET);
}

fn void vec_V_FR_N10() @test
{
	// three bytes are enough: the 1000-byte body is not needed to reject
	assert(@catch(packet::frame_length(hx("30 E8 07"), 100)) == mqtt::PACKET_TOO_LARGE);
	// the frame is exactly 1003 bytes: 1003 passes, 1002 does not
	assert(@catch(packet::frame_length(hx("30 E8 07"), 1002)) == mqtt::PACKET_TOO_LARGE);
	assert(packet::frame_length(hx("30 E8 07"), 1003)!! == 0, "within the limit, body still missing");
	assert(packet::frame_length(hx("30 E8 07"), 0)!! == 0, "no limit");
}

fn void vec_V_FR_N11() @test { expect_fault(hx("20 03 00 00 00"), mqtt::MALFORMED_PACKET); }

fn void framing_more() @test
{
	assert(@catch(packet::frame_length(hx("30 80 00"), 0)) == mqtt::MALFORMED_PACKET, "non-minimal remaining length");
	assert(packet::frame_length(hx("30 80"), 0)!! == 0, "length itself incomplete");
	assert(packet::frame_length(hx("C0 00"), 0)!! == 2);
	// decode wants exactly one frame
	expect_fault(hx("40 02 00 0A C0 00"), mqtt::MALFORMED_PACKET);
	expect_fault(hx("40 02 00"), mqtt::MALFORMED_PACKET);
	expect_fault(hx("40"), mqtt::MALFORMED_PACKET);
	// reserved packet type 15 in 3.1.1
	expect_fault(hx("F0 00"), mqtt::PROTOCOL_ERROR);
	// a protocol level that is neither 3.1.1 nor 5.0
	assert(@catch(packet::decode((Version)3, hx("40 02 00 0A"))) == mqtt::UNSUPPORTED_VERSION);
}

// ---- CONNECT ----

fn void vec_V_311_CONN_1() @test
{
	Packet p = roundtrip(hx("10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61"));
	assert(p.type == PacketType.CONNECT);
	Connect* c = &p.connect;
	assert(c.clean_start && c.keep_alive == 60 && c.client_id == "a");
	assert(!c.has_username && !c.has_password && !c.has_will);

	Packet q = { .type = PacketType.CONNECT };
	q.connect.client_id = "a";
	q.connect.clean_start = true;
	q.connect.keep_alive = 60;
	char[32] buf;
	usz n = packet::encode(Version.V311, &q, buf[..])!!;
	assert(buf[:n] == hx("10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61"));
}

fn void vec_V_311_CONN_2() @test
{
	char[] b = hx("10 19 00 04 4D 51 54 54 04 EE 00 0A 00 01 63 00 01 77 00 01 6D 00 01 75 00 01 70");
	Packet p = roundtrip(b);
	Connect* c = &p.connect;
	assert(c.clean_start && c.keep_alive == 10 && c.client_id == "c");
	assert(c.has_will && c.will.topic == "w" && c.will.payload == hx("6D"));
	assert(c.will.qos == QoS.AT_LEAST_ONCE && c.will.retain);
	assert(c.has_username && c.username == "u");
	assert(c.has_password && c.password == hx("70"));

	Packet q = { .type = PacketType.CONNECT };
	q.connect.client_id = "c";
	q.connect.clean_start = true;
	q.connect.keep_alive = 10;
	q.connect.has_will = true;
	q.connect.will = { .topic = "w", .payload = hx("6D"), .qos = QoS.AT_LEAST_ONCE, .retain = true };
	q.connect.has_username = true;
	q.connect.username = "u";
	q.connect.has_password = true;
	q.connect.password = hx("70");
	char[40] buf;
	usz n = packet::encode(Version.V311, &q, buf[..])!!;
	assert(buf[:n] == b);
}

fn void vec_V_311_CONN_3() @test
{
	Packet p = roundtrip(hx("10 0C 00 04 4D 51 54 54 04 02 00 3C 00 00"));
	assert(p.connect.client_id.len == 0 && p.connect.clean_start);
}

fn void vec_V_311_CONN_4() @test
{
	// the bytes decode (a server answers with return code 2) but the encoder refuses them
	char[] b = hx("10 0C 00 04 4D 51 54 54 04 00 00 3C 00 00");
	Packet p = dec(b);
	assert(p.connect.client_id.len == 0 && !p.connect.clean_start);
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
}

// every legal combination of the CONNECT flags round trips through encode and decode
fn void connect_all_flag_combinations() @test
{
	int count;
	for (int clean = 0; clean < 2; clean++)
	{
		for (int will = 0; will < 4; will++)           // 0 = none, 1..3 = will with QoS 0, 1, 2
		{
			for (int retain = 0; retain < 2; retain++)
			{
				if (will == 0 && retain == 1) continue;
				for (int user = 0; user < 2; user++)
				{
					for (int pass = 0; pass < 2; pass++)
					{
						if (pass == 1 && user == 0) continue;   // password needs a user name in 3.1.1
						Packet p = { .type = PacketType.CONNECT };
						Connect* c = &p.connect;
						c.client_id = "id";
						c.clean_start = clean == 1;
						c.keep_alive = 300;
						if (will > 0)
						{
							c.has_will = true;
							c.will = { .topic = "t/w", .payload = hx("00 FF"), .qos = (QoS)(will - 1), .retain = retain == 1 };
						}
						if (user == 1) { c.has_username = true; c.username = "usr"; }
						if (pass == 1) { c.has_password = true; c.password = hx("01 02 03"); }
						char[64] buf;
						usz n = packet::encode(Version.V311, &p, buf[..])!!;
						Packet d = packet::decode(Version.V311, buf[:n])!!;
						assert(d.connect.clean_start == c.clean_start);
						assert(d.connect.keep_alive == 300 && d.connect.client_id == "id");
						assert(d.connect.has_will == c.has_will);
						if (will > 0)
						{
							assert(d.connect.will.qos == c.will.qos && d.connect.will.retain == c.will.retain);
							assert(d.connect.will.topic == "t/w" && d.connect.will.payload == hx("00 FF"));
						}
						assert(d.connect.has_username == c.has_username && d.connect.has_password == c.has_password);
						if (user == 1) assert(d.connect.username == "usr");
						if (pass == 1) assert(d.connect.password == hx("01 02 03"));
						count++;
					}
				}
			}
		}
	}
	assert(count == 2 * 7 * 3, "number of legal combinations");
}

fn void connect_encode_refusals() @test
{
	Packet p = { .type = PacketType.CONNECT };
	p.connect.client_id = "a";
	p.connect.clean_start = true;
	p.connect.has_password = true;                     // password without user name
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
	p.connect.has_password = false;
	p.connect.has_will = true;
	p.connect.will = { .topic = "a/+", .payload = {} };   // wildcard in the will topic
	expect_encode_fault(&p, mqtt::INVALID_TOPIC_NAME);
	p.connect.will.topic = "";
	expect_encode_fault(&p, mqtt::INVALID_TOPIC_NAME);
	p.connect.has_will = false;
	p.connect.client_id = (String)hx("C0 80");
	expect_encode_fault(&p, mqtt::INVALID_UTF8);
}

fn void connect_buffer_too_small() @test
{
	Packet p = { .type = PacketType.CONNECT };
	p.connect.client_id = "a";
	p.connect.clean_start = true;
	char[14] small;                                    // the frame needs 15 bytes
	small[..] = 0x55;
	assert(@catch(packet::encode(Version.V311, &p, small[..])) == mqtt::BUFFER_TOO_SMALL);
	assert(small[0] == 0x55, "nothing written");
}

// ---- CONNACK ----

fn void connack_vector(String h, bool sp, char code)
{
	Packet p = roundtrip(hx(h));
	assert(p.type == PacketType.CONNACK);
	assert(p.connack.session_present == sp && p.connack.code == code);
}

fn void vec_V_311_CONNACK_1() @test { connack_vector("20 02 00 00", false, 0); }
fn void vec_V_311_CONNACK_2() @test { connack_vector("20 02 01 00", true, 0); }
fn void vec_V_311_CONNACK_3() @test { connack_vector("20 02 00 01", false, 1); }
fn void vec_V_311_CONNACK_4() @test { connack_vector("20 02 00 02", false, 2); }
fn void vec_V_311_CONNACK_5() @test { connack_vector("20 02 00 03", false, 3); }
fn void vec_V_311_CONNACK_6() @test { connack_vector("20 02 00 04", false, 4); }
fn void vec_V_311_CONNACK_7() @test { connack_vector("20 02 00 05", false, 5); }

fn void connack_encode_refusals() @test
{
	Packet p = { .type = PacketType.CONNACK };
	p.connack = { .session_present = true, .code = 5 };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
	p.connack = { .session_present = false, .code = 6 };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
}

// ---- PUBLISH ----

fn void vec_V_311_PUB_1() @test
{
	Packet p = roundtrip(hx("30 07 00 03 61 2F 62 68 69"));
	Publish* u = &p.publish;
	assert(u.qos == QoS.AT_MOST_ONCE && !u.dup && !u.retain && u.topic == "a/b" && u.payload == hx("68 69"));
}

fn void vec_V_311_PUB_2() @test
{
	Packet p = roundtrip(hx("32 09 00 03 61 2F 62 00 0A 68 69"));
	Publish* u = &p.publish;
	assert(u.qos == QoS.AT_LEAST_ONCE && !u.dup && !u.retain && u.packet_id == 10 && u.topic == "a/b");
}

fn void vec_V_311_PUB_3() @test
{
	Packet p = roundtrip(hx("33 09 00 03 61 2F 62 00 0A 68 69"));
	assert(p.publish.retain && p.publish.qos == QoS.AT_LEAST_ONCE);
}

fn void vec_V_311_PUB_4() @test
{
	Packet p = roundtrip(hx("3A 09 00 03 61 2F 62 00 0A 68 69"));
	assert(p.publish.dup && !p.publish.retain && p.publish.packet_id == 10);
}

fn void vec_V_311_PUB_5() @test
{
	Packet p = roundtrip(hx("34 06 00 01 61 00 07 78"));
	assert(p.publish.qos == QoS.EXACTLY_ONCE && p.publish.packet_id == 7 && p.publish.topic == "a" && p.publish.payload == hx("78"));
}

fn void vec_V_311_PUB_6() @test
{
	Packet p = roundtrip(hx("3C 06 00 01 61 00 07 78"));
	assert(p.publish.dup && p.publish.qos == QoS.EXACTLY_ONCE);
}

fn void vec_V_311_PUB_7() @test
{
	Packet p = roundtrip(hx("31 05 00 03 61 2F 62"));
	assert(p.publish.retain && p.publish.payload.len == 0);
}

fn void vec_V_311_PUB_8() @test
{
	char[] b = mem::temp_array(char, 6 + 200 + 1);
	char[] head = hx("30 CB 01 00 01 74");
	b[:head.len] = head[..];
	b[head.len:200] = 'a';
	b = b[:head.len + 200];
	Packet p = roundtrip(b);
	assert(p.publish.topic == "t" && p.publish.payload.len == 200 && p.publish.payload[199] == 'a');
}

fn void publish_encode_refusals() @test
{
	Packet p = { .type = PacketType.PUBLISH };
	p.publish = { .qos = QoS.AT_LEAST_ONCE, .topic = "a", .packet_id = 0 };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);          // QoS 1 needs an id
	p.publish = { .qos = QoS.AT_MOST_ONCE, .dup = true, .topic = "a" };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);          // DUP with QoS 0
	p.publish = { .topic = "" };
	expect_encode_fault(&p, mqtt::INVALID_TOPIC_NAME);
	p.publish = { .topic = "a/#" };
	expect_encode_fault(&p, mqtt::INVALID_TOPIC_NAME);
	p.publish = { .topic = "+" };
	expect_encode_fault(&p, mqtt::INVALID_TOPIC_NAME);
	p.publish = { .topic = (String)hx("ED A0 80") };
	expect_encode_fault(&p, mqtt::INVALID_UTF8);
}

fn void publish_large_payload() @test
{
	// 3-byte remaining length: 20000-byte payload
	char[] payload = mem::temp_array(char, 20_000);
	payload[..] = 0x42;
	char[] out = mem::temp_array(char, 20_100);
	Packet p = { .type = PacketType.PUBLISH };
	p.publish = { .topic = "big", .payload = payload };
	usz n = packet::encode(Version.V311, &p, out[..])!!;
	assert(n == 1 + 3 + 2 + 3 + 20_000);
	check_rl(out[:n]);
	Packet d = packet::decode(Version.V311, out[:n])!!;
	assert(d.publish.payload.len == 20_000 && d.publish.topic == "big");
}

// ---- acknowledgements ----

fn void ack_vector(String h, PacketType t)
{
	Packet p = roundtrip(hx(h));
	assert(p.type == t && p.ack.packet_id == 10);
}

fn void vec_V_311_PUBACK() @test { ack_vector("40 02 00 0A", PacketType.PUBACK); }
fn void vec_V_311_PUBREC() @test { ack_vector("50 02 00 0A", PacketType.PUBREC); }
fn void vec_V_311_PUBREL() @test { ack_vector("62 02 00 0A", PacketType.PUBREL); }
fn void vec_V_311_PUBCOMP() @test { ack_vector("70 02 00 0A", PacketType.PUBCOMP); }

fn void ack_encode_refusals() @test
{
	Packet p = { .type = PacketType.PUBACK };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);          // id 0
	p.type = PacketType.PUBREL;
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
}

// ---- malformed 3.1.1 packets ----

fn void vec_V_311_N1() @test { expect_fault(hx("36 07 00 03 61 2F 62 00 01"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N2() @test { expect_fault(hx("38 07 00 03 61 2F 62 68 69"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N3() @test { expect_fault(hx("32 07 00 03 61 2F 62 00 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N4() @test { expect_fault(hx("32 05 00 03 61 2F 62"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N5() @test { expect_fault(hx("32 06 00 03 61 2F 62 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N6() @test { expect_fault(hx("30 02 00 00"), mqtt::INVALID_TOPIC_NAME); }
fn void vec_V_311_N7() @test { expect_fault(hx("30 05 00 03 61 2F 23"), mqtt::INVALID_TOPIC_NAME); }
fn void vec_V_311_N8() @test { expect_fault(hx("30 05 00 03 61 2F 2B"), mqtt::INVALID_TOPIC_NAME); }
fn void vec_V_311_N9() @test { expect_fault(hx("40 02 00 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N10() @test { expect_fault(hx("40 03 00 0A 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N11() @test { expect_fault(hx("40 01 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N12() @test { expect_fault(hx("20 02 02 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N13() @test { expect_fault(hx("20 02 01 05"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N14() @test { expect_fault(hx("20 02 00 06"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N15() @test { expect_fault(hx("20 01 00"), mqtt::MALFORMED_PACKET); }

fn void vec_V_311_N25() @test { expect_fault(hx("10 0D 00 04 4D 51 54 55 04 02 00 3C 00 01 61"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N26() @test { expect_fault(hx("10 0D 00 04 4D 51 54 54 04 03 00 3C 00 01 61"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N27() @test { expect_fault(hx("10 0D 00 04 4D 51 54 54 04 04 00 3C 00 01 61"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N28() @test { expect_fault(hx("10 0D 00 04 4D 51 54 54 04 42 00 3C 00 01 61"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N29() @test { expect_fault(hx("10 0D 00 04 4D 51 54 54 04 0A 00 3C 00 01 61"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N30() @test { expect_fault(hx("10 0D 00 04 4D 51 54 54 04 1C 00 3C 00 01 61"), mqtt::MALFORMED_PACKET); }

fn void connect_more_malformed() @test
{
	// level 3 (3.1) and level 5 are not 3.1.1
	expect_fault(hx("10 0D 00 04 4D 51 54 54 03 02 00 3C 00 01 61"), mqtt::UNSUPPORTED_VERSION);
	expect_fault(hx("10 0D 00 04 4D 51 54 54 05 02 00 3C 00 01 61"), mqtt::UNSUPPORTED_VERSION);
	// trailing byte after the payload
	expect_fault(hx("10 0E 00 04 4D 51 54 54 04 02 00 3C 00 01 61 00"), mqtt::MALFORMED_PACKET);
	// client id longer than the frame
	expect_fault(hx("10 0D 00 04 4D 51 54 54 04 02 00 3C 00 05 61"), mqtt::MALFORMED_PACKET);
	// reserved flags in the fixed header
	expect_fault(hx("11 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61"), mqtt::MALFORMED_PACKET);
	// will topic with a wildcard
	expect_fault(hx("10 14 00 04 4D 51 54 54 04 06 00 3C 00 01 61 00 03 61 2F 23 00 00"), mqtt::INVALID_TOPIC_NAME);
}

fn void connack_publish_more_malformed() @test
{
	expect_fault(hx("21 02 00 00"), mqtt::MALFORMED_PACKET);          // CONNACK with flag bits
	expect_fault(hx("20 04 00 00 00 00"), mqtt::MALFORMED_PACKET);    // too long
	expect_fault(hx("30 01 00"), mqtt::MALFORMED_PACKET);             // topic length cut off
	expect_fault(hx("30 00"), mqtt::MALFORMED_PACKET);                // no topic at all
	expect_fault(hx("34 06 00 01 61 00"), mqtt::MALFORMED_PACKET);    // QoS 2 id cut off
}

// ---- strings: the V-STR vectors framed in a PUBLISH ----

fn void str_ok(String topic_hex)
{
	char[] t = hx(topic_hex);
	char[] b = mem::temp_array(char, 4 + t.len);
	b[0] = 0x30;
	b[1] = (char)(2 + t.len);
	b[2] = 0;
	b[3] = (char)t.len;
	b[4:t.len] = t[..];
	Packet p = roundtrip(b[:4 + t.len]);
	assert(p.publish.topic.len == t.len);
	assert((char[])p.publish.topic == t, "topic bytes unchanged");
}

fn void vec_V_STR_1() @test { str_ok("C3 A9"); }
fn void vec_V_STR_2() @test { str_ok("F0 9F 98 80"); }
fn void vec_V_STR_3() @test { str_ok("F4 8F BF BF"); }
fn void vec_V_STR_4() @test { str_ok("EF BF BF"); }
fn void vec_V_STR_5() @test { str_ok("EF BB BF"); }

fn void vec_V_STR_N1() @test { expect_fault(hx("30 05 00 03 61 00 62"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N2() @test { expect_fault(hx("30 04 00 02 C0 80"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N3() @test { expect_fault(hx("30 05 00 03 ED A0 80"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N4() @test { expect_fault(hx("30 05 00 03 ED BF BF"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N5() @test { expect_fault(hx("30 06 00 04 F4 90 80 80"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N6() @test { expect_fault(hx("30 05 00 03 61 FF 62"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N7() @test { expect_fault(hx("30 04 00 02 C3 41"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N8() @test { expect_fault(hx("30 03 00 01 80"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N9() @test { expect_fault(hx("30 04 00 02 E2 82"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N10() @test { expect_fault(hx("30 05 00 03 E0 80 80"), mqtt::INVALID_UTF8); }
fn void vec_V_STR_N11() @test { expect_fault(hx("30 04 00 09 61 62"), mqtt::MALFORMED_PACKET); }
fn void vec_V_STR_N12() @test { expect_fault(hx("30 03 00 05 61"), mqtt::MALFORMED_PACKET); }

// ---- SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK ----

fn void vec_V_311_SUB_1() @test
{
	Packet p = roundtrip(hx("82 08 00 01 00 03 61 2F 23 01"));
	assert(p.type == PacketType.SUBSCRIBE && p.subscribe.packet_id == 1);
	usz cursor;
	SubEntry e;
	assert(p.subscribe.next(&cursor, Version.V311, &e)!!);
	assert(e.filter == "a/#" && e.qos == QoS.AT_LEAST_ONCE);
	assert(!p.subscribe.next(&cursor, Version.V311, &e)!!, "one filter only");

	Packet q = { .type = PacketType.SUBSCRIBE };
	SubEntry[1] entries = { { .filter = "a/#", .qos = QoS.AT_LEAST_ONCE } };
	q.subscribe = { .packet_id = 1, .entries = entries[..] };
	char[16] buf;
	usz n = packet::encode(Version.V311, &q, buf[..])!!;
	assert(buf[:n] == hx("82 08 00 01 00 03 61 2F 23 01"));
}

fn void vec_V_311_SUB_2() @test
{
	Packet p = roundtrip(hx("82 0E 00 05 00 03 61 2F 62 00 00 03 63 2F 2B 02"));
	assert(p.subscribe.packet_id == 5);
	usz cursor;
	SubEntry e;
	assert(p.subscribe.next(&cursor, Version.V311, &e)!!);
	assert(e.filter == "a/b" && e.qos == QoS.AT_MOST_ONCE);
	assert(p.subscribe.next(&cursor, Version.V311, &e)!!);
	assert(e.filter == "c/+" && e.qos == QoS.EXACTLY_ONCE);
	assert(!p.subscribe.next(&cursor, Version.V311, &e)!!);
}

fn void vec_V_311_SUBACK_1() @test
{
	Packet p = roundtrip(hx("90 03 00 01 01"));
	assert(p.type == PacketType.SUBACK && p.suback.packet_id == 1 && p.suback.codes == hx("01"));
}

fn void vec_V_311_SUBACK_2() @test
{
	Packet p = roundtrip(hx("90 04 00 05 00 80"));
	assert(p.suback.packet_id == 5 && p.suback.codes == hx("00 80"));
}

fn void vec_V_311_UNSUB() @test
{
	Packet p = roundtrip(hx("A2 07 00 02 00 03 61 2F 23"));
	assert(p.type == PacketType.UNSUBSCRIBE && p.unsubscribe.packet_id == 2);
	usz cursor;
	String f;
	assert(p.unsubscribe.next(&cursor, &f)!!);
	assert(f == "a/#");
	assert(!p.unsubscribe.next(&cursor, &f)!!);

	Packet q = { .type = PacketType.UNSUBSCRIBE };
	String[1] filters = { "a/#" };
	q.unsubscribe = { .packet_id = 2, .filters = filters[..] };
	char[16] buf;
	usz n = packet::encode(Version.V311, &q, buf[..])!!;
	assert(buf[:n] == hx("A2 07 00 02 00 03 61 2F 23"));
}

fn void vec_V_311_UNSUBACK() @test
{
	Packet p = roundtrip(hx("B0 02 00 02"));
	assert(p.type == PacketType.UNSUBACK && p.suback.packet_id == 2 && p.suback.codes.len == 0);
}

fn void vec_V_FR_1() @test { assert(roundtrip(hx("C0 00")).type == PacketType.PINGREQ); }
fn void vec_V_FR_2() @test { assert(roundtrip(hx("D0 00")).type == PacketType.PINGRESP); }
fn void vec_V_FR_3() @test { assert(roundtrip(hx("E0 00")).type == PacketType.DISCONNECT); }

fn void vec_V_FR_N2() @test
{
	// type 15 is reserved in 3.1.1 (the 5.0 half is checked with the 5.0 codec)
	assert(packet::frame_length(hx("F0 00"), 0)!! == 2);
	expect_fault(hx("F0 00"), mqtt::PROTOCOL_ERROR);
}

fn void vec_V_FR_N4() @test
{
	assert(dec(hx("82 08 00 01 00 03 61 2F 23 01")).type == PacketType.SUBSCRIBE);
	expect_fault(hx("80 08 00 01 00 03 61 2F 23 01"), mqtt::MALFORMED_PACKET);
}

fn void vec_V_FR_N5() @test { expect_fault(hx("A0 07 00 02 00 03 61 2F 23"), mqtt::MALFORMED_PACKET); }
fn void vec_V_FR_N7() @test { expect_fault(hx("C1 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_FR_N8() @test { expect_fault(hx("D0 01 00"), mqtt::MALFORMED_PACKET); }

fn void vec_V_311_N16() @test { expect_fault(hx("90 02 00 01"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N17() @test { expect_fault(hx("90 03 00 01 03"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N18() @test { expect_fault(hx("90 03 00 00 01"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N19() @test { expect_fault(hx("82 05 00 01 00 01 61"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N20() @test { expect_fault(hx("82 02 00 01"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N21() @test { expect_fault(hx("82 08 00 01 00 03 61 2F 23 04"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N22() @test { expect_fault(hx("A2 02 00 02"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N23() @test { expect_fault(hx("B0 03 00 02 00"), mqtt::MALFORMED_PACKET); }
fn void vec_V_311_N24() @test { expect_fault(hx("E0 01 00"), mqtt::MALFORMED_PACKET); }

fn void subscribe_more_malformed() @test
{
	expect_fault(hx("82 08 00 00 00 03 61 2F 23 01"), mqtt::MALFORMED_PACKET);    // packet id 0
	expect_fault(hx("82 08 00 01 00 03 61 2F 23 03"), mqtt::MALFORMED_PACKET);    // QoS 3
	expect_fault(hx("82 08 00 01 00 03 61 2F 23 21"), mqtt::MALFORMED_PACKET);    // reserved bit 5
	expect_fault(hx("82 05 00 01 00 00 01"), mqtt::INVALID_TOPIC_FILTER);          // empty filter
	expect_fault(hx("82 08 00 01 00 03 61 C0 80 01"), mqtt::INVALID_UTF8);
	// second entry cut off: caught at decode, not later
	expect_fault(hx("82 0C 00 01 00 03 61 2F 23 01 00 03 62"), mqtt::MALFORMED_PACKET);
	expect_fault(hx("A2 04 00 02 00 03"), mqtt::MALFORMED_PACKET);                  // filter cut off
	expect_fault(hx("A2 05 00 00 00 01 61"), mqtt::MALFORMED_PACKET);               // packet id 0
	expect_fault(hx("B0 02 00 00"), mqtt::MALFORMED_PACKET);
	expect_fault(hx("C0 01 00"), mqtt::MALFORMED_PACKET);
	expect_fault(hx("E1 00"), mqtt::MALFORMED_PACKET);
}

fn void subscribe_encode_refusals() @test
{
	Packet p = { .type = PacketType.SUBSCRIBE };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);                    // no id, no entries
	SubEntry[1] e = { { .filter = "" } };
	p.subscribe = { .packet_id = 1, .entries = e[..] };
	expect_encode_fault(&p, mqtt::INVALID_TOPIC_FILTER);
	e[0] = { .filter = "a", .no_local = true };                          // 5.0 option on a 3.1.1 packet
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
	p.type = PacketType.UNSUBSCRIBE;
	String[] none = {};
	p.unsubscribe = { .packet_id = 1, .filters = none };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
	p.type = PacketType.SUBACK;
	char[1] bad = { 3 };
	p.suback = { .packet_id = 1, .codes = bad[..] };
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);
	p.type = PacketType.AUTH;
	expect_encode_fault(&p, mqtt::INVALID_ARGUMENT);                    // AUTH is not in 3.1.1
}

fn void unknown_version_is_refused() @test
{
	assert(@catch(packet::decode((Version)3, hx("C0 00"))) == mqtt::UNSUPPORTED_VERSION);
	Packet p = { .type = PacketType.PINGREQ };
	char[4] buf;
	assert(@catch(packet::encode((Version)3, &p, buf[..])) == mqtt::UNSUPPORTED_VERSION);
}

// encode sizes the packet once: the limit is checked on the remaining length before any byte is written
fn void encode_limit_and_size_agree() @test
{
	char[1] one = { 0x61 };
	char[] huge = one[:1];
	Packet p = { .type = PacketType.PUBLISH };
	p.publish = { .topic = "t", .payload = huge };
	char[16] small;
	small[..] = 0x55;
	char[2] tiny;
	assert(@catch(packet::encode(Version.V311, &p, tiny[..])) == mqtt::BUFFER_TOO_SMALL);
	usz n = packet::encode(Version.V311, &p, small[..])!!;
	assert(n == packet::encoded_size(Version.V311, &p)!!, "encode and encoded_size agree");
	assert(n == 1 + 1 + 2 + 1 + 1);
}
