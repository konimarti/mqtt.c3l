module mqtt::props_test;
import mqtt, mqtt::props, mqtt::testutil, mqtt::wire;

fn char[] hx(String h) => testutil::hex(h);

// A property block: the length prefix and then the bytes in `h`.
fn char[] block(String h)
{
	char[] body = hx(h);
	char[] b = mem::temp_array(char, body.len + 4);
	usz n = wire::vbi_encode((uint)body.len, b[..])!!;
	b[n:body.len] = body[..];
	return b[:n + body.len];
}

fn Properties dec(String h, PropContext ctx)
{
	char[] b = block(h);
	ByteReader r = wire::reader(b);
	Properties p = r.properties(ctx)!!;
	assert(r.remaining() == 0, "the whole block is consumed");
	return p;
}

fn fault dec_fault(String h, PropContext ctx)
{
	char[] b = block(h);
	ByteReader r = wire::reader(b);
	return @catch(r.properties(ctx));
}

// decode, then encode again: the bytes must be identical (the input is in ascending id order)
fn Properties roundtrip(String h, PropContext ctx)
{
	Properties p = dec(h, ctx);
	char[] expected = block(h);
	char[] buf = mem::temp_array(char, expected.len + 8);
	ByteWriter w = wire::writer(buf);
	w.properties(&p, ctx)!!;
	assert(w.written() == expected, "re-encoding gives the original bytes");
	assert(props::properties_size(&p, ctx)!! == expected.len, "properties_size");
	return p;
}

// ---- one property per row, one test per identifier ----

fn void vec_prop_0x01() @test
{
	Properties p = roundtrip("01 01", PropContext.PUBLISH);
	assert(p.has(PropId.PAYLOAD_FORMAT_INDICATOR) && p.payload_format == 1);
}

fn void vec_prop_0x02() @test
{
	Properties p = roundtrip("02 00 00 00 3C", PropContext.PUBLISH);
	assert(p.has(PropId.MESSAGE_EXPIRY_INTERVAL) && p.message_expiry == 60);
}

fn void vec_prop_0x03() @test
{
	Properties p = roundtrip("03 00 01 61", PropContext.PUBLISH);
	assert(p.has(PropId.CONTENT_TYPE) && p.content_type == "a");
}

fn void vec_prop_0x08() @test
{
	Properties p = roundtrip("08 00 01 72", PropContext.PUBLISH);
	assert(p.has(PropId.RESPONSE_TOPIC) && p.response_topic == "r");
}

fn void vec_prop_0x09() @test
{
	Properties p = roundtrip("09 00 02 01 02", PropContext.PUBLISH);
	assert(p.has(PropId.CORRELATION_DATA) && p.correlation_data == hx("01 02"));
}

fn void vec_prop_0x0B() @test
{
	Properties p = roundtrip("0B 80 01", PropContext.PUBLISH);
	assert(p.has(PropId.SUBSCRIPTION_IDENTIFIER));
	SubIdIter it = p.subscription_id_iter();
	uint v;
	assert(it.next(&v)!! && v == 128);
	assert(!it.next(&v)!!);
}

fn void vec_prop_0x11() @test
{
	Properties p = roundtrip("11 FF FF FF FF", PropContext.CONNACK);
	assert(p.has(PropId.SESSION_EXPIRY_INTERVAL) && p.session_expiry == 0xFFFFFFFF);
}

fn void vec_prop_0x12() @test
{
	Properties p = roundtrip("12 00 01 78", PropContext.CONNACK);
	assert(p.has(PropId.ASSIGNED_CLIENT_IDENTIFIER) && p.assigned_client_id == "x");
}

fn void vec_prop_0x13() @test
{
	Properties p = roundtrip("13 00 1E", PropContext.CONNACK);
	assert(p.has(PropId.SERVER_KEEP_ALIVE) && p.server_keep_alive == 30);
}

fn void vec_prop_0x15() @test
{
	Properties p = roundtrip("15 00 01 61", PropContext.CONNACK);
	assert(p.has(PropId.AUTHENTICATION_METHOD) && p.auth_method == "a");
}

fn void vec_prop_0x16() @test
{
	Properties p = roundtrip("16 00 01 AA", PropContext.CONNACK);
	assert(p.has(PropId.AUTHENTICATION_DATA) && p.auth_data == hx("AA"));
}

fn void vec_prop_0x17() @test
{
	Properties p = roundtrip("17 00", PropContext.CONNECT);
	assert(p.has(PropId.REQUEST_PROBLEM_INFORMATION) && p.request_problem_info == 0);
}

fn void vec_prop_0x18() @test
{
	Properties p = roundtrip("18 00 00 00 0A", PropContext.WILL);
	assert(p.has(PropId.WILL_DELAY_INTERVAL) && p.will_delay == 10);
}

fn void vec_prop_0x19() @test
{
	Properties p = roundtrip("19 01", PropContext.CONNECT);
	assert(p.has(PropId.REQUEST_RESPONSE_INFORMATION) && p.request_response_info == 1);
}

fn void vec_prop_0x1A() @test
{
	Properties p = roundtrip("1A 00 01 69", PropContext.CONNACK);
	assert(p.has(PropId.RESPONSE_INFORMATION) && p.response_info == "i");
}

fn void vec_prop_0x1C() @test
{
	Properties p = roundtrip("1C 00 01 62", PropContext.CONNACK);
	assert(p.has(PropId.SERVER_REFERENCE) && p.server_reference == "b");
}

fn void vec_prop_0x1F() @test
{
	Properties p = roundtrip("1F 00 02 6F 6B", PropContext.CONNACK);
	assert(p.has(PropId.REASON_STRING) && p.reason_string == "ok");
}

fn void vec_prop_0x21() @test
{
	Properties p = roundtrip("21 00 14", PropContext.CONNACK);
	assert(p.has(PropId.RECEIVE_MAXIMUM) && p.receive_maximum == 20);
}

fn void vec_prop_0x22() @test
{
	Properties p = roundtrip("22 00 0A", PropContext.CONNACK);
	assert(p.has(PropId.TOPIC_ALIAS_MAXIMUM) && p.topic_alias_maximum == 10);
}

fn void vec_prop_0x23() @test
{
	Properties p = roundtrip("23 00 01", PropContext.PUBLISH);
	assert(p.has(PropId.TOPIC_ALIAS) && p.topic_alias == 1);
}

fn void vec_prop_0x24() @test
{
	Properties p = roundtrip("24 01", PropContext.CONNACK);
	assert(p.has(PropId.MAXIMUM_QOS) && p.maximum_qos == 1);
}

fn void vec_prop_0x25() @test
{
	Properties p = roundtrip("25 00", PropContext.CONNACK);
	assert(p.has(PropId.RETAIN_AVAILABLE) && p.retain_available == 0);
}

fn void vec_prop_0x26() @test
{
	Properties p = roundtrip("26 00 01 6B 00 01 76", PropContext.CONNACK);
	assert(p.has(PropId.USER_PROPERTY));
	UserPropIter it = p.user_props();
	UserProperty u;
	assert(it.next(&u)!! && u.key == "k" && u.value == "v");
	assert(!it.next(&u)!!);
}

fn void vec_prop_0x27() @test
{
	Properties p = roundtrip("27 00 00 04 00", PropContext.CONNACK);
	assert(p.has(PropId.MAXIMUM_PACKET_SIZE) && p.max_packet_size == 1024);
}

fn void vec_prop_0x28() @test
{
	Properties p = roundtrip("28 00", PropContext.CONNACK);
	assert(p.has(PropId.WILDCARD_SUBSCRIPTION_AVAILABLE) && p.wildcard_sub_available == 0);
}

fn void vec_prop_0x29() @test
{
	Properties p = roundtrip("29 00", PropContext.CONNACK);
	assert(p.has(PropId.SUBSCRIPTION_IDENTIFIER_AVAILABLE) && p.subid_available == 0);
}

fn void vec_prop_0x2A() @test
{
	Properties p = roundtrip("2A 00", PropContext.CONNACK);
	assert(p.has(PropId.SHARED_SUBSCRIPTION_AVAILABLE) && p.shared_sub_available == 0);
}

fn void all_27_ids_are_listed() @test
{
	assert(props::ALL_PROP_IDS.len == 27);
	char last = 0;
	foreach (id : props::ALL_PROP_IDS)
	{
		assert((char)id > last, "ascending and unique");
		last = (char)id;
		assert(props::kind_of((char)id) != PropKind.UNKNOWN);
	}
	// everything in between is unknown
	int known;
	for (uint c = 0; c < 256; c++)
	{
		if (props::kind_of((char)c) != PropKind.UNKNOWN) known++;
	}
	assert(known == 27);
}

// ---- the property-block half of V-5-N1 .. V-5-N16 ----

fn void vec_V_5_N1() @test { assert(dec_fault("11 00 00 00 0A 11 00 00 00 0B", PropContext.CONNACK) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N2() @test { assert(dec_fault("04 00", PropContext.CONNACK) == mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N3() @test
{
	// property length 5 and nothing follows
	ByteReader r = wire::reader(hx("05"));
	assert(@catch(r.properties(PropContext.CONNACK)) == mqtt::MALFORMED_PACKET);
}
fn void vec_V_5_N4() @test { assert(dec_fault("0B 01", PropContext.CONNACK) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N5() @test { assert(dec_fault("21 00 00", PropContext.CONNACK) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N6() @test { assert(dec_fault("24 02", PropContext.CONNACK) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N7() @test { assert(dec_fault("25 02", PropContext.CONNACK) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N8() @test { assert(dec_fault("1F 00 05 61", PropContext.CONNACK) == mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N9() @test
{
	ByteReader r = wire::reader(hx("80 80 80 80 01"));
	assert(@catch(r.properties(PropContext.CONNACK)) == mqtt::MALFORMED_PACKET);
}
// the vector lists MALFORMED; the string reader reports the cause, INVALID_UTF8, as in the 3.1.1 codec
fn void vec_V_5_N10() @test { assert(dec_fault("12 00 01 FF", PropContext.CONNACK) == mqtt::INVALID_UTF8); }
fn void vec_V_5_N11() @test { assert(dec_fault("13 00 1E 00", PropContext.CONNACK) == mqtt::MALFORMED_PACKET); }
fn void vec_V_5_N12() @test { assert(dec_fault("23 00 00", PropContext.PUBLISH) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N13() @test { assert(dec_fault("0B 00", PropContext.PUBLISH) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N14() @test { assert(dec_fault("01 02", PropContext.PUBLISH) == mqtt::INVALID_PROPERTY); }
fn void vec_V_5_N15() @test
{
	// the packet-level fault (empty topic without alias) belongs to the packet codec; the block itself is empty and valid
	Properties p = dec("", PropContext.PUBLISH);
	assert(p.present == 0);
}
fn void vec_V_5_N16() @test
{
	// length 4 declared, one byte follows
	ByteReader r = wire::reader(hx("04 01"));
	assert(@catch(r.properties(PropContext.PUBLISH)) == mqtt::MALFORMED_PACKET);
}

// ---- legality table ----

struct Legal
{
	PropContext ctx;
	char[] ids;
}

char[*] legal_connect = { 0x11, 0x15, 0x16, 0x17, 0x19, 0x21, 0x22, 0x26, 0x27 };
char[*] legal_connack = { 0x11, 0x12, 0x13, 0x15, 0x16, 0x1A, 0x1C, 0x1F, 0x21, 0x22, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A };
char[*] legal_publish = { 0x01, 0x02, 0x03, 0x08, 0x09, 0x0B, 0x23, 0x26 };
char[*] legal_will = { 0x01, 0x02, 0x03, 0x08, 0x09, 0x18, 0x26 };
char[*] legal_ack = { 0x1F, 0x26 };
char[*] legal_subscribe = { 0x0B, 0x26 };
char[*] legal_unsubscribe = { 0x26 };
char[*] legal_disconnect = { 0x11, 0x1C, 0x1F, 0x26 };
char[*] legal_auth = { 0x15, 0x16, 0x1F, 0x26 };

// written from the property table of 2.2.2.2, one list per packet (independent of the rule table in props.c3)
fn Legal[] expected_legal()
{
	Legal[] t = mem::temp_array(Legal, 14);
	t[0] = { PropContext.CONNECT, legal_connect[..] };
	t[1] = { PropContext.CONNACK, legal_connack[..] };
	t[2] = { PropContext.PUBLISH, legal_publish[..] };
	t[3] = { PropContext.WILL, legal_will[..] };
	t[4] = { PropContext.PUBACK, legal_ack[..] };
	t[5] = { PropContext.PUBREC, legal_ack[..] };
	t[6] = { PropContext.PUBREL, legal_ack[..] };
	t[7] = { PropContext.PUBCOMP, legal_ack[..] };
	t[8] = { PropContext.SUBSCRIBE, legal_subscribe[..] };
	t[9] = { PropContext.SUBACK, legal_ack[..] };
	t[10] = { PropContext.UNSUBSCRIBE, legal_unsubscribe[..] };
	t[11] = { PropContext.UNSUBACK, legal_ack[..] };
	t[12] = { PropContext.DISCONNECT, legal_disconnect[..] };
	t[13] = { PropContext.AUTH, legal_auth[..] };
	return t;
}

fn bool listed(char[] ids, char id)
{
	foreach (x : ids)
	{
		if (x == id) return true;
	}
	return false;
}

fn void legality_table_every_cell() @test
{
	Legal[] table = expected_legal();
	int cells;
	foreach (row : table)
	{
		foreach (id : props::ALL_PROP_IDS)
		{
			assert(props::allowed(row.ctx, id) == listed(row.ids, (char)id), "legality cell differs from the spec table");
			cells++;
		}
	}
	assert(cells == 27 * 14);
}

// A valid value for each identifier.
const String[*] ROWS = {
	"01 01", "02 00 00 00 3C", "03 00 01 61", "08 00 01 72", "09 00 02 01 02", "0B 80 01",
	"11 FF FF FF FF", "12 00 01 78", "13 00 1E", "15 00 01 61", "16 00 01 AA", "17 00", "18 00 00 00 0A",
	"19 01", "1A 00 01 69", "1C 00 01 62", "1F 00 02 6F 6B", "21 00 14", "22 00 0A", "23 00 01", "24 01",
	"25 00", "26 00 01 6B 00 01 76", "27 00 00 04 00", "28 00", "29 00", "2A 00",
};

fn void decode_follows_legality_in_every_context() @test
{
	assert(ROWS.len == 27);
	Legal[] table = expected_legal();
	foreach (row : table)
	{
		foreach (i, h : ROWS)
		{
			char id = hx(h)[0];
			if (listed(row.ids, id))
			{
				Properties p = dec(h, row.ctx);
				assert(p.has((PropId)id));
			}
			else
			{
				assert(dec_fault(h, row.ctx) == mqtt::INVALID_PROPERTY, "property not allowed in this packet");
			}
		}
	}
}

// ---- more decode rules ----

fn void empty_block() @test
{
	Properties p = roundtrip("", PropContext.CONNACK);
	assert(p.present == 0);
	char[1] one;
	ByteWriter w = wire::writer(one[..]);
	Properties none;
	w.properties(&none, PropContext.CONNECT)!!;
	assert(w.written() == hx("00"));
}

fn void decode_accepts_any_order() @test
{
	Properties p = dec("27 00 00 04 00 11 00 00 00 0A 21 00 05", PropContext.CONNECT);
	assert(p.max_packet_size == 1024 && p.session_expiry == 10 && p.receive_maximum == 5);
}

fn void encode_is_ascending() @test
{
	Properties p;
	p.set(PropId.MAXIMUM_PACKET_SIZE);
	p.max_packet_size = 1024;
	p.set(PropId.SESSION_EXPIRY_INTERVAL);
	p.session_expiry = 10;
	p.set(PropId.RECEIVE_MAXIMUM);
	p.receive_maximum = 5;
	char[32] buf;
	ByteWriter w = wire::writer(buf[..]);
	w.properties(&p, PropContext.CONNECT)!!;
	assert(w.written() == block("11 00 00 00 0A 21 00 05 27 00 00 04 00"));
}

fn void other_properties_after_the_first_fault() @test
{
	// the first violation decides, later bytes are not looked at
	assert(dec_fault("21 00 00 FF FF FF", PropContext.CONNACK) == mqtt::INVALID_PROPERTY);
}

fn void user_properties_keep_order_and_interleave() @test
{
	// 0x26 pairs around other properties: both pairs survive, in order, and the block re-encodes identically
	String h = "11 00 00 00 0A 26 00 01 6B 00 01 76 26 00 01 6B 00 01 77 27 00 00 04 00";
	Properties p = roundtrip(h, PropContext.CONNECT);
	UserPropIter it = p.user_props();
	UserProperty u;
	assert(it.next(&u)!! && u.key == "k" && u.value == "v");
	assert(it.next(&u)!! && u.key == "k" && u.value == "w");
	assert(!it.next(&u)!!);
	assert(p.session_expiry == 10 && p.max_packet_size == 1024);
}

fn void user_properties_in_connack_vector() @test
{
	// two user properties in one CONNACK
	char[] frame = hx("20 11 00 00 0E 26 00 01 6B 00 01 76 26 00 01 6B 00 01 77");
	ByteReader r = wire::reader(frame[4..]);
	Properties p = r.properties(PropContext.CONNACK)!!;
	UserPropIter it = p.user_props();
	UserProperty u;
	assert(it.next(&u)!! && u.value == "v");
	assert(it.next(&u)!! && u.value == "w");
	assert(!it.next(&u)!!);
}

fn void encode_from_user_slice() @test
{
	UserProperty[2] list = { { "k", "v" }, { "a", "b" } };
	Properties p;
	p.user = list[..];
	char[32] buf;
	ByteWriter w = wire::writer(buf[..]);
	w.properties(&p, PropContext.PUBLISH)!!;
	assert(w.written() == block("26 00 01 6B 00 01 76 26 00 01 61 00 01 62"));
}

fn void subscription_identifiers() @test
{
	// several in a PUBLISH are fine and keep their order; the largest value round trips
	Properties p = roundtrip("0B 05 0B FF FF FF 7F 0B 80 01", PropContext.PUBLISH);
	SubIdIter it = p.subscription_id_iter();
	uint v;
	assert(it.next(&v)!! && v == 5);
	assert(it.next(&v)!! && v == 268_435_455);
	assert(it.next(&v)!! && v == 128);
	assert(!it.next(&v)!!);
	// one only in SUBSCRIBE
	assert(dec_fault("0B 05 0B 06", PropContext.SUBSCRIBE) == mqtt::INVALID_PROPERTY);
	Properties s = roundtrip("0B FF FF FF 7F", PropContext.SUBSCRIBE);
	assert(s.has(PropId.SUBSCRIPTION_IDENTIFIER));
	// not in minimal form, or 5 bytes
	assert(dec_fault("0B 80 00", PropContext.PUBLISH) == mqtt::MALFORMED_PACKET);
	assert(dec_fault("0B 80 80 80 80 01", PropContext.PUBLISH) == mqtt::MALFORMED_PACKET);
	// from the caller's list
	uint[2] ids = { 7, 300 };
	Properties q;
	q.subscription_ids = ids[..];
	char[16] buf;
	ByteWriter w = wire::writer(buf[..]);
	w.properties(&q, PropContext.PUBLISH)!!;
	assert(w.written() == block("0B 07 0B AC 02"));
}

fn void range_checks() @test
{
	assert(dec_fault("27 00 00 00 00", PropContext.CONNECT) == mqtt::INVALID_PROPERTY);      // Maximum Packet Size 0
	assert(dec_fault("17 02", PropContext.CONNECT) == mqtt::INVALID_PROPERTY);
	assert(dec_fault("19 02", PropContext.CONNECT) == mqtt::INVALID_PROPERTY);
	assert(dec_fault("28 02", PropContext.CONNACK) == mqtt::INVALID_PROPERTY);
	assert(dec_fault("29 02", PropContext.CONNACK) == mqtt::INVALID_PROPERTY);
	assert(dec_fault("2A 02", PropContext.CONNACK) == mqtt::INVALID_PROPERTY);
	assert(dec_fault("24 03", PropContext.CONNACK) == mqtt::INVALID_PROPERTY);
}

fn void zero_topic_alias_maximum_is_legal() @test
{
	Properties p = dec("22 00 00", PropContext.CONNACK);
	assert(p.has(PropId.TOPIC_ALIAS_MAXIMUM) && p.topic_alias_maximum == 0);
}

fn void strings_and_binaries() @test
{
	assert(dec_fault("03 00 02 C0 80", PropContext.PUBLISH) == mqtt::INVALID_UTF8);
	assert(dec_fault("03 00 05 61", PropContext.PUBLISH) == mqtt::MALFORMED_PACKET);
	assert(dec_fault("09 00 05 01", PropContext.PUBLISH) == mqtt::MALFORMED_PACKET);
	assert(dec_fault("26 00 01 6B 00", PropContext.PUBLISH) == mqtt::MALFORMED_PACKET);       // pair without value
	assert(dec_fault("26 00 01 6B 00 01 C3", PropContext.PUBLISH) == mqtt::INVALID_UTF8);
	// truncated numbers
	assert(dec_fault("11 00 00 00", PropContext.CONNACK) == mqtt::MALFORMED_PACKET);
	assert(dec_fault("13 00", PropContext.CONNACK) == mqtt::MALFORMED_PACKET);
	assert(dec_fault("24", PropContext.CONNACK) == mqtt::MALFORMED_PACKET);
	// empty binary and string are fine
	Properties p = dec("09 00 00 03 00 00", PropContext.PUBLISH);
	assert(p.correlation_data.len == 0 && p.content_type.len == 0);
}

fn void block_length_rules() @test
{
	// the reader stops at the end of the block; following bytes belong to the packet
	ByteReader r = wire::reader(hx("02 24 01 AA BB"));
	Properties p = r.properties(PropContext.CONNACK)!!;
	assert(p.maximum_qos == 1);
	assert(r.remaining() == 2);
	// non-minimal length prefix
	ByteReader bad = wire::reader(hx("80 00"));
	assert(@catch(bad.properties(PropContext.CONNACK)) == mqtt::MALFORMED_PACKET);
	ByteReader none = wire::reader({});
	assert(@catch(none.properties(PropContext.CONNACK)) == mqtt::MALFORMED_PACKET);
}

// ---- encode refusals ----

fn void encode_refuses_bad_properties() @test
{
	char[64] buf;
	{
		Properties p;
		p.set(PropId.TOPIC_ALIAS);
		p.topic_alias = 1;
		ByteWriter w = wire::writer(buf[..]);
		assert(@catch(w.properties(&p, PropContext.CONNECT)) == mqtt::INVALID_PROPERTY, "Topic Alias is not a CONNECT property");
		assert(w.pos == 0);
	}
	{
		Properties p;
		p.set(PropId.RECEIVE_MAXIMUM);                      // value 0
		assert(@catch(props::properties_size(&p, PropContext.CONNECT)) == mqtt::INVALID_PROPERTY);
	}
	{
		Properties p;
		p.set(PropId.MAXIMUM_QOS);
		p.maximum_qos = 2;
		assert(@catch(props::properties_size(&p, PropContext.CONNACK)) == mqtt::INVALID_PROPERTY);
	}
	{
		Properties p;
		p.set(PropId.REASON_STRING);
		p.reason_string = (String)hx("C0 80");
		assert(@catch(props::properties_size(&p, PropContext.CONNACK)) == mqtt::INVALID_UTF8);
	}
	{
		uint[1] ids = { 0 };
		Properties p;
		p.subscription_ids = ids[..];
		assert(@catch(props::properties_size(&p, PropContext.PUBLISH)) == mqtt::INVALID_PROPERTY);
		uint[1] big = { 268_435_456 };
		p.subscription_ids = big[..];
		assert(@catch(props::properties_size(&p, PropContext.PUBLISH)) == mqtt::INVALID_PROPERTY);
	}
	{
		Properties p;
		p.set(PropId.SESSION_EXPIRY_INTERVAL);
		p.session_expiry = 1;
		char[3] small;
		small[..] = 0x55;
		ByteWriter w = wire::writer(small[..]);
		assert(@catch(w.properties(&p, PropContext.CONNECT)) == mqtt::BUFFER_TOO_SMALL);
		assert(small[0] == 0x55 && w.pos == 0, "nothing written");
	}
}

// ---- stress: many duplicates, many user properties ----

fn void stress_65535_duplicates_are_rejected() @test
{
	char[] body = mem::temp_array(char, 2 * 65_535);
	for (usz i = 0; i < 65_535; i++)
	{
		body[2 * i] = 0x01;
		body[2 * i + 1] = 0x00;
	}
	char[] b = mem::temp_array(char, body.len + 4);
	usz n = wire::vbi_encode((uint)body.len, b[..])!!;
	b[n:body.len] = body[..];
	ByteReader r = wire::reader(b[:n + body.len]);
	assert(@catch(r.properties(PropContext.PUBLISH)) == mqtt::INVALID_PROPERTY);
}

fn void stress_10000_user_properties() @test
{
	// 10 000 pairs `k`=`v`: no cap in the codec, linear time, all of them reachable through the iterator
	char[] pair = hx("26 00 01 6B 00 01 76");
	char[] body = mem::temp_array(char, 7 * 10_000);
	for (usz i = 0; i < 10_000; i++) body[7 * i:7] = pair[..];
	char[] b = mem::temp_array(char, body.len + 4);
	usz n = wire::vbi_encode((uint)body.len, b[..])!!;
	b[n:body.len] = body[..];
	ByteReader r = wire::reader(b[:n + body.len]);
	Properties p = r.properties(PropContext.PUBLISH)!!;
	UserPropIter it = p.user_props();
	UserProperty u;
	int count;
	while (it.next(&u)!!) count++;
	assert(count == 10_000);
}
