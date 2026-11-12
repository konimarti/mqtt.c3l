module mqtt::wire_test;
import mqtt, mqtt::wire, mqtt::testutil;

fn void check_vbi(String h, uint value)
{
	char[] b = testutil::hex(h);
	usz used;
	uint v = wire::vbi_decode(b, &used)!!;
	assert(v == value, "decoded value");
	assert(used == b.len, "consumed all bytes");
	char[4] enc;
	usz n = wire::vbi_encode(value, enc[..])!!;
	assert(n == b.len, "encoded length");
	assert(enc[:n] == b, "encoded bytes");
	assert(wire::vbi_size(value) == b.len, "vbi_size");
}

fn void expect_vbi_fault(String h, fault expected)
{
	usz used;
	fault f = @catch(wire::vbi_decode(testutil::hex(h), &used));
	assert(f == expected, "wrong fault");
}

fn void vec_V_VBI_1() @test { check_vbi("00", 0); }
fn void vec_V_VBI_2() @test { check_vbi("7F", 127); }
fn void vec_V_VBI_3() @test { check_vbi("80 01", 128); }
fn void vec_V_VBI_4() @test { check_vbi("FF 7F", 16_383); }
fn void vec_V_VBI_5() @test { check_vbi("80 80 01", 16_384); }
fn void vec_V_VBI_6() @test { check_vbi("FF FF 7F", 2_097_151); }
fn void vec_V_VBI_7() @test { check_vbi("80 80 80 01", 2_097_152); }
fn void vec_V_VBI_8() @test { check_vbi("FF FF FF 7F", 268_435_455); }
fn void vec_V_VBI_9() @test { check_vbi("C1 02", 321); }
fn void vec_V_VBI_10() @test { check_vbi("CB 01", 203); }
fn void vec_V_VBI_11() @test { check_vbi("E8 07", 1000); }

fn void vec_V_VBI_N1() @test { expect_vbi_fault("80 80 80 80 01", mqtt::MALFORMED_PACKET); }
fn void vec_V_VBI_N2() @test { expect_vbi_fault("FF FF FF FF 7F", mqtt::MALFORMED_PACKET); }
fn void vec_V_VBI_N3() @test { expect_vbi_fault("80", mqtt::INCOMPLETE); }
fn void vec_V_VBI_N4() @test { expect_vbi_fault("FF FF FF", mqtt::INCOMPLETE); }
fn void vec_V_VBI_N5() @test { expect_vbi_fault("80 00", mqtt::MALFORMED_PACKET); }
fn void vec_V_VBI_N6() @test { expect_vbi_fault("80 80 80 80", mqtt::MALFORMED_PACKET); }

fn void vbi_empty_input() @test { expect_vbi_fault("", mqtt::INCOMPLETE); }

fn void vbi_non_minimal_longer() @test
{
	expect_vbi_fault("80 80 00", mqtt::MALFORMED_PACKET);
	expect_vbi_fault("FF 80 00", mqtt::MALFORMED_PACKET);
	expect_vbi_fault("80 80 80 00", mqtt::MALFORMED_PACKET);
}

fn void vbi_consumes_only_its_bytes() @test
{
	usz used;
	uint v = wire::vbi_decode(testutil::hex("E8 07 C0 00"), &used)!!;
	assert(v == 1000 && used == 2);
}

fn void vbi_encode_limits() @test
{
	char[4] out;
	assert(@catch(wire::vbi_encode(268_435_456, out[..])) == mqtt::INVALID_ARGUMENT);
	assert(wire::vbi_size(268_435_456) == 0);
	assert(@catch(wire::vbi_encode(128, out[:1])) == mqtt::BUFFER_TOO_SMALL);
	assert(@catch(wire::vbi_encode(0, out[:0])) == mqtt::BUFFER_TOO_SMALL);
}

fn void vbi_round_trip_boundaries() @test
{
	uint[] values = { 0, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_454, 268_435_455 };
	foreach (v : values)
	{
		char[4] enc;
		usz n = wire::vbi_encode(v, enc[..])!!;
		usz used;
		assert(wire::vbi_decode(enc[:n], &used)!! == v);
		assert(used == n);
	}
}

// ---- UTF-8: the string bytes of the V-STR vectors ----

fn void expect_utf8_ok(String h)
{
	char[] b = testutil::hex(h);
	assert(!@catch(wire::validate_utf8((String)b)), "should be valid");
}

fn void expect_utf8_bad(String h)
{
	char[] b = testutil::hex(h);
	assert(@catch(wire::validate_utf8((String)b)) == mqtt::INVALID_UTF8, "should be invalid");
}

fn void vec_V_STR_1() @test { expect_utf8_ok("C3 A9"); }
fn void vec_V_STR_2() @test { expect_utf8_ok("F0 9F 98 80"); }
fn void vec_V_STR_3() @test { expect_utf8_ok("F4 8F BF BF"); }
fn void vec_V_STR_4() @test { expect_utf8_ok("EF BF BF"); }
fn void vec_V_STR_5() @test
{
	// byte order mark is a plain character: valid, and the bytes are returned as they are
	char[] framed = testutil::hex("00 03 EF BB BF");
	ByteReader r = wire::reader(framed);
	String s = r.string()!!;
	assert(s.len == 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF);
}
fn void vec_V_STR_N1() @test { expect_utf8_bad("61 00 62"); }
fn void vec_V_STR_N2() @test { expect_utf8_bad("C0 80"); }
fn void vec_V_STR_N3() @test { expect_utf8_bad("ED A0 80"); }
fn void vec_V_STR_N4() @test { expect_utf8_bad("ED BF BF"); }
fn void vec_V_STR_N5() @test { expect_utf8_bad("F4 90 80 80"); }
fn void vec_V_STR_N6() @test { expect_utf8_bad("61 FF 62"); }
fn void vec_V_STR_N7() @test { expect_utf8_bad("C3 41"); }
fn void vec_V_STR_N8() @test { expect_utf8_bad("80"); }
fn void vec_V_STR_N9() @test { expect_utf8_bad("E2 82"); }
fn void vec_V_STR_N10() @test { expect_utf8_bad("E0 80 80"); }
fn void vec_V_STR_N11() @test
{
	// length prefix 9, only 2 bytes follow
	ByteReader r = wire::reader(testutil::hex("00 09 61 62"));
	assert(@catch(r.string()) == mqtt::INCOMPLETE);
}
fn void vec_V_STR_N12() @test
{
	ByteReader r = wire::reader(testutil::hex("00 05 61"));
	assert(@catch(r.string()) == mqtt::INCOMPLETE);
}

fn void utf8_more_boundaries() @test
{
	expect_utf8_ok("");
	expect_utf8_ok("7F");                // DEL is only a SHOULD NOT
	expect_utf8_ok("01 1F");             // control characters are only a SHOULD NOT
	expect_utf8_ok("C2 80");             // lowest 2-byte
	expect_utf8_ok("DF BF");             // highest 2-byte
	expect_utf8_ok("E0 A0 80");          // lowest 3-byte
	expect_utf8_ok("ED 9F BF");          // just below the surrogates
	expect_utf8_ok("EE 80 80");          // just above the surrogates
	expect_utf8_ok("F0 90 80 80");       // lowest 4-byte
	expect_utf8_bad("C1 BF");            // overlong
	expect_utf8_bad("F0 8F BF BF");      // overlong 4-byte
	expect_utf8_bad("F5 80 80 80");      // above U+10FFFF
	expect_utf8_bad("FF");
	expect_utf8_bad("F0 90 80");         // truncated 4-byte
	expect_utf8_bad("E2 28 A1");         // bad continuation byte in the middle
}

fn void utf8_length_limit() @test
{
	char[] big = mem::temp_array(char, 65_536);
	big[..] = 'a';
	assert(!@catch(wire::validate_utf8((String)big[:65_535])), "65535 bytes are fine");
	assert(@catch(wire::validate_utf8((String)big[:65_536])) == mqtt::INVALID_UTF8, "65536 bytes are too long");
}

// ---- Reader / Writer ----

fn void reader_big_endian() @test
{
	ByteReader r = wire::reader(testutil::hex("12 34 AB CD EF 01 02"));
	assert(r.u8()!! == 0x12);
	assert(r.u8()!! == 0x34);
	assert(r.u16()!! == 0xABCD);
	assert(r.remaining() == 3);
	assert(@catch(r.u32()) == mqtt::INCOMPLETE);
	assert(r.pos == 4, "a failed read consumes nothing");
	assert(r.u8()!! == 0xEF);
	assert(r.rest().len == 2);
	ByteReader r2 = wire::reader(testutil::hex("01 02 03 04"));
	assert(r2.u32()!! == 0x01020304);
	assert(@catch(r2.u8()) == mqtt::INCOMPLETE);
}

fn void reader_string_and_binary() @test
{
	ByteReader r = wire::reader(testutil::hex("00 03 61 2F 62 00 02 FF 00 00 00 DE"));
	String s = r.string()!!;
	assert(s == "a/b");
	char[] b = r.binary()!!;
	assert(b.len == 2 && b[0] == 0xFF && b[1] == 0x00, "binary may hold any byte");
	char[] empty = r.binary()!!;
	assert(empty.len == 0);
	assert(r.u8()!! == 0xDE);
	assert(r.remaining() == 0);
}

fn void reader_string_rejects_bad_utf8_without_consuming() @test
{
	ByteReader r = wire::reader(testutil::hex("00 02 C0 80 00 01 41"));
	assert(@catch(r.string()) == mqtt::INVALID_UTF8);
	assert(r.pos == 0);
}

fn void reader_take_and_vbi() @test
{
	ByteReader r = wire::reader(testutil::hex("E8 07 01 02 03"));
	assert(r.vbi()!! == 1000);
	char[] t = r.take(2)!!;
	assert(t.len == 2 && t[0] == 1 && t[1] == 2);
	assert(@catch(r.take(2)) == mqtt::INCOMPLETE);
	assert(r.pos == 4);
	ByteReader bad = wire::reader(testutil::hex("80 00"));
	assert(@catch(bad.vbi()) == mqtt::MALFORMED_PACKET);
	assert(bad.pos == 0);
}

fn void writer_big_endian() @test
{
	char[32] buf;
	ByteWriter w = wire::writer(buf[..]);
	w.u8(0x12)!!;
	w.u16(0xABCD)!!;
	w.u32(0x01020304)!!;
	w.vbi(1000)!!;
	w.string("a/b")!!;
	w.binary(testutil::hex("FF 00"))!!;
	assert(w.written() == testutil::hex("12 AB CD 01 02 03 04 E8 07 00 03 61 2F 62 00 02 FF 00"));
}

fn void writer_buffer_too_small() @test
{
	char[3] buf;
	ByteWriter w = wire::writer(buf[..]);
	w.u16(0x0102)!!;
	assert(@catch(w.u16(0x0304)) == mqtt::BUFFER_TOO_SMALL);
	assert(w.pos == 2, "a failed write writes nothing");
	assert(@catch(w.u32(1)) == mqtt::BUFFER_TOO_SMALL);
	assert(@catch(w.string("abc")) == mqtt::BUFFER_TOO_SMALL);
	assert(@catch(w.raw(testutil::hex("01 02"))) == mqtt::BUFFER_TOO_SMALL);
	assert(@catch(w.vbi(300)) == mqtt::BUFFER_TOO_SMALL);
	w.u8(9)!!;
	assert(@catch(w.u8(9)) == mqtt::BUFFER_TOO_SMALL);
	assert(w.written() == testutil::hex("01 02 09"));
}

fn void writer_string_validation() @test
{
	char[64] buf;
	ByteWriter w = wire::writer(buf[..]);
	assert(@catch(w.string((String)testutil::hex("C0 80"))) == mqtt::INVALID_UTF8);
	assert(w.pos == 0);
	assert(@catch(w.vbi(268_435_456)) == mqtt::INVALID_ARGUMENT);
	w.string("")!!;
	assert(w.written() == testutil::hex("00 00"));
}

fn void writer_string_length_limit() @test
{
	char[] big = mem::temp_array(char, 70_000);
	big[..] = 'a';
	char[] out = mem::temp_array(char, 70_000);
	ByteWriter w = wire::writer(out);
	w.string((String)big[:65_535])!!;
	assert(w.pos == 65_537);
	ByteWriter w2 = wire::writer(out);
	assert(@catch(w2.string((String)big[:65_536])) == mqtt::INVALID_UTF8);
	assert(@catch(w2.binary(big[:65_536])) == mqtt::INVALID_ARGUMENT);
}

fn void reader_writer_round_trip() @test
{
	char[64] buf;
	ByteWriter w = wire::writer(buf[..]);
	w.u16(7)!!;
	w.string("héllo")!!;
	w.vbi(321)!!;
	w.binary(testutil::hex("00 01 02"))!!;
	ByteReader r = wire::reader(w.written());
	assert(r.u16()!! == 7);
	assert(r.string()!! == "héllo");
	assert(r.vbi()!! == 321);
	assert(r.binary()!! == testutil::hex("00 01 02"));
	assert(r.remaining() == 0);
}
