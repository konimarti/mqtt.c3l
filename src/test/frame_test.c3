module mqtt::frame_test;
import mqtt, mqtt::packet, mqtt::testutil, std::io;

// Every valid 3.1.1 fixture of the codec tests (CONNECT, CONNACK, PUBLISH, acknowledgements,
// SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT). The 200-byte
// PUBLISH is built in valid_frames().
const String[*] VALID = {
	"10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61",
	"10 19 00 04 4D 51 54 54 04 EE 00 0A 00 01 63 00 01 77 00 01 6D 00 01 75 00 01 70",
	"10 0C 00 04 4D 51 54 54 04 02 00 3C 00 00",
	"10 0C 00 04 4D 51 54 54 04 00 00 3C 00 00",
	"20 02 00 00", "20 02 01 00", "20 02 00 01", "20 02 00 02", "20 02 00 03", "20 02 00 04", "20 02 00 05",
	"30 07 00 03 61 2F 62 68 69",
	"32 09 00 03 61 2F 62 00 0A 68 69",
	"33 09 00 03 61 2F 62 00 0A 68 69",
	"3A 09 00 03 61 2F 62 00 0A 68 69",
	"34 06 00 01 61 00 07 78",
	"3C 06 00 01 61 00 07 78",
	"31 05 00 03 61 2F 62",
	"40 02 00 0A", "50 02 00 0A", "62 02 00 0A", "70 02 00 0A",
	"C0 00", "D0 00", "E0 00",
	"82 08 00 01 00 03 61 2F 23 01",
	"82 0E 00 05 00 03 61 2F 62 00 00 03 63 2F 2B 02",
	"90 03 00 01 01", "90 04 00 05 00 80",
	"A2 07 00 02 00 03 61 2F 23",
	"B0 02 00 02",
};

fn char[][] valid_frames()
{
	char[][] list = mem::temp_array(char[], VALID.len + 1);
	foreach (i, h : VALID) list[i] = testutil::hex(h);
	char[] big = mem::temp_array(char, 206);
	char[] head = testutil::hex("30 CB 01 00 01 74");
	big[:head.len] = head[..];
	big[head.len:200] = 'a';
	list[VALID.len] = big[:head.len + 200];
	return list;
}

fn void every_prefix_needs_more() @test
{
	char[][] frames = valid_frames();
	assert(frames.len == 32, "number of valid 3.1.1 vectors");
	io::printfn("frame_test: %d valid fixtures", frames.len);
	foreach (f : frames)
	{
		for (usz n = 0; n < f.len; n++)
		{
			assert(packet::frame_length(f[:n], 0)!! == 0, "strict prefix needs more bytes");
		}
		assert(packet::frame_length(f, 0)!! == f.len, "whole frame");
		assert(packet::frame_length(f, f.len)!! == f.len, "limit equal to the frame is fine");
	}
}

fn void two_frames_back_to_back() @test
{
	char[][] frames = valid_frames();
	char[] ping = testutil::hex("C0 00");
	foreach (f : frames)
	{
		char[] both = mem::temp_array(char, f.len + 2);
		both[:f.len] = f[..];
		both[f.len:2] = ping[..];
		assert(packet::frame_length(both, 0)!! == f.len, "first frame only");
		assert(packet::frame_length(both[f.len..], 0)!! == 2);
	}
}

fn void byte_by_byte_equals_whole() @test
{
	foreach (f : valid_frames())
	{
		char[] stream = mem::temp_array(char, f.len);
		usz have;
		usz done;
		for (usz i = 0; i < f.len; i++)
		{
			stream[have++] = f[i];
			usz n = packet::frame_length(stream[:have], 0)!!;
			if (n != 0)
			{
				done = n;
				assert(i == f.len - 1, "complete only at the last byte");
			}
		}
		assert(done == f.len);
		Packet a = packet::decode(Version.V311, stream[:have])!!;
		Packet b = packet::decode(Version.V311, f)!!;
		char[512] ea;
		char[512] eb;
		usz? ra = packet::encode(Version.V311, &a, ea[..]);
		usz? rb = packet::encode(Version.V311, &b, eb[..]);
		if (catch err = ra)
		{
			// the one fixture that decodes but must not encode (empty id without clean session)
			assert(@catch(rb) == err);
			continue;
		}
		assert(ea[:ra] == eb[:rb!!]);
	}
}

// one packet of each of the 14 types of 3.1.1: encode, decode, encode again
fn void all_14_types_round_trip() @test
{
	SubEntry[1] entries = { { .filter = "a/b", .qos = QoS.EXACTLY_ONCE } };
	String[1] filters = { "a/b" };
	char[2] codes = { 2, 0x80 };
	int seen;
	for (char t = 1; t <= 14; t++)
	{
		Packet p;
		p.type = (PacketType)t;
		switch (t)
		{
			case 1: p.connect = { .client_id = "id", .clean_start = true, .keep_alive = 30 };
			case 2: p.connack = { .session_present = true, .code = 0 };
			case 3: p.publish = { .qos = QoS.AT_LEAST_ONCE, .topic = "t", .packet_id = 9, .payload = testutil::hex("01 02") };
			case 4:
			case 5:
			case 6:
			case 7: p.ack = { .packet_id = 77 };
			case 8: p.subscribe = { .packet_id = 3, .entries = entries[..] };
			case 9: p.suback = { .packet_id = 3, .codes = codes[..] };
			case 10: p.unsubscribe = { .packet_id = 4, .filters = filters[..] };
			case 11: p.suback = { .packet_id = 4 };
			default: break;                                    // PINGREQ, PINGRESP, DISCONNECT
		}
		char[64] a;
		usz n = packet::encode(Version.V311, &p, a[..])!!;
		Packet d = packet::decode(Version.V311, a[:n])!!;
		assert(d.type == p.type);
		char[64] b;
		usz m = packet::encode(Version.V311, &d, b[..])!!;
		assert(a[:n] == b[:m], "second encoding is identical");
		seen++;
	}
	assert(seen == 14);
}
