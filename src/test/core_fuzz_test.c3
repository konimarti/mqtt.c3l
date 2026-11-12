module mqtt::core_fuzz_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::packet, mqtt::wire, mqtt::testutil;
import std::core::mem::allocators, std::core::env, std::collections::list, std::io, std::time;

// Robustness of the codec and the session core: deterministic mutation of every valid vector and of
// scripted server streams, the robustness expectations of TEST-VECTORS section 11, and no crash,
// no out-of-bounds read (run with sanitize=address), only the library's own faults, no leak and
// memory under the configured caps.

const CONNACK_311 = "20 02 00 00";
const CONNACK_5 = "20 03 00 00 00";

const usz MIN_MUTATED = 20_000;
const usz RANDOM_STRINGS = env::ADDRESS_SANITIZER ? 20_000 : 1_000_000;
const usz MUTATION_CAP = 2 * 1024 * 1024;       // peak bytes held by one core on a small input

// ---- deterministic generator (xorshift64) ----

struct Rng
{
	ulong state;
}

fn ulong Rng.next(&self)
{
	ulong x = self.state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	self.state = x;
	return x;
}

// 0..n-1
fn usz Rng.below(&self, usz n) => n == 0 ? 0 : (usz)(self.next() % n);

// ---- corpus: every valid vector of TEST-VECTORS sections 4 and 6, and server scripts ----

struct Vec
{
	Version version;
	char[] bytes;
	bool stream;                    // several frames
}

const String[*] V311_HEX = {
	"10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61",
	"10 19 00 04 4D 51 54 54 04 EE 00 0A 00 01 63 00 01 77 00 01 6D 00 01 75 00 01 70",
	"10 0C 00 04 4D 51 54 54 04 02 00 3C 00 00",
	"20 02 00 00", "20 02 01 00", "20 02 00 01", "20 02 00 02", "20 02 00 03", "20 02 00 04", "20 02 00 05",
	"30 07 00 03 61 2F 62 68 69",
	"32 09 00 03 61 2F 62 00 0A 68 69",
	"33 09 00 03 61 2F 62 00 0A 68 69",
	"3A 09 00 03 61 2F 62 00 0A 68 69",
	"34 06 00 01 61 00 07 78",
	"3C 06 00 01 61 00 07 78",
	"31 05 00 03 61 2F 62",
	"40 02 00 0A", "50 02 00 0A", "62 02 00 0A", "70 02 00 0A",
	"82 08 00 01 00 03 61 2F 23 01",
	"82 0E 00 05 00 03 61 2F 62 00 00 03 63 2F 2B 02",
	"90 03 00 01 01", "90 04 00 05 00 80",
	"A2 07 00 02 00 03 61 2F 23",
	"B0 02 00 02",
	"C0 00", "D0 00", "E0 00",
};

const String[*] V5_HEX = {
	"10 0E 00 04 4D 51 54 54 05 02 00 3C 00 00 01 61",
	"10 16 00 04 4D 51 54 54 05 02 00 3C 08 11 00 00 0E 10 21 00 14 00 01 61",
	"10 15 00 04 4D 51 54 54 05 06 00 0A 00 00 01 63 00 00 01 77 00 01 6D",
	"10 0D 00 04 4D 51 54 54 05 02 00 3C 00 00 00",
	"20 03 00 00 00", "20 03 01 00 00",
	"20 09 00 00 06 22 00 0A 13 00 1E",
	"20 07 00 9C 04 1C 00 01 62",
	"20 03 00 87 00",
	"30 08 00 03 61 2F 62 00 68 69",
	"32 09 00 00 00 01 03 23 00 01 78",
	"32 0A 00 01 61 00 01 03 23 00 01 78",
	"30 06 00 01 61 02 0B 05",
	"40 02 00 0A", "40 03 00 0A 00", "40 04 00 0A 10 00", "40 04 00 0A 87 00",
	"50 04 00 0A 97 00",
	"62 02 00 0A", "62 03 00 0A 92",
	"70 02 00 0A", "70 03 00 0A 92",
	"82 09 00 01 00 00 03 61 2F 23 01",
	"82 0B 00 01 02 0B 05 00 03 61 2F 23 01",
	"82 09 00 01 00 00 03 61 2F 23 2E",
	"90 04 00 01 00 01", "90 05 00 01 00 02 8F", "90 04 00 01 00 9E",
	"A2 08 00 02 00 00 03 61 2F 23",
	"B0 04 00 02 00 00", "B0 04 00 02 00 11",
	"E0 00", "E0 01 04", "E0 02 04 00",
	"E0 0B 9C 09 1C 00 06 68 6F 73 74 3A 31",
	"F0 06 18 04 15 00 01 61",
	"C0 00", "D0 00",
};

// What a server sends in a session where the client has a SUBSCRIBE (id 3), a QoS 1 (id 1) and a QoS 2
// (id 2) PUBLISH in flight: the acknowledgements, then deliveries of its own.
const String SCRIPT_311 = "90 03 00 03 01 40 02 00 01 50 02 00 02 70 02 00 02 34 06 00 01 61 00 07 78 62 02 00 07 32 09 00 03 61 2F 62 00 0A 68 69 30 07 00 03 61 2F 62 68 69 D0 00";
const String SCRIPT_5 = "90 04 00 03 00 01 40 04 00 01 10 00 50 04 00 02 00 00 70 03 00 02 92 34 07 00 01 61 00 07 00 78 62 02 00 07 32 0A 00 03 61 2F 62 00 0A 00 68 69 30 08 00 03 61 2F 62 00 68 69 D0 00 E0 00";

fn Vec[] corpus()
{
	usz total = V311_HEX.len + V5_HEX.len + 2 + 2;
	Vec[] out = mem::temp_array(Vec, (sz)total);
	usz n;
	foreach (h : V311_HEX) out[n++] = { Version.V311, testutil::hex(h), false };
	foreach (h : V5_HEX) out[n++] = { Version.V5, testutil::hex(h), false };
	// a 200 byte payload (remaining length of two bytes) in both versions
	char[] big311 = mem::temp_array(char, 206);
	big311[0] = 0x30;
	big311[1] = 0xCB;
	big311[2] = 0x01;
	big311[3] = 0x00;
	big311[4] = 0x01;
	big311[5] = 't';
	big311[6..] = 'a';
	out[n++] = { Version.V311, big311, false };
	char[] big5 = mem::temp_array(char, 207);
	big5[0] = 0x30;
	big5[1] = 0xCC;
	big5[2] = 0x01;
	big5[3] = 0x00;
	big5[4] = 0x01;
	big5[5] = 't';
	big5[6] = 0x00;
	big5[7..] = 'a';
	out[n++] = { Version.V5, big5, false };
	out[n++] = { Version.V311, testutil::hex(SCRIPT_311), true };
	out[n++] = { Version.V5, testutil::hex(SCRIPT_5), true };
	return out[:n];
}

// ---- running bytes against a core ----

struct Outcome
{
	bool failed;
	fault err;
	EventKind[] kinds;
	char[] output;
	ulong sum;                      // every byte of every delivered message, so out-of-bounds reads show up
}

// Only faults the library defines may come out of the core.
const fault[*] LIB_FAULTS = {
	mqtt::MALFORMED_PACKET, mqtt::PROTOCOL_ERROR, mqtt::PACKET_TOO_LARGE, mqtt::BUFFER_TOO_SMALL,
	mqtt::INCOMPLETE, mqtt::INVALID_UTF8, mqtt::INVALID_TOPIC_NAME, mqtt::INVALID_TOPIC_FILTER,
	mqtt::INVALID_PROPERTY, mqtt::INVALID_ARGUMENT, mqtt::UNSUPPORTED_VERSION, mqtt::NOT_CONNECTED,
	mqtt::ALREADY_CONNECTED, mqtt::PACKET_ID_EXHAUSTED, mqtt::SEND_QUOTA_EXHAUSTED, mqtt::QUEUE_FULL,
	mqtt::NOT_SUPPORTED_BY_SERVER, mqtt::CONNECTION_REFUSED, mqtt::KEEPALIVE_TIMEOUT,
	mqtt::TOPIC_ALIAS_INVALID, mqtt::RECEIVE_MAXIMUM_EXCEEDED, mqtt::PAYLOAD_FORMAT_INVALID, mqtt::CLOSED, mqtt::TIMEOUT,
	mqtt::AUTH_FAILED, mqtt::SERVER_DISCONNECTED,
};

fn bool is_lib_fault(fault f)
{
	foreach (known : LIB_FAULTS)
	{
		if (known == f) return true;
	}
	return false;
}

fn Config cfg(Version v)
{
	Config c = core::default_config(v, "fz");
	c.max_in_buffer = 128 * 1024;
	c.max_out_buffer = 64 * 1024;
	c.max_packet_size = 64 * 1024;
	return c;
}

// An accepted session with a SUBSCRIBE (id 3), a QoS 1 (id 1) and a QoS 2 (id 2) PUBLISH in flight, and the
// output taken as written.
fn void open_with_flows(Session* s, Config* c)
{
	s.open(c, c.version == Version.V5 ? CONNACK_5 : CONNACK_311);
	OutMessage a = { .topic = "t", .payload = { 'x' }, .qos = QoS.AT_LEAST_ONCE };
	OutMessage b = { .topic = "t", .payload = { 'y' }, .qos = QoS.EXACTLY_ONCE };
	assert(s.core.publish(s.clock.now, &a)!! == 1);
	assert(s.core.publish(s.clock.now, &b)!! == 2);
	SubEntry[1] entries = { { .filter = "a/#" } };
	assert(s.core.subscribe(s.clock.now, entries[..], null)!! == 3);
	s.core.output_done(s.core.pending_output().len);
}

// Takes every event (touching the bytes they point to) and the output.
fn void absorb(Session* s, Outcome* o, List{EventKind}* kinds, List{char}* out)
{
	Event ev;
	while (s.core.poll_event(&ev))
	{
		kinds.push(ev.kind);
		switch (ev.kind)
		{
			case EventKind.MESSAGE:
				foreach (c : ev.message.topic) o.sum += c;
				foreach (c : ev.message.payload) o.sum += c;
			case EventKind.SUBSCRIBED:
				foreach (c : ev.suback.codes) o.sum += c;
			case EventKind.CLOSED:
				foreach (c : ev.closed.server_reference) o.sum += c;
			default:
				break;
		}
	}
	char[] pending = s.core.pending_output();
	out.push_all(pending);
	s.core.output_done(pending.len);
}

// Feeds data to the core, `chunk` bytes at a time (0 = at once). A fault ends the connection the way the
// adapter does: take what is queued, then transport_closed.
fn Outcome run_feed(Session* s, char[] data, usz chunk)
{
	Outcome o;
	List{EventKind} kinds;
	List{char} out;
	kinds.tinit();
	out.tinit();
	usz pos;
	while (pos < data.len)
	{
		usz n = data.len - pos;
		if (chunk != 0 && chunk < n) n = chunk;
		if (catch err = s.core.input(s.clock.now, data[pos:n]))
		{
			assert(is_lib_fault(err), "only library faults");
			o.failed = true;
			o.err = err;
			absorb(s, &o, &kinds, &out);
			s.core.transport_closed(s.clock.now);
			absorb(s, &o, &kinds, &out);
			assert(@catch(s.core.input(s.clock.now, data[pos:1])) == mqtt::NOT_CONNECTED, "closed core refuses input");
			break;
		}
		absorb(s, &o, &kinds, &out);
		pos += n;
	}
	o.kinds = kinds.array_view();
	o.output = out.array_view();
	// caps: undelivered input and encoded output stay under the configured limits
	assert((usz)s.core.in_buf.len() <= s.core.config.effective_max_in_buffer(), "in buffer cap");
	assert(s.core.pending_output().len <= s.core.config.effective_max_out_buffer(), "out buffer cap");
	assert((usz)s.mem_track.max_allocated() <= MUTATION_CAP, "memory stays under the cap");
	return o;
}

fn bool same_outcome(Outcome* a, Outcome* b)
{
	if (a.failed != b.failed || a.sum != b.sum) return false;
	if (a.failed && a.err != b.err) return false;
	return a.kinds == b.kinds && a.output == b.output;
}

// one case on a fresh session with flows
fn Outcome run_case(Version v, char[] data, usz chunk)
{
	Session s;
	Config c = cfg(v);
	open_with_flows(&s, &c);
	Outcome o = run_feed(&s, data, chunk);
	s.close();
	return o;
}

// ---- mutation ----

fn char[] mutate(Rng* r, char[] src, Vec[] all)
{
	usz rounds = 1 + r.below(3);
	char[] cur = mem::temp_array(char, (sz)src.len);
	cur[..] = src[..];
	for (usz k = 0; k < rounds; k++)
	{
		switch (r.below(9))
		{
			case 0:                                       // bit flip
				if (cur.len > 0) cur[r.below(cur.len)] ^= (char)(1 << r.below(8));
			case 1:                                       // truncation
				if (cur.len > 0) cur = cur[:r.below(cur.len)];
			case 2:                                       // length field edit (the byte after the type)
				if (cur.len > 1) cur[1 + r.below(cur.len > 4 ? 3 : cur.len - 1)] = (char)r.next();
			case 3:                                       // duplication of the whole input
				char[] d = mem::temp_array(char, (sz)(cur.len * 2));
				d[:cur.len] = cur[..];
				d[cur.len..] = cur[..];
				cur = d;
			case 4:                                       // concatenation with another vector (or a prefix of one)
				char[] other = all[r.below(all.len)].bytes;
				if (r.below(2) == 0) other = other[:r.below(other.len + 1)];
				char[] cat = mem::temp_array(char, (sz)(cur.len + other.len));
				cat[:cur.len] = cur[..];
				cat[cur.len..] = other[..];
				cur = cat;
			case 5:                                       // replace a byte
				if (cur.len > 0) cur[r.below(cur.len)] = (char)r.next();
			case 6:                                       // insert a byte
				usz at = r.below(cur.len + 1);
				char[] ins = mem::temp_array(char, (sz)(cur.len + 1));
				ins[:at] = cur[:at];
				ins[at] = (char)r.next();
				ins[at + 1..] = cur[at..];
				cur = ins;
			case 7:                                       // delete a byte
				if (cur.len > 0)
				{
					usz at = r.below(cur.len);
					char[] del = mem::temp_array(char, (sz)(cur.len - 1));
					del[:at] = cur[:at];
					del[at..] = cur[at + 1..];
					cur = del;
				}
			default:                                      // repeat a slice (a run of the same frame header)
				if (cur.len > 1)
				{
					usz from = r.below(cur.len);
					usz len = 1 + r.below(cur.len - from);
					char[] rep = mem::temp_array(char, (sz)(cur.len + len));
					rep[:cur.len] = cur[..];
					rep[cur.len..] = cur[from:len];
					cur = rep;
				}
		}
	}
	return cur;
}

fn void mutated_vectors() @test
{
	Rng rng = { 0x9E3779B97F4A7C15 };
	usz cases;
	usz faulted;
	usz events;
	@pool()
	{
		Vec[] all = corpus();
		foreach (v : all)
		{
			for (usz i = 0; i < 300; i++)
			{
				@pool()
				{
					char[] data = mutate(&rng, v.bytes, all);
					usz chunk = rng.below(3) == 0 ? 1 + rng.below(7) : 0;
					Outcome o = run_case(v.version, data, chunk);
					cases++;
					if (o.failed) faulted++;
					events += o.kinds.len;
				};
			}
		}
	};
	io::printfn("core_fuzz_test: %d mutated inputs (%d ended the connection, %d events)", cases, faulted, events);
	assert(cases >= MIN_MUTATED, "at least 20000 mutated inputs");
}

// The scripts are valid streams: unmutated they are accepted (the 5.0 one ends with a server DISCONNECT).
fn void scripts_unmutated() @test
{
	char[] s311 = testutil::hex(SCRIPT_311);
	Outcome a = run_case(Version.V311, s311, 0);
	assert(!a.failed, "3.1.1 script accepted");
	Outcome b = run_case(Version.V311, s311, 1);
	assert(same_outcome(&a, &b), "byte by byte equals whole");
	char[] s5 = testutil::hex(SCRIPT_5);
	Outcome c = run_case(Version.V5, s5, 0);
	assert(c.failed && c.err == mqtt::SERVER_DISCONNECTED, "5.0 script ends with the server DISCONNECT");
	Outcome d = run_case(Version.V5, s5, 1);
	assert(same_outcome(&c, &d), "byte by byte equals whole");
}

// ---- TEST-VECTORS section 11 ----

// (1) every proper prefix of a valid vector is "need more", the whole vector is complete and decodes;
// the core accepts the prefixes silently.
fn void section11_prefixes() @test
{
	usz checked;
	@pool()
	{
		foreach (v : corpus())
		{
			if (!v.stream)
			{
				assert(packet::frame_length(v.bytes, 0)!! == v.bytes.len, "whole vector is one frame");
				Packet? p = packet::decode(v.version, v.bytes);
				assert(@ok(p), "valid vector decodes");
			}
			for (usz k = 0; k < v.bytes.len; k++)
			{
				if (k == v.bytes.len) break;
				usz? n = packet::frame_length(v.bytes[:k], 0);
				// the scripts hold several frames: a prefix may contain whole ones
				assert(@ok(n), "a prefix is never an error");
				Session s;
				Config c = cfg(v.version);
				open_with_flows(&s, &c);
				if (n!! == 0)
				{
					Outcome o = run_feed(&s, v.bytes[:k], 0);
					assert(!o.failed || v.bytes.len > k, "no error");
				}
				s.close();
				checked++;
			}
		}
	};
	io::printfn("core_fuzz_test: %d prefixes", checked);
}

// (2) byte by byte equals whole
fn void section11_byte_by_byte() @test
{
	usz checked;
	@pool()
	{
		foreach (v : corpus())
		{
			Outcome whole = run_case(v.version, v.bytes, 0);
			Outcome bytes = run_case(v.version, v.bytes, 1);
			assert(same_outcome(&whole, &bytes), "byte by byte equals whole");
			checked++;
		}
	};
	io::printfn("core_fuzz_test: %d byte-by-byte comparisons", checked);
}

// (3) every single bit flip: a packet or an error, in the codec and in the core
fn void section11_bit_flips() @test
{
	usz flips;
	@pool()
	{
		foreach (v : corpus())
		{
			if (v.bytes.len > 64) continue;              // the long scripts and payloads are covered by mutation
			for (usz bit = 0; bit < v.bytes.len * 8; bit++)
			{
				@pool()
				{
					char[] f = mem::temp_array(char, (sz)v.bytes.len);
					f[..] = v.bytes[..];
					f[bit / 8] ^= (char)(1 << (bit % 8));
					usz? n = packet::frame_length(f, 0);
					if (catch err = n)
					{
						assert(is_lib_fault(err), "framing fault is a library fault");
					}
					else if (n > 0 && n <= f.len)
					{
						Packet? p = packet::decode(v.version, f[:n]);
						if (catch derr = p) assert(is_lib_fault(derr), "decode fault is a library fault");
					}
					Outcome o = run_case(v.version, f, 0);
					assert(!o.failed || is_lib_fault(o.err));
					flips++;
				};
			}
		}
	};
	io::printfn("core_fuzz_test: %d single bit flips", flips);
	assert(flips > 5000);
}

// (4) random byte strings, a fresh core each (a quarter of them before the CONNACK arrives)
fn void section11_random_strings() @test
{
	Rng rng = { 0x2545F4914F6CDD1D };
	String bias = "\x00\x01\x02\x03\x0A\x7F\x80\xFF";
	usz faults;
	TrackingAllocator ta;
	ta.init(mem);
	char[32] data;
	for (usz i = 0; i < RANDOM_STRINGS; i++)
	{
		Version v = rng.below(2) == 0 ? Version.V311 : Version.V5;
		usz len = rng.below(25);
		for (usz k = 0; k < len; k++)
		{
			data[k] = rng.below(2) == 0 ? (char)rng.next() : bias[rng.below(bias.len)];
		}
		if (len > 0 && rng.below(2) == 0) data[0] = (char)(((2 + rng.below(13)) << 4) | rng.below(16));
		Config c = cfg(v);
		Core core;
		core.init(&ta, &c)!!;
		core.connect(time::ms(0))!!;
		core.output_done(core.pending_output().len);
		if (rng.below(4) != 0)
		{
			char[] ack = v == Version.V5 ? { 0x20, 0x03, 0x00, 0x00, 0x00 } : { 0x20, 0x02, 0x00, 0x00 };
			core.input(time::ms(0), ack)!!;
			Event ev;
			while (core.poll_event(&ev)) {}
		}
		if (catch err = core.input(time::ms(1), data[:len]))
		{
			assert(is_lib_fault(err), "only library faults");
			faults++;
		}
		Event ev;
		while (core.poll_event(&ev))
		{
			if (ev.kind == EventKind.MESSAGE)
			{
				ulong sum;
				foreach (b : ev.message.payload) sum += b;
				foreach (b : ev.message.topic) sum += b;
			}
		}
		assert(core.pending_output().len <= c.effective_max_out_buffer());
		core.free();
		assert(ta.allocation_count() == 0, "no leak");
	}
	assert((usz)ta.max_allocated() < 1024 * 1024, "memory stays small");
	ta.free();
	io::printfn("core_fuzz_test: %d random strings (%d ended the connection)", RANDOM_STRINGS, faults);
}

// (5) Remaining Length 268 435 455 against a 1 MiB limit: refused after the header, nothing allocated for it
fn void section11_huge_remaining_length() @test
{
	Version[2] versions = { Version.V311, Version.V5 };
	foreach (v : versions)
	{
		Session s;
		Config c = core::default_config(v, "fz");
		c.max_packet_size = 1024 * 1024;
		s.open(&c, v == Version.V5 ? CONNACK_5 : CONNACK_311);
		char[5] header = { 0x30, 0xFF, 0xFF, 0xFF, 0x7F };
		assert(@catch(s.core.input(s.clock.now, header[..])) == mqtt::PACKET_TOO_LARGE);
		assert(s.mem_track.max_allocated() < (sz)(64 * 1024), "no big allocation");
		s.core.transport_closed(s.clock.now);
		s.close();
		// byte by byte: refused as soon as the length is known
		Session t;
		t.open(&c, v == Version.V5 ? CONNACK_5 : CONNACK_311);
		fault f;
		foreach (b : header)
		{
			char[1] one = { b };
			if (catch err = t.core.input(t.clock.now, one[..]))
			{
				f = err;
				break;
			}
		}
		assert(f == mqtt::PACKET_TOO_LARGE);
		assert(t.mem_track.max_allocated() < (sz)(64 * 1024), "no big allocation");
		t.core.transport_closed(t.clock.now);
		t.close();
	}
}

// the frame of a 5.0 PUBLISH to "a" whose property block is `props`
fn char[] publish5_with(char[] props)
{
	usz plen = props.len;
	char[4] pl;
	usz pl_n = wire::vbi_encode((uint)plen, pl[..])!!;
	usz rl = 3 + pl_n + plen;
	char[4] rlb;
	usz rl_n = wire::vbi_encode((uint)rl, rlb[..])!!;
	char[] f = mem::temp_array(char, (sz)(1 + rl_n + rl));
	usz n;
	f[n++] = 0x30;
	f[n:rl_n] = rlb[:rl_n];
	n += rl_n;
	f[n++] = 0x00;
	f[n++] = 0x01;
	f[n++] = 'a';
	f[n:pl_n] = pl[:pl_n];
	n += pl_n;
	f[n:plen] = props[..];
	return f;
}

// (6) 65 535 one-byte properties (a duplicate of Payload Format Indicator each): refused
fn void section11_property_flood() @test
{
	@pool()
	{
		char[] props = mem::temp_array(char, 65_535 * 2);
		for (usz i = 0; i < 65_535; i++)
		{
			props[2 * i] = 0x01;
			props[2 * i + 1] = 0x00;
		}
		char[] frame = publish5_with(props);
		assert(!@ok(packet::decode(Version.V5, frame)), "refused by the codec");
		Session s;
		Config c = cfg(Version.V5);
		c.max_packet_size = 256 * 1024;
		c.max_in_buffer = 512 * 1024;
		s.open(&c, CONNACK_5);
		if (catch err = s.core.input(s.clock.now, frame))
		{
			assert(is_lib_fault(err), "refused with a library fault");
		}
		else
		{
			assert(false, "refused by the core");
		}
		s.core.transport_closed(s.clock.now);
		assert((usz)s.mem_track.max_allocated() < 2 * 1024 * 1024, "memory bounded");
		s.close();
	};
}

// (7) 10 000 user properties (70 000 bytes): accepted or refused by a cap, memory bounded
fn void section11_user_properties() @test
{
	@pool()
	{
		char[] unit = { 0x26, 0x00, 0x01, 0x6B, 0x00, 0x01, 0x76 };
		char[] props = mem::temp_array(char, 10_000 * 7);
		for (usz i = 0; i < 10_000; i++) props[i * 7:7] = unit[..];
		char[] frame = publish5_with(props);
		Session s;
		Config c = cfg(Version.V5);
		c.max_packet_size = 256 * 1024;
		c.max_in_buffer = 512 * 1024;
		s.open(&c, CONNACK_5);
		Outcome o = run_feed(&s, frame, 0);
		assert(!o.failed || is_lib_fault(o.err));
		assert((usz)s.mem_track.max_allocated() < 2 * 1024 * 1024, "memory bounded");
		s.close();
	};
}

// (8) a subscription to a filter of 65 535 bytes goes out whole and its SUBACK is accepted
fn void section11_long_filter() @test
{
	@pool()
	{
		char[] f = mem::temp_array(char, 65_535);
		for (usz i = 0; i + 1 < 65_535; i += 2)
		{
			f[i] = '+';
			f[i + 1] = '/';
		}
		f[65_534] = '#';
		Session s;
		Config c = core::default_config(Version.V311, "fz");
		s.open(&c, CONNACK_311);
		SubEntry[1] entries = { { .filter = (String)f } };
		assert(s.core.subscribe(s.clock.now, entries[..], null)!! == 1);
		char[] out = s.core.pending_output();
		assert(out.len == 65_544, "SUBSCRIBE frame");
		assert(out[0] == 0x82);
		s.core.output_done(out.len);
		harness::feed(&s.core, &s.clock, "90 03 00 01 01");
		EventKind[] kinds = harness::drain(&s.core);
		assert(kinds.len == 1 && kinds[0] == EventKind.SUBSCRIBED);
		s.close();
	};
}
