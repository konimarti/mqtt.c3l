module mqtt::client_test;
import mqtt, mqtt::client, mqtt::core, mqtt::testutil, mqtt::transport, std::net, std::net::tcp, std::time;

// A transport in memory: what the "server" will send is in `incoming`, what the client wrote is collected
// in `written`. Rules make it answer writes (a CONNACK after the CONNECT, a PUBACK after a PUBLISH). It
// does not list (Transport): it is passed with the cast that a TLS transport from another library needs.
// Time is virtual: a read that finds nothing moves it forward by the timeout it was given, so a test that
// waits for a keep alive of one second takes no time.
struct Rule
{
	char first;                     // first byte of a write that triggers the rule
	char[] reply;                   // bytes that become readable
	bool eof;                       // the link ends after the reply
	bool used;
}

struct Script
{
	char[1024] incoming;
	usz in_len;
	usz pos;
	char[1024] written;
	usz out_len;
	Rule[8] rules;
	usz nrules;
	bool eof;
	bool stall_writes;
	bool closed;
	Duration now;
}

fn void Script.add(&self, String hex)
{
	char[] b = testutil::hex(hex);
	self.incoming[self.in_len:b.len] = b[..];
	self.in_len += b.len;
}

fn void Script.on_write(&self, char first, String reply_hex, bool eof = false)
{
	self.rules[self.nrules++] = { .first = first, .reply = testutil::hex(reply_hex), .eof = eof };
}

fn usz? Script.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (self.pos < self.in_len)
	{
		usz n = self.in_len - self.pos;
		if (n > buf.len) n = buf.len;
		buf[:n] = self.incoming[self.pos:n];
		self.pos += n;
		return n;
	}
	if (self.eof || self.closed) return mqtt::CLOSED~;
	self.now = self.now + timeout;                          // nothing to read: the time passes
	return mqtt::TIMEOUT~;
}

fn void? Script.write(&self, char[] data, Duration timeout) @dynamic
{
	if (self.closed) return mqtt::CLOSED~;
	if (self.stall_writes)
	{
		self.now = self.now + timeout;
		return mqtt::TIMEOUT~;
	}
	self.written[self.out_len:data.len] = data[..];
	self.out_len += data.len;
	for (usz i = 0; i < self.nrules; i++)
	{
		Rule* r = &self.rules[i];
		if (r.used || r.first != data[0]) continue;
		r.used = true;
		self.incoming[self.in_len:r.reply.len] = r.reply[..];
		self.in_len += r.reply.len;
		if (r.eof) self.eof = true;
	}
}

fn void? Script.close(&self) @dynamic
{
	self.closed = true;
}

fn Duration script_clock(void* context) => ((Script*)context).now;

fn Config cfg(ushort keep_alive = 60)
{
	Config c = core::default_config(Version.V311, "a");
	c.keep_alive = keep_alive;
	return c;
}

fn bool wrote(Script* s, String hex)
{
	char[] needle = testutil::hex(hex);
	for (usz i = 0; i + needle.len <= s.out_len; i++)
	{
		if (s.written[i:needle.len] == needle) return true;
	}
	return false;
}

// opens a client on the script, with the CONNACK answering the CONNECT
fn void start(Client* c, Script* s, Config* config)
{
	s.on_write(0x10, "20 02 00 00");
	c.use_clock(&script_clock, s);
	c.open(mem, (Transport)s, config, time::sec(5))!!;
}

fn void client_open() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	assert(c.core.state == State.CONNECTED);
	assert(wrote(&s, "10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61"), "the CONNECT was written");
	assert(!s.closed);
	c.close();
}

fn void client_publish_wait_qos1() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	s.on_write(0x32, "40 02 00 01");
	OutMessage m = { .topic = "a/b", .payload = testutil::hex("68 69"), .qos = QoS.AT_LEAST_ONCE };
	ReasonCode r = c.publish_wait(&m, time::sec(5))!!;
	assert(r == ReasonCode.SUCCESS);
	assert(wrote(&s, "32 09 00 03 61 2F 62 00 01 68 69"));
	assert(c.core.inflight_count() == 0);
	// QoS 0 has nothing to wait for
	OutMessage z = { .topic = "a/b", .payload = testutil::hex("68 69") };
	assert(c.publish_wait(&z, time::sec(5))!! == ReasonCode.SUCCESS);
	assert(wrote(&s, "30 07 00 03 61 2F 62 68 69"));
	c.close();
}

fn void client_subscribe() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	s.on_write(0x82, "90 04 00 01 01 80");
	SubEntry[2] entries = { { .filter = "a/#", .qos = QoS.AT_LEAST_ONCE }, { .filter = "b", .qos = QoS.AT_MOST_ONCE } };
	char[4] codes;
	usz n = c.subscribe(entries[..], codes[..], time::sec(5))!!;
	assert(n == 2 && codes[0] == 1 && codes[1] == 0x80);
	s.on_write(0xA2, "B0 02 00 02");
	String[1] filters = { "a/#" };
	usz m = c.unsubscribe(filters[..], codes[..], time::sec(5))!!;
	assert(m == 0, "a 3.1.1 UNSUBACK carries no codes");
	c.close();
}

fn void client_next_message() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	s.add("30 07 00 03 61 2F 62 68 69");
	Event ev;
	assert(c.next(&ev, time::sec(1))!!);
	assert(ev.kind == EventKind.MESSAGE && ev.message.topic == "a/b" && ev.message.payload == testutil::hex("68 69"));
	// nothing more: the call waits its time and says so
	assert(!c.next(&ev, time::ms(300))!!);
	c.close();
}

fn void client_message_during_wait_not_lost() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	// the server sends a QoS 1 message of its own right before the PUBACK
	s.on_write(0x32, "32 09 00 03 61 2F 62 00 0A 68 69 40 02 00 01");
	OutMessage m = { .topic = "a/b", .payload = testutil::hex("68 69"), .qos = QoS.AT_LEAST_ONCE };
	assert(c.publish_wait(&m, time::sec(5))!! == ReasonCode.SUCCESS);
	// its PUBACK was written while we waited, before the application looked at the message
	assert(wrote(&s, "40 02 00 0A"));
	Event ev;
	assert(c.next(&ev, time::sec(1))!!);
	assert(ev.kind == EventKind.MESSAGE && ev.message.packet_id == 10 && ev.message.payload == testutil::hex("68 69"));
	c.close();
}

fn void client_subscribe_closed() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	s.on_write(0x82, "", true);                              // the link ends after the SUBSCRIBE
	SubEntry[1] entries = { { .filter = "a" } };
	char[2] codes;
	assert(@catch(c.subscribe(entries[..], codes[..], time::sec(5))) == mqtt::CLOSED);
	assert(s.closed && c.core.state == State.DISCONNECTED);
	// the application can still see how it ended
	Event ev;
	assert(c.next(&ev, time::sec(1))!! && ev.kind == EventKind.CLOSED);
	assert(@catch(c.next(&ev, time::sec(1))) == mqtt::NOT_CONNECTED);
	c.close();
}

fn void client_keepalive_ping() @test
{
	Script s;
	Client c;
	Config cf = cfg(1);                                       // keep alive of one second: PINGREQ after 750 ms
	start(&c, &s, &cf);
	usz before = s.out_len;
	Event ev;
	assert(!c.next(&ev, time::ms(1500))!!);
	assert(s.out_len == before + 2 && wrote(&s, "C0 00"), "the PINGREQ was written without the caller doing anything");
	// the reply keeps the connection; without one it ends after another second
	s.add("D0 00");
	assert(c.next(&ev, time::ms(100))!! && ev.kind == EventKind.PONG);
	c.close();
}

fn void client_keepalive_timeout_ends_the_link() @test
{
	Script s;
	Client c;
	Config cf = cfg(1);
	start(&c, &s, &cf);
	Event ev;
	// no PINGRESP: the link is declared dead at 750 ms + 1 s
	bool got_closed;
	for (int i = 0; i < 4 && !got_closed; i++)
	{
		bool? r = c.next(&ev, time::sec(1));
		if (try ok = r)
		{
			if (ok && ev.kind == EventKind.CLOSED)
			{
				assert(ev.closed.cause == mqtt::KEEPALIVE_TIMEOUT);
				got_closed = true;
			}
		}
	}
	assert(got_closed && s.closed);
	c.close();
}

fn void client_open_timeout() @test
{
	Script s;                                                  // no CONNACK ever
	Client c;
	Config cf = cfg();
	c.use_clock(&script_clock, &s);
	assert(@catch(c.open(mem, (Transport)&s, &cf, time::ms(500))) == mqtt::TIMEOUT);
	assert(s.closed, "the attempt is over, the link is released");
	c.close();
}

fn void client_open_refused() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	s.on_write(0x10, "20 02 00 05");                            // not authorized
	c.use_clock(&script_clock, &s);
	assert(@catch(c.open(mem, (Transport)&s, &cf, time::sec(5))) == mqtt::CONNECTION_REFUSED);
	Event ev;
	assert(c.next(&ev, time::ms(10))!! && ev.kind == EventKind.CLOSED && ev.closed.reason == ReasonCode.NOT_AUTHORIZED);
	c.close();
}

fn void client_write_stall_timeout() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	s.stall_writes = true;                                     // the peer takes no byte
	OutMessage m = { .topic = "a", .payload = testutil::hex("01") };
	assert(@catch(c.publish(&m, time::ms(200))) == mqtt::TIMEOUT);
	assert(s.closed && c.core.state == State.DISCONNECTED, "half a packet may be on the wire: the link is finished");
	c.close();
}

fn void client_disconnect() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	c.disconnect(ReasonCode.NORMAL_DISCONNECTION, time::sec(1))!!;
	assert(wrote(&s, "E0 00") && s.closed);
	c.close();
}

// ---- real sockets (single thread: the kernel queues the connection and the bytes) ----

fn void client_over_tcp_loopback() @test
{
	TcpServerSocket server = std::net::tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)server.close();
	ushort port = server.local_port()!!;
	TcpTransport t = mqtt::tcp::connect("127.0.0.1", port, time::ms(2000))!!;
	defer (void)t.close();
	TcpSocket peer = std::net::tcp::accept(&server)!!;
	defer (void)peer.close();
	// the CONNACK is waiting in the socket before the client sends its CONNECT
	char[4] connack = { 0x20, 0x02, 0x00, 0x00 };
	assert(peer.write(connack[..])!! == 4);
	Client c;
	Config cf = cfg();
	c.open(mem, (Transport)&t, &cf, time::sec(5))!!;
	char[32] buf;
	sz n = peer.read(buf[..])!!;
	assert(buf[:n] == testutil::hex("10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61"), "the server got the CONNECT");
	OutMessage m = { .topic = "a/b", .payload = testutil::hex("68 69") };
	c.publish(&m, time::sec(2))!!;
	sz k = peer.read(buf[..])!!;
	assert(buf[:k] == testutil::hex("30 07 00 03 61 2F 62 68 69"));
	c.close();
}

// ---- timeouts ----

fn void client_huge_timeout_does_not_wrap() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	s.now = time::sec(100);                                   // the clock is well above zero
	start(&c, &s, &cf);
	Duration forever = (Duration)long::max;
	s.add("30 07 00 03 61 2F 62 68 69");
	Event ev;
	assert(c.next(&ev, forever)!!, "a readable message is returned, not a wrapped deadline");
	assert(ev.kind == EventKind.MESSAGE);
	s.on_write(0x32, "40 02 00 01");
	OutMessage m = { .topic = "a/b", .payload = testutil::hex("68 69"), .qos = QoS.AT_LEAST_ONCE };
	assert(c.publish_wait(&m, forever)!! == ReasonCode.SUCCESS);
	// a negative timeout means "now": one poll, no wait
	assert(!c.next(&ev, (Duration)-5)!!);
	c.close();
}

// ---- memory and reconnecting ----

fn void client_open_again_and_close_leave_nothing_allocated() @test
{
	TrackingAllocator t;
	t.init(mem);
	Script s;
	Client c;
	Config cf = cfg();
	s.on_write(0x10, "20 02 00 00");
	c.use_clock(&script_clock, &s);
	c.open(&t, (Transport)&s, &cf, time::sec(5))!!;
	// a second open starts a new session: the first core is released, not leaked
	Script s2;
	s2.on_write(0x10, "20 02 00 00");
	c.use_clock(&script_clock, &s2);
	c.open(&t, (Transport)&s2, &cf, time::sec(5))!!;
	c.close();
	assert(t.allocation_count() == 0, "nothing left after open twice and close");
	// a failed attempt (no CONNACK) and a configuration the core refuses
	Script s3;
	Client d;
	d.use_clock(&script_clock, &s3);
	assert(@catch(d.open(&t, (Transport)&s3, &cf, time::ms(100))) == mqtt::TIMEOUT);
	d.close();
	Config bad = core::default_config(Version.V311, "");
	bad.clean_start = false;                                  // an empty id needs a clean session
	Client e;
	assert(@catch(e.open(&t, (Transport)&s3, &bad, time::ms(100))) == mqtt::INVALID_ARGUMENT);
	e.close();
	assert(t.allocation_count() == 0, "nothing left after the failed attempts");
	t.free();
}

fn void client_reconnect_keeps_the_session() @test
{
	TrackingAllocator t;
	t.init(mem);
	Script s;
	Client c;
	Config cf = cfg();
	cf.clean_start = false;
	s.on_write(0x10, "20 02 00 00");
	c.use_clock(&script_clock, &s);
	c.open(&t, (Transport)&s, &cf, time::sec(5))!!;
	// a QoS 1 message that is never acknowledged, then the link breaks
	OutMessage m = { .topic = "a/b", .payload = testutil::hex("68 69"), .qos = QoS.AT_LEAST_ONCE };
	assert(c.publish(&m, time::sec(1))!! == 1);
	s.eof = true;
	Event ev;
	assert(c.next(&ev, time::sec(1))!! && ev.kind == EventKind.CLOSED);
	assert(c.core.inflight_count() == 1, "the message is still held");
	// the same Client, a new link: session present, the message goes out again with DUP set
	Script s2;
	s2.on_write(0x10, "20 02 01 00");
	c.use_clock(&script_clock, &s2);
	c.reconnect((Transport)&s2, time::sec(5))!!;
	assert(wrote(&s2, "3A 09 00 03 61 2F 62 00 01 68 69"), "resent in the original form, DUP set");
	s2.add("40 02 00 01");
	assert(c.next(&ev, time::sec(1))!!);
	assert(ev.kind == EventKind.PUBLISH_DONE && ev.done.packet_id == 1);
	c.close();
	assert(t.allocation_count() == 0);
	t.free();
}

// ---- polling and the end of the link inside next ----

fn void client_next_zero_polls_once() @test
{
	Script s;
	Client c;
	Config cf = cfg(1);
	start(&c, &s, &cf);
	s.add("30 07 00 03 61 2F 62 68 69");
	Event ev;
	assert(c.next(&ev, time::DURATION_ZERO)!!, "a readable message with a zero timeout");
	assert(ev.kind == EventKind.MESSAGE);
	// nothing readable and no timer due: false, and the connection is untouched
	assert(!c.next(&ev, time::DURATION_ZERO)!!);
	assert(c.core.state == State.CONNECTED);
	// a due timer runs on a poll as well: the keep-alive PINGREQ goes out
	s.now = s.now + time::ms(800);
	usz before = s.out_len;
	assert(!c.next(&ev, time::DURATION_ZERO)!!);
	assert(s.out_len == before + 2 && wrote(&s, "C0 00"));
	c.close();
}

fn void client_next_reports_a_write_timeout_as_the_end_of_the_link() @test
{
	Script s;
	Client c;
	Config cf = cfg(1);
	start(&c, &s, &cf);
	s.stall_writes = true;                                    // the PINGREQ cannot be written
	Event ev;
	bool closed;
	for (int i = 0; i < 3 && !closed; i++)
	{
		if (c.next(&ev, time::ms(1500))!! && ev.kind == EventKind.CLOSED) closed = true;
	}
	assert(closed && s.closed && c.core.state == State.DISCONNECTED, "not reported as 'nothing came'");
	c.close();
}

// ---- a publish that times out while it waits for the window ----

fn void client_publish_timeout_while_queued_does_not_send_later() @test
{
	Script s;
	Client c;
	Config cf = core::default_config(Version.V5, "a");
	s.on_write(0x10, "20 06 00 00 03 21 00 01");            // Receive Maximum 1
	c.use_clock(&script_clock, &s);
	c.open(mem, (Transport)&s, &cf, time::sec(5))!!;
	OutMessage a = { .topic = "a", .payload = testutil::hex("01"), .qos = QoS.AT_LEAST_ONCE };
	assert(c.publish(&a, time::sec(1))!! == 1);
	OutMessage b = { .topic = "b", .payload = testutil::hex("02"), .qos = QoS.AT_LEAST_ONCE };
	assert(@catch(c.publish(&b, time::ms(200))) == mqtt::TIMEOUT);
	assert(c.core.queued_count() == 0, "a message the caller was told about is not kept for later");
	// the PUBACK of the first one arrives: nothing is sent for the second
	usz before = s.out_len;
	s.add("40 02 00 01");
	Event ev;
	assert(c.next(&ev, time::ms(100))!! && ev.kind == EventKind.PUBLISH_DONE);
	assert(s.out_len == before, "the timed out message was not sent");
	c.close();
}

// the window-full path of publish: it runs the connection until the message went out and returns its id
fn void client_publish_waits_for_the_window() @test
{
	Script s;
	Client c;
	Config cf = core::default_config(Version.V5, "a");
	s.on_write(0x10, "20 06 00 00 03 21 00 01");
	c.use_clock(&script_clock, &s);
	c.open(mem, (Transport)&s, &cf, time::sec(5))!!;
	OutMessage a = { .topic = "a", .payload = testutil::hex("01"), .qos = QoS.AT_LEAST_ONCE };
	assert(c.publish(&a, time::sec(1))!! == 1);
	OutMessage b = { .topic = "b", .payload = testutil::hex("02"), .qos = QoS.AT_LEAST_ONCE };
	// the server acknowledges the first message: the second one is sent and gets the next id
	s.add("40 02 00 01");
	assert(c.publish(&b, time::sec(1))!! == 2);
	assert(wrote(&s, "32 07 00 01 62 00 02 00 02"));
	c.close();
}

// ---- what a held event survives ----

fn void client_held_event_survives_calls_that_only_write() @test
{
	Script s;
	Client c;
	Config cf = cfg();
	start(&c, &s, &cf);
	s.add("30 07 00 03 61 2F 62 68 69");
	Event ev;
	assert(c.next(&ev, time::sec(1))!!);
	OutMessage m = { .topic = "x", .payload = testutil::hex("01") };
	c.publish(&m, time::sec(1))!!;                                         // QoS 0: only writes
	OutMessage q1 = { .topic = "x", .payload = testutil::hex("01"), .qos = QoS.AT_LEAST_ONCE };
	c.publish(&q1, time::sec(1))!!;                                        // QoS 1 with room in the window: only writes
	assert(ev.message.topic == "a/b" && ev.message.payload == testutil::hex("68 69"), "the held event is intact");
	c.disconnect(ReasonCode.NORMAL_DISCONNECTION, time::sec(1))!!;
	assert(ev.message.topic == "a/b");
	c.close();
}
