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
