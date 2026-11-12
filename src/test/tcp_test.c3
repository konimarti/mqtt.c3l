module mqtt::tcp_test;
import mqtt, mqtt::tcp, std::net, std::net::tcp, std::time, std::time::clock, std::thread;

struct Pair
{
	TcpServerSocket server;
	TcpTransport client;
	TcpSocket peer;
}

// Listens on an ephemeral loopback port, connects a TcpTransport and accepts the peer side.
fn Pair open_pair()
{
	TcpServerSocket server = std::net::tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	ushort port = server.local_port()!!;
	TcpTransport c = mqtt::tcp::connect("127.0.0.1", port, time::ms(2000))!!;
	TcpSocket peer = std::net::tcp::accept(&server)!!;
	return { server, c, peer };
}

fn void close_pair(Pair* p)
{
	(void)p.client.close();
	(void)p.peer.close();
	(void)p.server.close();
}

fn void tcp_roundtrip() @test
{
	Pair p = open_pair();
	defer close_pair(&p);
	char[5] out = { 'h', 'e', 'l', 'l', 'o' };
	p.client.write(out[..], time::ms(1000))!!;
	char[16] buf;
	sz n = p.peer.read(buf[..])!!;
	assert(n == 5 && buf[:5] == out[..], "peer got the bytes");
	char[3] back = { 'a', 'b', 'c' };
	assert(p.peer.write(back[..])!! == 3);
	char[16] rb;
	usz m = p.client.read(rb[..], time::ms(1000))!!;
	assert(m == 3 && rb[:3] == back[..], "client got the bytes");
}

fn void tcp_read_timeout_zero() @test
{
	Pair p = open_pair();
	defer close_pair(&p);
	char[8] buf;
	// zero timeout polls once
	assert(@catch(p.client.read(buf[..], time::DURATION_ZERO)) == mqtt::TIMEOUT, "zero timeout");
	// a 20 ms timeout, and the link is still usable afterwards
	Clock t = clock::now();
	assert(@catch(p.client.read(buf[..], time::ms(20))) == mqtt::TIMEOUT, "20 ms timeout");
	assert(t.to_now().to_ms() < 1000, "returned in time");
	char[1] one = { 'x' };
	assert(p.peer.write(one[..])!! == 1);
	assert(p.client.read(buf[..], time::ms(1000))!! == 1 && buf[0] == 'x', "usable after timeout");
}

fn void tcp_eof_closed() @test
{
	Pair p = open_pair();
	defer close_pair(&p);
	p.peer.close()!!;
	char[8] buf;
	assert(@catch(p.client.read(buf[..], time::ms(1000))) == mqtt::CLOSED, "eof");
}

fn void tcp_close_idempotent() @test
{
	Pair p = open_pair();
	defer close_pair(&p);
	p.client.close()!!;
	p.client.close()!!;
	char[8] buf;
	assert(@catch(p.client.read(buf[..], time::ms(10))) == mqtt::CLOSED, "read after close");
	char[1] one = { 'x' };
	assert(@catch(p.client.write(one[..], time::ms(10))) == mqtt::CLOSED, "write after close");
}

fn void tcp_write_deadline() @test
{
	Pair p = open_pair();
	defer close_pair(&p);
	// far more than the socket buffers hold; the peer never reads
	usz size = 64 * 1024 * 1024;
	char[] big = mem::new_array(char, (sz)size);
	defer free(big);
	big[..] = 'z';
	Clock t = clock::now();
	assert(@catch(p.client.write(big, time::ms(200))) == mqtt::TIMEOUT, "write deadline");
	assert(t.to_now().to_ms() < 2000, "returned near the deadline");
}

fn void tcp_write_to_closed_peer() @test
{
	Pair p = open_pair();
	defer close_pair(&p);
	p.peer.close()!!;
	// the first writes may be accepted by the kernel; the reset follows. An unprotected process
	// would be killed by SIGPIPE here.
	char[1024] data;
	data[..] = 'q';
	fault f;
	for (usz i = 0; i < 200; i++)
	{
		if (catch err = p.client.write(data[..], time::ms(200)))
		{
			f = err;
			break;
		}
		(void)thread::sleep_ms(1);
	}
	assert(f == mqtt::CLOSED, "fault, not a signal");
}

// After a write that went out only in part and then timed out the link is finished: the whole packet must not be sent
// again behind its first part.
fn void tcp_partial_write_timeout_ends_the_link() @test
{
	Pair p = open_pair();
	defer close_pair(&p);
	usz size = 64 * 1024 * 1024;
	char[] big = mem::new_array(char, (sz)size);
	defer free(big);
	big[..] = 'z';
	assert(@catch(p.client.write(big, time::ms(200))) == mqtt::TIMEOUT);
	char[4] more = { 1, 2, 3, 4 };
	assert(@catch(p.client.write(more[..], time::ms(100))) == mqtt::CLOSED, "a retry must fail, not resend");
}
