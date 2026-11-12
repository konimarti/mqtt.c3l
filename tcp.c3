module mqtt::tcp;
import mqtt, mqtt::transport;
import std::io, std::net, std::net::tcp, std::net::os, std::time, std::time::clock, std::core::env, libc;

// Plain TCP over std::net::tcp with a poll (POSIX) / WSAPoll (Windows) based timeout, isolated in
// this one file. Not thread safe.
//
// The socket is switched to non-blocking mode, so a send or receive never waits beyond the
// deadline given to read or write.
//
// SIGPIPE: std::net sends with flags 0, so writing to a peer that has closed would raise SIGPIPE
// and kill the process. Linux: this file sends with MSG_NOSIGNAL. macOS: SO_NOSIGPIPE is set on
// the socket when it is created or adopted. Windows has no SIGPIPE. A write to a closed peer
// returns CLOSED.
//
// TCP_NODELAY is set best effort (a failure is ignored): std::net::SocketOption has no such option,
// so the level and option number are passed to setsockopt directly (6 and 1 on all three OSes).

const CInt IPPROTO_TCP = 6;
const CInt TCP_NODELAY = 1;
const CInt SEND_CHUNK = 65536;

struct TcpTransport (Transport)
{
	TcpSocket sock;
	bool open;
}

// Resolves and connects (connect timeout zero = OS default).
fn TcpTransport? connect(String host, int port, Duration timeout)
{
	TcpSocket s = std::net::tcp::connect(host, port, timeout)!;
	TcpTransport t = from_socket(s);
	if (catch err = prepare(&t))
	{
		(void)s.close();
		return err~;
	}
	return t;
}

// Adopts a connected socket (for example one returned by tcp::accept).
fn TcpTransport from_socket(TcpSocket s)
{
	TcpTransport t = { .sock = s, .open = true };
	if (catch prepare(&t))
	{
		t.open = false;
	}
	return t;
}

fn void? prepare(TcpTransport* t) @private
{
	t.sock.sock.set_non_blocking(true)!;
	$if env::DARWIN:
		CInt on = 1;
		os::setsockopt(t.sock.sock, os::SOL_SOCKET, os::SO_NOSIGPIPE, &on, CInt::size);
	$endif
	CInt flag = 1;
	(void)os::setsockopt(t.sock.sock, IPPROTO_TCP, TCP_NODELAY, &flag, CInt::size);
}

// Milliseconds left until deadline, at least 0.
fn long remaining_ms(Clock deadline) @private
{
	long left = (long)deadline.nano_diff(clock::now());
	if (left <= 0) return 0;
	return left / 1_000_000 + (left % 1_000_000 != 0 ? 1 : 0);
}

fn sz? raw_send(TcpTransport* self, char[] data) @private
{
	$if env::LINUX:
		sz n = libc::send(self.sock.sock, data.ptr, (usz)data.len, os::MSG_NOSIGNAL);
		if (n < 0) return os::socket_error()~;
		return n;
	$else
		return self.sock.write(data);
	$endif
}

fn usz? TcpTransport.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (!self.open) return mqtt::CLOSED~;
	if (buf.len == 0) return mqtt::INVALID_ARGUMENT~;
	Clock deadline = clock::now() + (timeout > (Duration)0 ? timeout : (Duration)0);
	while (true)
	{
		Poll[1] p = { { .socket = self.sock.sock, .events = PollSubscribe.ANY_READ } };
		ulong? ready = net::poll_ms(&p, remaining_ms(deadline));
		if (catch err = ready)
		{
			if (err == io::INTERRUPTED) continue;
			return mqtt::CLOSED~;
		}
		if (ready == 0) return mqtt::TIMEOUT~;
		sz? n = self.sock.read(buf);
		if (catch err = n)
		{
			if (err == io::INTERRUPTED) continue;
			if (err == io::WOULD_BLOCK)
			{
				if (remaining_ms(deadline) == 0) return mqtt::TIMEOUT~;
				continue;
			}
			return mqtt::CLOSED~;
		}
		if (n == 0) return mqtt::CLOSED~;
		return (usz)n;
	}
}

// A write that ran out of time after some of the bytes went out has left part of a packet on the wire: sending the
// whole of it again would put duplicate bytes in the stream and the rest alone cannot be told apart by the caller. The
// link is closed, so that a retry fails with CLOSED instead. A timeout before the first byte left changes nothing and
// can be retried.
fn fault broken_after_partial(TcpTransport* self, usz written, fault cause) @private
{
	if (written == 0) return cause;
	self.open = false;
	(void)self.sock.close();
	return cause;
}

fn void? TcpTransport.write(&self, char[] data, Duration timeout) @dynamic
{
	if (!self.open) return mqtt::CLOSED~;
	Clock deadline = clock::now() + (timeout > (Duration)0 ? timeout : (Duration)0);
	usz off;
	while (off < data.len)
	{
		Poll[1] p = { { .socket = self.sock.sock, .events = PollSubscribe.ANY_WRITE } };
		ulong? ready = net::poll_ms(&p, remaining_ms(deadline));
		if (catch err = ready)
		{
			if (err == io::INTERRUPTED) continue;
			return mqtt::CLOSED~;
		}
		if (ready == 0) return broken_after_partial(self, off, mqtt::TIMEOUT)~;
		usz chunk = data.len - off;
		if (chunk > SEND_CHUNK) chunk = SEND_CHUNK;
		sz? n = raw_send(self, data[off:chunk]);
		if (catch err = n)
		{
			if (err == io::INTERRUPTED) continue;
			if (err == io::WOULD_BLOCK)
			{
				if (remaining_ms(deadline) == 0) return broken_after_partial(self, off, mqtt::TIMEOUT)~;
				continue;
			}
			return mqtt::CLOSED~;
		}
		off += (usz)n;
	}
}

fn void? TcpTransport.close(&self) @dynamic
{
	if (!self.open) return;
	self.open = false;
	(void)self.sock.close();
}
