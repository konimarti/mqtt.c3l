module mqtt::client;
import mqtt, mqtt::core, mqtt::transport, mqtt::packet, mqtt::props;
import std::time, std::time::clock;

// The time the core works with, and where it comes from. The default reads the monotonic clock (never
// wall time) and counts from the moment the client was opened; a test can put its own source in with
// use_clock.
alias ClockFn = fn Duration(void* context);

// Blocking adapter: drives a Core over a Transport. This is the only place of the library that looks at the
// time. Every blocking call takes a timeout (a Duration); the reads and writes it does are bounded by what is
// left of it. Not thread safe.
//
// Events: `next` hands out the next event. Data in an Event is borrowed from the core's input buffer and stays
// valid until the next call that reads from the transport; `publish` and the other commands never touch that
// buffer, so they may be called while an Event is in hand. The waiting calls (publish_wait, wait_done,
// subscribe, unsubscribe) take only the answer they wait for; every other event stays queued for `next`.
// While they wait the input buffer keeps filling with what the server sends meanwhile; when it is full they
// return QUEUE_FULL and the application has to call `next` to take the events.
struct Client
{
	Core core;
	Transport transport;
	Allocator allocator;
	char[] rbuf;                    // read scratch, owned
	bool opened;                    // the core is initialised
	Clock origin;
	ClockFn clock_fn;               // null = the monotonic clock
	void* clock_context;
}

const usz READ_BUFFER_SIZE = 4096;

// Replaces the time source (before open). For tests that have to be deterministic.
fn void Client.use_clock(&self, ClockFn fn_, void* context)
{
	self.clock_fn = fn_;
	self.clock_context = context;
}

// The moment `timeout` from now, without wrapping around: a huge Duration (there is no "forever" constant, pass a
// very large one) means a deadline far away, and a negative one means "now".
fn Duration Client.deadline_after(&self, Duration timeout)
{
	Duration now = self.now();
	if (timeout <= time::DURATION_ZERO) return now;
	Duration room = (Duration)long::max - now;
	return timeout >= room ? (Duration)long::max : now + timeout;
}

// The time handed to the core.
fn Duration Client.now(&self)
{
	if (self.clock_fn != null) return self.clock_fn(self.clock_context);
	return time::ms(self.origin.to_now().to_ms());
}

// Connects the session: sends CONNECT and blocks until the CONNACK has been accepted, at most `timeout`.
// Faults: CONNECTION_REFUSED (the reason is in the CLOSED event: read it with next), TIMEOUT, CLOSED, AUTH_FAILED,
// any fault of the core for a bad answer. After a fault the transport is closed and the client is not
// connected, but the core stays until close() so that the CLOSED event can still be read.
// The Client does not own `transport` (the caller releases it); it does own `core`.
fn void? Client.open(&self, Allocator allocator, Transport transport, Config* config, Duration timeout)
{
	self.allocator = allocator;
	self.transport = transport;
	self.origin = clock::now();
	if (self.rbuf.len == 0) self.rbuf = alloc::alloc_array(allocator, char, (sz)READ_BUFFER_SIZE);
	self.core.init(allocator, config)!;
	self.opened = true;
	Duration deadline = self.deadline_after(timeout);
	self.core.connect(self.now())!;
	Event ev;
	while (true)
	{
		if (self.core.poll_matching(EventKind.CONNECTED, 0, &ev)) return;
		if (catch err = self.pump(deadline))
		{
			// no CONNACK in time: the attempt is over, the link is not kept
			if (err == mqtt::TIMEOUT && self.core.state != State.DISCONNECTED) self.link_dead();
			return err~;
		}
	}
}

// Releases the core and the read buffer. Does not touch the transport.
fn void Client.close(&self)
{
	if (self.opened) self.core.free();
	self.opened = false;
	if (self.rbuf.len > 0) alloc::free(self.allocator, self.rbuf.ptr);
	self.rbuf = {};
}

// Sends a message. QoS 0 returns 0 once the bytes were written; QoS 1 and 2 return the packet id (the message is
// written; completion comes with PUBLISH_DONE, see wait_done). When the server's window was full the message
// waited in the core's queue: the call then runs the connection until it was sent, and returns the id it got.
fn ushort? Client.publish(&self, OutMessage* msg, Duration timeout)
{
	Duration deadline = self.deadline_after(timeout);
	ushort id = self.core.publish(self.now(), msg)!;
	if (msg.qos != QoS.AT_MOST_ONCE && id == 0)
	{
		while (self.core.queued_count() > 0) self.pump(deadline)!;
		id = self.core.last_inflight_id();
	}
	self.flush(deadline)!;
	return id;
}

// Blocks until the message `id` is done (PUBACK or PUBCOMP, or a refusal: the reason code says which); other
// events stay queued.
fn ReasonCode? Client.wait_done(&self, ushort id, Duration timeout)
{
	Duration deadline = self.deadline_after(timeout);
	Event ev;
	while (true)
	{
		if (self.core.poll_matching(EventKind.PUBLISH_DONE, id, &ev)) return ev.done.reason;
		self.pump(deadline)!;
	}
}

// publish and wait_done in one. QoS 0 has nothing to wait for: SUCCESS once it was written.
fn ReasonCode? Client.publish_wait(&self, OutMessage* msg, Duration timeout)
{
	Duration deadline = self.deadline_after(timeout);
	ushort id = self.publish(msg, timeout)!;
	if (msg.qos == QoS.AT_MOST_ONCE) return ReasonCode.SUCCESS;
	return self.wait_done(id, deadline - self.now());
}

// Subscribes and blocks for the SUBACK; copies the reply codes into codes_out (as many as fit) and returns how
// many filters were answered.
fn usz? Client.subscribe(&self, SubEntry[] entries, char[] codes_out, Duration timeout)
{
	Duration deadline = self.deadline_after(timeout);
	ushort id = self.core.subscribe(self.now(), entries, null)!;
	return self.wait_answer(EventKind.SUBSCRIBED, id, codes_out, deadline);
}

fn usz? Client.unsubscribe(&self, String[] filters, char[] codes_out, Duration timeout)
{
	Duration deadline = self.deadline_after(timeout);
	ushort id = self.core.unsubscribe(self.now(), filters, null)!;
	return self.wait_answer(EventKind.UNSUBSCRIBED, id, codes_out, deadline);
}

fn usz? Client.wait_answer(&self, EventKind kind, ushort id, char[] codes_out, Duration deadline)
{
	Event ev;
	while (true)
	{
		if (self.core.poll_matching(kind, id, &ev))
		{
			usz n = ev.suback.codes.len < codes_out.len ? ev.suback.codes.len : codes_out.len;
			codes_out[:n] = ev.suback.codes[:n];
			return ev.suback.codes.len;
		}
		self.pump(deadline)!;
	}
}

// The next event, waiting at most `timeout` (false: nothing came). Runs the connection meanwhile: the
// keep-alive PINGREQ is written without the caller doing anything. The event data is valid until the next
// call that reads from the transport. When the connection ended the CLOSED event is returned first, and the
// call after it faults with NOT_CONNECTED.
fn bool? Client.next(&self, Event* ev, Duration timeout)
{
	Duration deadline = self.deadline_after(timeout);
	while (true)
	{
		if (self.core.poll_event(ev)) return true;
		if (self.core.state == State.DISCONNECTED) return mqtt::NOT_CONNECTED~;
		if (self.now() >= deadline) return false;
		if (catch err = self.pump(deadline))
		{
			if (err == mqtt::TIMEOUT) return false;
			// the connection ended: the CLOSED event tells how
			if (self.core.poll_event(ev)) return true;
			return err~;
		}
	}
}

// Sends DISCONNECT, writes it, closes the transport and tells the core. The CLOSED event can be read with next.
fn void? Client.disconnect(&self, ReasonCode reason, Duration timeout)
{
	Duration deadline = self.deadline_after(timeout);
	self.core.disconnect(self.now(), reason, null)!;
	fault failed;
	if (catch err = self.flush(deadline)) failed = err;
	(void)self.transport.close();
	self.core.transport_closed(self.now());
	if (failed) return failed~;
}

// ---- the connection loop ----

// Writes what the core wants written. A write that fails may have left half a packet on the wire, so the link is
// finished: the transport is closed and the core told.
fn void? Client.flush(&self, Duration deadline)
{
	char[] out = self.core.pending_output();
	if (out.len == 0) return;
	Duration left = deadline - self.now();
	if (left < time::DURATION_ZERO) left = time::DURATION_ZERO;
	if (catch err = self.transport.write(out, left))
	{
		self.link_dead();
		return err == mqtt::TIMEOUT ? mqtt::TIMEOUT~ : mqtt::CLOSED~;
	}
	self.core.output_done(out.len);
}

fn void Client.link_dead(&self)
{
	(void)self.transport.close();
	self.core.transport_closed(self.now());
}

// One round: write, wait for bytes until the next timer or the deadline (whichever is first), hand them to the
// core, run the timers, write again. TIMEOUT when the deadline has passed.
fn void? Client.pump(&self, Duration deadline)
{
	self.flush(deadline)!;
	Duration now = self.now();
	if (now >= deadline) return mqtt::TIMEOUT~;
	Duration wait = deadline - now;
	Duration timer;
	if (self.core.next_deadline(&timer))
	{
		Duration to_timer = timer > now ? timer - now : time::DURATION_ZERO;
		if (to_timer < wait) wait = to_timer;
	}
	usz room = self.core.input_room();
	if (room == 0) return mqtt::QUEUE_FULL~;                // the application has to take its events
	if (room > self.rbuf.len) room = self.rbuf.len;
	usz? got = self.transport.read(self.rbuf[:room], wait);
	if (catch err = got)
	{
		if (err != mqtt::TIMEOUT)
		{
			self.link_dead();
			return mqtt::CLOSED~;
		}
	}
	else
	{
		if (catch ierr = self.core.input(self.now(), self.rbuf[:got]))
		{
			// the core ended the connection (a DISCONNECT may be waiting): say goodbye if the link takes it, then close
			(void)self.flush(self.now() + time::ms(100));
			self.link_dead();
			return ierr~;
		}
	}
	if (catch err = self.core.timeout(self.now()))
	{
		self.link_dead();
		return err~;
	}
	self.flush(deadline)!;
}
