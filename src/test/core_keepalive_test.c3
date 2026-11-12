module mqtt::core_keepalive_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::testutil, std::core::mem::allocators, std::time;

struct Rig
{
	TrackingAllocator mem_track;
	Core core;
	VirtualClock clock;
}

fn void Rig.start(&self, Config* c, String connack_hex)
{
	self.mem_track.init(mem);
	self.core.init(&self.mem_track, c)!!;
	self.core.connect(self.clock.now)!!;
	self.core.output_done(self.core.pending_output().len);
	harness::feed(&self.core, &self.clock, connack_hex);
	EventKind[] kinds = harness::drain(&self.core);
	assert(kinds.len == 1 && kinds[0] == EventKind.CONNECTED);
}

fn void Rig.finish(&self)
{
	self.core.free();
	assert(self.mem_track.allocation_count() == 0);
	self.mem_track.free();
}

// the virtual time is set to ms milliseconds since the start (never backwards)
fn void Rig.at(&self, long ms)
{
	assert(time::ms(ms) >= self.clock.now);
	self.clock.now = time::ms(ms);
}

fn Duration Rig.deadline(&self)
{
	Duration d;
	assert(self.core.next_deadline(&d), "a timer is armed");
	return d;
}

fn Config cfg(Version v, ushort keep_alive)
{
	Config c = core::default_config(v, "a");
	c.keep_alive = keep_alive;
	return c;
}

fn void seq_9_1() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	r.mem_track.init(mem);
	r.core.init(&r.mem_track, &c)!!;
	r.core.connect(r.clock.now)!!;
	harness::expect_out(&r.core, "10 0D 00 04 4D 51 54 54 04 02 00 0A 00 01 61");
	r.at(10);
	harness::feed(&r.core, &r.clock, "20 02 00 00");
	EventKind[] kinds = harness::drain(&r.core);
	assert(kinds.len == 1 && kinds[0] == EventKind.CONNECTED);
	// the first PINGREQ is due 7.5 s after the CONNECT was queued
	assert(r.deadline() == time::ms(7500));
	r.at(7499);
	r.core.timeout(r.clock.now)!!;
	harness::expect_no_out(&r.core);
	r.at(7500);
	r.core.timeout(r.clock.now)!!;
	harness::expect_out(&r.core, "C0 00");
	r.at(7600);
	harness::feed(&r.core, &r.clock, "D0 00");
	kinds = harness::drain(&r.core);
	assert(kinds.len == 1 && kinds[0] == EventKind.PONG);
	assert(r.deadline() == time::ms(15_000), "the next one is 7.5 s after the last packet");
	r.at(15_000);
	r.core.timeout(r.clock.now)!!;
	harness::expect_out(&r.core, "C0 00");
	r.finish();
}

fn void seq_9_9() @test
{
	Rig r;
	Config c = cfg(Version.V5, 60);
	r.start(&c, "20 09 00 00 06 22 00 0A 13 00 1E");        // the server asks for a keep alive of 30 s
	assert(r.deadline() == time::ms(22_500), "75 % of 30 s");
	r.at(22_499);
	r.core.timeout(r.clock.now)!!;
	harness::expect_no_out(&r.core);
	r.at(22_500);
	r.core.timeout(r.clock.now)!!;
	harness::expect_out(&r.core, "C0 00");
	r.finish();
}

fn void keepalive_ping_at_75pct() @test
{
	Rig r;
	Config c = cfg(Version.V311, 60);
	r.start(&c, "20 02 00 00");
	assert(r.deadline() == time::ms(45_000));
	r.at(44_999);
	r.core.timeout(r.clock.now)!!;
	harness::expect_no_out(&r.core);
	r.at(45_000);
	r.core.timeout(r.clock.now)!!;
	harness::expect_out(&r.core, "C0 00");
	r.finish();
}

fn void keepalive_pong_timeout() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	r.start(&c, "20 02 00 00");
	r.at(7500);
	r.core.timeout(r.clock.now)!!;
	harness::expect_out(&r.core, "C0 00");
	assert(r.deadline() == time::ms(17_500), "the reply is due one keep alive after the PINGREQ");
	r.at(17_499);
	r.core.timeout(r.clock.now)!!;
	r.at(17_500);
	assert(@catch(r.core.timeout(r.clock.now)) == mqtt::KEEPALIVE_TIMEOUT);
	assert(r.core.state == State.DISCONNECTED);
	Event ev;
	assert(r.core.poll_event(&ev) && ev.kind == EventKind.CLOSED);
	assert(ev.closed.cause == mqtt::KEEPALIVE_TIMEOUT && ev.closed.reason == ReasonCode.KEEP_ALIVE_TIMEOUT && !ev.closed.by_server);
	assert(!r.core.poll_event(&ev));
	Duration none;
	assert(!r.core.next_deadline(&none), "no timer after the close");
	r.finish();
}

fn void keepalive_pong_reset_by_inbound_data() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	r.start(&c, "20 02 00 00");
	r.at(7500);
	r.core.timeout(r.clock.now)!!;
	harness::expect_out(&r.core, "C0 00");
	// a slow link: the first byte of some other packet arrives, the PINGRESP is still behind it
	r.at(15_000);
	harness::feed(&r.core, &r.clock, "30");
	assert(r.deadline() == time::ms(25_000), "any inbound data moves the deadline");
	r.at(24_999);
	r.core.timeout(r.clock.now)!!;
	r.at(25_000);
	assert(@catch(r.core.timeout(r.clock.now)) == mqtt::KEEPALIVE_TIMEOUT);
	r.finish();
}

fn void keepalive_zero() @test
{
	Rig r;
	Config c = cfg(Version.V311, 0);
	r.start(&c, "20 02 00 00");
	Duration d;
	assert(!r.core.next_deadline(&d));
	r.at(100 * 24 * 3600 * 1000);
	r.core.timeout(r.clock.now)!!;
	harness::expect_no_out(&r.core);
	r.finish();
}

fn void keepalive_server_may_switch_it_off() @test
{
	Rig r;
	Config c = cfg(Version.V5, 60);
	r.start(&c, "20 06 00 00 03 13 00 00");
	Duration d;
	assert(!r.core.next_deadline(&d), "a Server Keep Alive of 0 disables the timers");
	r.finish();
}

fn void keepalive_unsolicited_pingresp() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	r.start(&c, "20 02 00 00");
	harness::feed(&r.core, &r.clock, "D0 00");
	EventKind[] kinds = harness::drain(&r.core);
	assert(kinds.len == 0, "ignored without an event");
	assert(r.core.state == State.CONNECTED);
	assert(r.deadline() == time::ms(7500), "the timers did not change");
	r.finish();
}

fn void keepalive_percentages_come_from_the_config() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	c.ping_after_pct = 50;
	c.pong_timeout_pct = 200;
	r.start(&c, "20 02 00 00");
	assert(r.deadline() == time::ms(5000));
	r.at(5000);
	r.core.timeout(r.clock.now)!!;
	harness::expect_out(&r.core, "C0 00");
	assert(r.deadline() == time::ms(25_000), "200 % of 10 s after the PINGREQ");
	r.finish();
}

fn void keepalive_largest_value_does_not_overflow() @test
{
	Rig r;
	Config c = cfg(Version.V311, 65_535);
	r.start(&c, "20 02 00 00");
	assert(r.deadline() == time::ms(49_151_250), "65535 s * 75 %");
	r.finish();
}

fn void clock_backwards() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	r.start(&c, "20 02 00 00");
	// the core has seen t = 10 s; a later call with an earlier value counts as 10 s, so the ping is due
	r.at(10_000);
	char[] none;
	r.core.input(r.clock.now, none)!!;
	r.core.timeout(time::ms(5000))!!;
	harness::expect_out(&r.core, "C0 00");
	assert(r.deadline() == time::ms(20_000));
	r.finish();
}

fn void clock_jump() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	r.start(&c, "20 02 00 00");
	Duration ten_days = time::ms(10 * 24 * 3600 * 1000L);
	r.core.timeout(ten_days)!!;
	harness::expect_out(&r.core, "C0 00");
	r.core.timeout(ten_days)!!;
	harness::expect_no_out(&r.core);                // each due timer fires once
	assert(@catch(r.core.timeout(ten_days + time::sec(10))) == mqtt::KEEPALIVE_TIMEOUT);
	r.finish();
}

fn void keepalive_does_not_run_before_connected() @test
{
	Rig r;
	Config c = cfg(Version.V311, 10);
	r.mem_track.init(mem);
	r.core.init(&r.mem_track, &c)!!;
	Duration d;
	assert(!r.core.next_deadline(&d), "not connected");
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	assert(!r.core.next_deadline(&d), "waiting for CONNACK: the adapter's connect timeout applies, not the keep alive");
	r.core.timeout(time::ms(3_600_000))!!;
	harness::expect_no_out(&r.core);
	r.finish();
}
