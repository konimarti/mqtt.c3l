module mqtt::core_auth_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::packet, mqtt::props, mqtt::testutil, std::core::dstring, std::time;

const String CONNACK_5 = "20 03 00 00 00";

// An authentication method that answers every challenge with "r" and the round number.
struct FakeAuth (AuthHook)
{
	int round;
	int fail_round;                 // 0 = never
	int done_round;                 // 0 = never: answer nothing in this round
	bool initial_fails;
}

fn void? FakeAuth.initial(&self, DString* out) @dynamic
{
	if (self.initial_fails) return mqtt::AUTH_FAILED~;
	out.append("init");
}

fn AuthAction? FakeAuth.step(&self, char[] server_data, DString* out) @dynamic
{
	self.round++;
	if (self.round == self.fail_round) return AuthAction.FAIL;
	if (self.round == self.done_round) return AuthAction.DONE;
	out.append("r");
	out.append((char)('0' + self.round));
	return AuthAction.CONTINUE;
}

fn Config cfg()
{
	Config c = core::default_config(Version.V5, "a");
	c.auth_method = "m";
	return c;
}

// ---- redirect ----

fn void seq_9_11() @test
{
	Session s;
	Config c = core::default_config(Version.V5, "a");
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	char[] frame = testutil::hex("20 07 00 9C 04 1C 00 01 62");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::CONNECTION_REFUSED);
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.by_server);
	assert(ev.closed.reason == ReasonCode.USE_ANOTHER_SERVER && ev.closed.server_reference == "b");
	// the core does not connect by itself: that is the application's decision
	assert(s.core.state == State.DISCONNECTED && s.core.pending_output().len == 0);
	s.close();
}

fn void redirect_connack_9c() @test
{
	Session s;
	Config c = core::default_config(Version.V5, "a");
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	// the server sends the reference text of a list
	char[] frame = testutil::hex("20 0E 00 9C 0B 1C 00 08 68 6F 73 74 3A 31 20 78");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::CONNECTION_REFUSED);
	Event ev = s.take();
	assert(ev.closed.reason == ReasonCode.USE_ANOTHER_SERVER && ev.closed.server_reference == "host:1 x");
	s.close();
}

fn void redirect_disconnect_9d() @test
{
	Session s;
	Config c = core::default_config(Version.V5, "a");
	s.open(&c, CONNACK_5);
	char[] frame = testutil::hex("E0 0B 9D 09 1C 00 06 68 6F 73 74 3A 31");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::SERVER_DISCONNECTED);
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.by_server);
	assert(ev.closed.reason == ReasonCode.SERVER_MOVED && ev.closed.server_reference == "host:1");
	s.close();
}

// ---- enhanced authentication ----

fn void auth_two_round_hook() @test
{
	Session s;
	FakeAuth fake;
	Config c = cfg();
	c.auth_hook = &fake;
	c.has_auth_hook = true;
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	// the CONNECT carries the method and the first data from the hook
	Packet p = packet::decode(Version.V5, s.core.pending_output())!!;
	assert(p.connect.props.auth_method == "m" && p.connect.props.auth_data == (char[])"init");
	s.core.output_done(s.core.pending_output().len);
	// two challenges, two answers, then the CONNACK
	harness::feed(&s.core, &s.clock, "F0 0B 18 09 15 00 01 6D 16 00 02 63 31");
	harness::expect_out(&s.core, "F0 0B 18 09 15 00 01 6D 16 00 02 72 31");
	harness::feed(&s.core, &s.clock, "F0 0B 18 09 15 00 01 6D 16 00 02 63 32");
	harness::expect_out(&s.core, "F0 0B 18 09 15 00 01 6D 16 00 02 72 32");
	assert(harness::drain(&s.core).len == 0, "the hook handled the exchange without the application");
	assert(s.core.state == State.CONNECTING);
	harness::feed(&s.core, &s.clock, CONNACK_5);
	Event ev = s.take();
	assert(ev.kind == EventKind.CONNECTED);
	assert(fake.round == 2);
	s.close();
}

fn void auth_hook_done_sends_nothing() @test
{
	Session s;
	FakeAuth fake = { .done_round = 1 };
	Config c = cfg();
	c.auth_hook = &fake;
	c.has_auth_hook = true;
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "F0 0B 18 09 15 00 01 6D 16 00 02 63 31");
	harness::expect_no_out(&s.core);
	assert(s.core.state == State.CONNECTING);
	s.close();
}

fn void auth_event_without_hook() @test
{
	Session s;
	Config c = cfg();
	c.auth_data = testutil::hex("69");
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	Packet p = packet::decode(Version.V5, s.core.pending_output())!!;
	assert(p.connect.props.auth_method == "m" && p.connect.props.auth_data == testutil::hex("69"));
	s.core.output_done(s.core.pending_output().len);
	// only AUTH and DISCONNECT may be sent before the CONNACK
	OutMessage m = { .topic = "t" };
	assert(@catch(s.core.publish(s.clock.now, &m)) == mqtt::NOT_CONNECTED);
	// the challenge reaches the application, which answers
	harness::feed(&s.core, &s.clock, "F0 0B 18 09 15 00 01 6D 16 00 02 63 31");
	Event ev = s.take();
	assert(ev.kind == EventKind.AUTH && ev.auth.reason == ReasonCode.CONTINUE_AUTHENTICATION);
	assert(ev.auth.method == "m" && ev.auth.data == (char[])"c1");
	s.core.send_auth(s.clock.now, ReasonCode.CONTINUE_AUTHENTICATION, testutil::hex("72"))!!;
	harness::expect_out(&s.core, "F0 0A 18 08 15 00 01 6D 16 00 01 72");
	harness::feed(&s.core, &s.clock, CONNACK_5);
	assert(s.take().kind == EventKind.CONNECTED);
	s.close();
}

fn void auth_reauth_0x19() @test
{
	Session s;
	Config c = cfg();
	s.open(&c, CONNACK_5);
	s.core.send_auth(s.clock.now, ReasonCode.RE_AUTHENTICATE, testutil::hex("78"))!!;
	harness::expect_out(&s.core, "F0 0A 19 08 15 00 01 6D 16 00 01 78");
	harness::feed(&s.core, &s.clock, "F0 0B 18 09 15 00 01 6D 16 00 02 63 31");           // a challenge
	Event ev = s.take();
	assert(ev.kind == EventKind.AUTH && ev.auth.reason == ReasonCode.CONTINUE_AUTHENTICATION);
	s.core.send_auth(s.clock.now, ReasonCode.CONTINUE_AUTHENTICATION, testutil::hex("79"))!!;
	harness::expect_out(&s.core, "F0 0A 18 08 15 00 01 6D 16 00 01 79");
	harness::feed(&s.core, &s.clock, "F0 06 00 04 15 00 01 6D");                           // success
	ev = s.take();
	assert(ev.kind == EventKind.AUTH && ev.auth.reason == ReasonCode.SUCCESS);
	assert(s.core.state == State.CONNECTED);
	// the arguments are checked
	assert(@catch(s.core.send_auth(s.clock.now, ReasonCode.NORMAL_DISCONNECTION, {})) == mqtt::INVALID_ARGUMENT);
	s.close();
	// with a hook the core answers challenges of a re-authentication itself
	Session t;
	FakeAuth fake;
	Config d = cfg();
	d.auth_hook = &fake;
	d.has_auth_hook = true;
	t.open(&d, CONNACK_5);
	t.core.send_auth(t.clock.now, ReasonCode.RE_AUTHENTICATE, {})!!;
	harness::expect_out(&t.core, "F0 06 19 04 15 00 01 6D");
	harness::feed(&t.core, &t.clock, "F0 0B 18 09 15 00 01 6D 16 00 02 63 31");
	harness::expect_out(&t.core, "F0 0B 18 09 15 00 01 6D 16 00 02 72 31");
	t.close();
}

fn void auth_method_mismatch() @test
{
	Session s;
	Config c = cfg();
	s.open(&c, CONNACK_5);
	char[] other = testutil::hex("F0 06 18 04 15 00 01 78");              // method "x" instead of "m"
	assert(@catch(s.core.input(s.clock.now, other)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&s.core, "E0 01 82");
	s.close();
	// no method at all
	Session t;
	Config d = cfg();
	t.open(&d, CONNACK_5);
	char[] none = testutil::hex("F0 02 18 00");
	assert(@catch(t.core.input(t.clock.now, none)) == mqtt::PROTOCOL_ERROR);
	t.close();
	// a challenge is not a way to end an authentication that was never started, and 0x19 is for clients
	Session u;
	Config e = cfg();
	u.open(&e, CONNACK_5);
	char[] weird = testutil::hex("F0 06 19 04 15 00 01 6D");
	assert(@catch(u.core.input(u.clock.now, weird)) == mqtt::PROTOCOL_ERROR);
	u.close();
}

fn void auth_hook_fail() @test
{
	Session s;
	FakeAuth fake = { .fail_round = 2 };
	Config c = cfg();
	c.auth_hook = &fake;
	c.has_auth_hook = true;
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	harness::feed(&s.core, &s.clock, "F0 0B 18 09 15 00 01 6D 16 00 02 63 31");
	s.core.output_done(s.core.pending_output().len);
	char[] second = testutil::hex("F0 0B 18 09 15 00 01 6D 16 00 02 63 32");
	assert(@catch(s.core.input(s.clock.now, second)) == mqtt::AUTH_FAILED);
	harness::expect_out(&s.core, "E0 01 87");                                          // Not authorized
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::AUTH_FAILED && !ev.closed.by_server);
	s.close();
}

fn void auth_hook_initial_failure() @test
{
	Core core;
	FakeAuth fake = { .initial_fails = true };
	Config c = cfg();
	c.auth_hook = &fake;
	c.has_auth_hook = true;
	core.init(mem, &c)!!;
	defer core.free();
	Duration t;
	assert(@catch(core.connect(t)) == mqtt::AUTH_FAILED);
	assert(core.state == State.DISCONNECTED);
}

fn void connack_bad_auth_method_0x8c() @test
{
	Session s;
	Config c = cfg();
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	char[] frame = testutil::hex("20 03 00 8C 00");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::CONNECTION_REFUSED);
	Event ev = s.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.reason == ReasonCode.BAD_AUTHENTICATION_METHOD && ev.closed.by_server);
	s.close();
}

fn void vec_V_5_N26() @test
{
	// an AUTH packet although we never asked for enhanced authentication
	Session s;
	Config c = core::default_config(Version.V5, "a");
	s.open(&c, CONNACK_5);
	char[] frame = testutil::hex("F0 01 18");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&s.core, "E0 01 82");
	s.close();
}

fn void auth_on_311_protocol_error() @test
{
	Session s;
	Config c = core::default_config(Version.V311, "a");
	s.open(&c, "20 02 00 00");
	char[] frame = testutil::hex("F0 00");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	harness::expect_no_out(&s.core);
	s.close();
}

fn void auth_method_on_311_invalid_argument() @test
{
	Core core;
	Config c = core::default_config(Version.V311, "a");
	c.auth_method = "m";
	assert(@catch(core.init(mem, &c)) == mqtt::INVALID_ARGUMENT);
	FakeAuth fake;
	Config d = core::default_config(Version.V5, "a");
	d.auth_hook = &fake;                              // a hook needs a method to belong to
	d.has_auth_hook = true;
	assert(@catch(core.init(mem, &d)) == mqtt::INVALID_ARGUMENT);
	// the application cannot send AUTH without a method either
	Session s;
	Config e = core::default_config(Version.V5, "a");
	s.open(&e, CONNACK_5);
	assert(@catch(s.core.send_auth(s.clock.now, ReasonCode.RE_AUTHENTICATE, {})) == mqtt::INVALID_ARGUMENT);
	s.close();
}

// ---- the CONNACK and the authentication method ----

fn void connack_with_an_unasked_authentication_method() @test
{
	// we asked for no authentication: the server must not claim one
	Session s;
	Config c = core::default_config(Version.V5, "a");
	s.mem_track.init(mem);
	s.core.init(&s.mem_track, &c)!!;
	s.core.connect(s.clock.now)!!;
	s.core.output_done(s.core.pending_output().len);
	char[] frame = testutil::hex("20 07 00 00 04 15 00 01 6D");
	assert(@catch(s.core.input(s.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&s.core, "E0 01 82");
	s.close();
	// another method than ours
	Session t;
	Config d = cfg();
	t.mem_track.init(mem);
	t.core.init(&t.mem_track, &d)!!;
	t.core.connect(t.clock.now)!!;
	t.core.output_done(t.core.pending_output().len);
	char[] other = testutil::hex("20 07 00 00 04 15 00 01 78");
	assert(@catch(t.core.input(t.clock.now, other)) == mqtt::PROTOCOL_ERROR);
	t.close();
	// our method, or none at all, is fine
	Session u;
	Config e = cfg();
	u.mem_track.init(mem);
	u.core.init(&u.mem_track, &e)!!;
	u.core.connect(u.clock.now)!!;
	u.core.output_done(u.core.pending_output().len);
	harness::feed(&u.core, &u.clock, "20 07 00 00 04 15 00 01 6D");
	assert(u.take().kind == EventKind.CONNECTED);
	u.close();
	Session v;
	v.mem_track.init(mem);
	v.core.init(&v.mem_track, &e)!!;
	v.core.connect(v.clock.now)!!;
	v.core.output_done(v.core.pending_output().len);
	harness::feed(&v.core, &v.clock, CONNACK_5);
	assert(v.take().kind == EventKind.CONNECTED);
	v.close();
}
