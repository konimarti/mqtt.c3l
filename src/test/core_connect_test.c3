module mqtt::core_connect_test;
import mqtt, mqtt::core, mqtt::harness, mqtt::packet, mqtt::testutil, std::core::mem::allocators, std::time;

fn Config c311(String id, ushort keep_alive = 60)
{
	Config c = core::default_config(Version.V311, id);
	c.keep_alive = keep_alive;
	return c;
}

fn Config c5(String id, ushort keep_alive = 60)
{
	Config c = core::default_config(Version.V5, id);
	c.keep_alive = keep_alive;
	return c;
}

// Core with a tracking allocator: every test frees the core and requires that nothing is left over.
struct Rig
{
	TrackingAllocator mem_track;
	Core core;
	VirtualClock clock;
}

fn void Rig.start(&self, Config* c)
{
	self.mem_track.init(mem);
	self.core.init(&self.mem_track, c)!!;
}

fn void Rig.finish(&self)
{
	self.core.free();
	self.core.free();                                    // a second free is harmless
	assert(self.mem_track.allocation_count() == 0, "the core released everything");
	self.mem_track.free();
}

// connect and take the CONNECT bytes
fn void Rig.connect_expecting(&self, String hex)
{
	self.core.connect(self.clock.now)!!;
	harness::expect_out(&self.core, hex);
}

fn void Rig.accept(&self, String connack_hex)
{
	harness::feed(&self.core, &self.clock, connack_hex);
	EventKind[] kinds = harness::drain(&self.core);
	assert(kinds.len == 1 && kinds[0] == EventKind.CONNECTED, "CONNACK accepted");
}

fn Event Rig.take(&self)
{
	Event ev;
	assert(self.core.poll_event(&ev), "an event is waiting");
	return ev;
}

// ---- CONNECT bytes ----

fn void vec_V_311_CONN_1_via_core() @test
{
	Rig r;
	Config c = c311("a");
	r.start(&c);
	r.connect_expecting("10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61");
	assert(r.core.state == State.CONNECTING);
	r.finish();
}

fn void vec_V_311_CONN_2_via_core() @test
{
	Rig r;
	Config c = c311("c", 10);
	char[1] pass = { 0x70 };
	c.set_credentials("u", pass[..]);
	Will w = { .topic = "w", .payload = testutil::hex("6D"), .qos = QoS.AT_LEAST_ONCE, .retain = true };
	c.will = &w;
	r.start(&c);
	r.connect_expecting("10 19 00 04 4D 51 54 54 04 EE 00 0A 00 01 63 00 01 77 00 01 6D 00 01 75 00 01 70");
	r.finish();
}

fn void vec_V_311_CONN_3_via_core() @test
{
	Rig r;
	Config c = c311("");
	r.start(&c);
	r.connect_expecting("10 0C 00 04 4D 51 54 54 04 02 00 3C 00 00");
	r.finish();
}

fn void vec_V_311_CONN_4_refused_by_init() @test
{
	// an empty client id without a clean session is not a valid 3.1.1 configuration
	Core core;
	Config c = c311("");
	c.clean_start = false;
	assert(@catch(core.init(mem, &c)) == mqtt::INVALID_ARGUMENT);
}

// A 5.0 CONNECT always carries Maximum Packet Size (256 KiB = 00 04 00 00 unless configured), so the
// bytes are the codec vectors with the property `27 00 04 00 00` added to the property block.
fn void vec_V_5_CONN_1_via_core() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.connect_expecting("10 13 00 04 4D 51 54 54 05 02 00 3C 05 27 00 04 00 00 00 01 61");
	r.finish();
}

fn void vec_V_5_CONN_2_via_core() @test
{
	Rig r;
	Config c = c5("a");
	c.session_expiry = 3600;
	c.receive_maximum = 20;
	r.start(&c);
	r.connect_expecting("10 1B 00 04 4D 51 54 54 05 02 00 3C 0D 11 00 00 0E 10 21 00 14 27 00 04 00 00 00 01 61");
	r.finish();
}

fn void vec_V_5_CONN_3_via_core() @test
{
	Rig r;
	Config c = c5("c", 10);
	Will w = { .topic = "w", .payload = testutil::hex("6D") };
	c.will = &w;
	r.start(&c);
	r.connect_expecting("10 1A 00 04 4D 51 54 54 05 06 00 0A 05 27 00 04 00 00 00 01 63 00 00 01 77 00 01 6D");
	r.finish();
}

fn void vec_V_5_CONN_4_via_core() @test
{
	Rig r;
	Config c = c5("");
	r.start(&c);
	r.connect_expecting("10 12 00 04 4D 51 54 54 05 02 00 3C 05 27 00 04 00 00 00 00");
	r.finish();
}

fn void connect_properties_from_config() @test
{
	Rig r;
	Config c = c5("id");
	c.topic_alias_maximum = 10;
	c.request_response_info = true;
	c.omit_problem_info = true;
	c.max_packet_size = 1024;
	UserProperty[1] users = { { "k", "v" } };
	c.user_props.user = users[..];
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	Packet p = packet::decode(Version.V5, r.core.pending_output())!!;
	Connect* k = &p.connect;
	assert(k.props.topic_alias_maximum == 10 && k.props.request_response_info == 1);
	assert(k.props.has(PropId.REQUEST_PROBLEM_INFORMATION) && k.props.request_problem_info == 0);
	assert(k.props.max_packet_size == 1024);
	assert(!k.props.has(PropId.SESSION_EXPIRY_INTERVAL) && !k.props.has(PropId.RECEIVE_MAXIMUM));
	UserPropIter it = k.props.user_props();
	UserProperty u;
	assert(it.next(&u)!! && u.key == "k" && u.value == "v");
	r.finish();
}

fn void connect_twice_is_refused() @test
{
	Rig r;
	Config c = c311("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	assert(@catch(r.core.connect(r.clock.now)) == mqtt::ALREADY_CONNECTED);
	r.finish();
}

fn void init_refuses_bad_configurations() @test
{
	Core core;
	{
		Config c = c311("a");
		c.version = (Version)0;
		assert(@catch(core.init(mem, &c)) == mqtt::UNSUPPORTED_VERSION, "no protocol version chosen");
	}
	{
		Config c = c311("a");
		c.has_password = true;
		c.password = testutil::hex("01");
		assert(@catch(core.init(mem, &c)) == mqtt::INVALID_ARGUMENT, "3.1.1 password without user name");
		Config d = c5("a");
		d.set_password_only(testutil::hex("01"));
		core.init(mem, &d)!!;
		core.free();
	}
	{
		Config c = c311("a");
		c.auth_method = "x";
		assert(@catch(core.init(mem, &c)) == mqtt::INVALID_ARGUMENT, "enhanced authentication is 5.0 only");
	}
	{
		Config c = c311("a");
		Will w = { .topic = "a/+" };
		c.will = &w;
		assert(@catch(core.init(mem, &c)) == mqtt::INVALID_ARGUMENT, "will topic with a wildcard");
	}
	{
		Config c = c5("a");
		c.max_packet_size = 100_000;
		c.max_in_buffer = 99_999;
		assert(@catch(core.init(mem, &c)) == mqtt::INVALID_ARGUMENT, "input buffer smaller than one packet");
		c.max_in_buffer = 100_000;
		core.init(mem, &c)!!;
		core.free();
	}
	{
		Config c = c5("a");
		c.max_packet_size = 268_435_456;
		assert(@catch(core.init(mem, &c)) == mqtt::INVALID_ARGUMENT, "above the protocol maximum");
	}
}

// ---- CONNACK ----

fn void connack_refused_311(char code, ReasonCode expected)
{
	Rig r;
	Config c = c311("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	char[4] frame = { 0x20, 0x02, 0x00, code };
	assert(@catch(r.core.input(r.clock.now, frame[..])) == mqtt::CONNECTION_REFUSED);
	assert(r.core.state == State.DISCONNECTED);
	Event ev = r.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.by_server);
	assert(ev.closed.cause == mqtt::CONNECTION_REFUSED && ev.closed.reason == expected);
	Event none;
	assert(!r.core.poll_event(&none));
	r.core.transport_closed(r.clock.now);
	assert(!r.core.poll_event(&none), "CLOSED is queued once per connection");
	r.finish();
}

fn void connack_refused_all_311_codes() @test
{
	connack_refused_311(1, ReasonCode.UNSUPPORTED_PROTOCOL_VERSION);
	connack_refused_311(2, ReasonCode.CLIENT_ID_NOT_VALID);
	connack_refused_311(3, ReasonCode.SERVER_UNAVAILABLE);
	connack_refused_311(4, ReasonCode.BAD_USER_NAME_OR_PASSWORD);
	connack_refused_311(5, ReasonCode.NOT_AUTHORIZED);
}

fn void connack_accepted_311() @test
{
	Rig r;
	Config c = c311("a", 30);
	c.clean_start = false;
	r.start(&c);
	r.connect_expecting("10 0D 00 04 4D 51 54 54 04 00 00 1E 00 01 61");
	harness::feed(&r.core, &r.clock, "20 02 01 00");
	Event ev = r.take();
	assert(ev.kind == EventKind.CONNECTED && ev.connected.session_present);
	ConnectedInfo* i = &ev.connected;
	assert(i.keep_alive == 30 && !i.server_keep_alive_set);
	assert(i.receive_maximum == 20, "the 3.1.1 send window is the configured max_inflight (default 20)");
	assert(i.maximum_qos == QoS.EXACTLY_ONCE && i.retain_available && i.wildcard_available && i.subid_available && i.shared_available);
	assert(i.topic_alias_maximum == 0 && i.max_packet_size == 0);
	assert(r.core.state == State.CONNECTED);
	r.finish();
}

fn void connack_v5_properties() @test
{
	Rig r;
	Config c = c5("");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	harness::feed(&r.core, &r.clock, "20 19 00 00 16 21 00 14 24 01 25 00 27 00 00 04 00 28 00 29 00 2A 00 12 00 01 78");
	Event ev = r.take();
	ConnectedInfo* i = &ev.connected;
	assert(ev.kind == EventKind.CONNECTED && !i.session_present);
	assert(i.receive_maximum == 20 && i.maximum_qos == QoS.AT_LEAST_ONCE && !i.retain_available);
	assert(i.max_packet_size == 1024 && !i.wildcard_available && !i.subid_available && !i.shared_available);
	assert(i.assigned_client_id == "x" && i.props.assigned_client_id == "x");
	assert(i.keep_alive == 60 && !i.server_keep_alive_set);
	// the assigned identifier is used for every later connection
	r.core.transport_closed(r.clock.now);
	EventKind[] kinds = harness::drain(&r.core);
	assert(kinds.len == 1 && kinds[0] == EventKind.CLOSED);
	r.core.connect(r.clock.now)!!;
	harness::expect_out(&r.core, "10 13 00 04 4D 51 54 54 05 02 00 3C 05 27 00 04 00 00 00 01 78");
	r.finish();
}

fn void connack_v5_defaults_when_properties_are_absent() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	harness::feed(&r.core, &r.clock, "20 03 00 00 00");
	Event ev = r.take();
	ConnectedInfo* i = &ev.connected;
	assert(i.receive_maximum == 65_535 && i.maximum_qos == QoS.EXACTLY_ONCE && i.retain_available);
	assert(i.wildcard_available && i.subid_available && i.shared_available);
	assert(i.max_packet_size == 0 && i.topic_alias_maximum == 0 && i.assigned_client_id.len == 0);
	r.finish();
}

fn void connack_split_byte_by_byte() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	String frame = "20 09 00 00 06 22 00 0A 13 00 1E";
	harness::feed(&r.core, &r.clock, frame, 1);
	Event ev = r.take();
	assert(ev.kind == EventKind.CONNECTED && ev.connected.topic_alias_maximum == 10 && ev.connected.keep_alive == 30);
	Event none;
	assert(!r.core.poll_event(&none));
	r.finish();
}

fn void connack_refused_v5_with_server_reference() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	char[] frame = testutil::hex("20 07 00 9C 04 1C 00 01 62");
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::CONNECTION_REFUSED);
	Event ev = r.take();
	assert(ev.closed.reason == ReasonCode.USE_ANOTHER_SERVER && ev.closed.server_reference == "b");
	assert(r.core.pending_output().len == 0, "no DISCONNECT after a refusal");
	r.finish();
}

fn void connack_session_present_after_clean_start() @test
{
	Rig r;
	Config c = c311("a");                       // clean session
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	char[] frame = testutil::hex("20 02 01 00");
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	assert(r.core.state == State.DISCONNECTED);
	Event ev = r.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::PROTOCOL_ERROR && !ev.closed.by_server);
	assert(r.core.pending_output().len == 0, "3.1.1 sends nothing for a fault");
	r.finish();

	Rig q;
	Config d = c5("a");
	q.start(&d);
	q.core.connect(q.clock.now)!!;
	q.core.output_done(q.core.pending_output().len);
	char[] f5 = testutil::hex("20 03 01 00 00");
	assert(@catch(q.core.input(q.clock.now, f5)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&q.core, "E0 01 82");
	q.finish();
}

// ---- wrong packets ----

fn void vec_V_FR_N11() @test
{
	Rig r;
	Config c = c311("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	char[] frame = testutil::hex("20 03 00 00 00");           // a 3.1.1 CONNACK is exactly 2 bytes long
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::MALFORMED_PACKET);
	Event ev = r.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::MALFORMED_PACKET);
	r.finish();
}

fn void vec_V_FR_N12() @test
{
	// a DISCONNECT before any CONNACK
	{
		Rig r;
		Config c = c311("a");
		r.start(&c);
		r.core.connect(r.clock.now)!!;
		r.core.output_done(r.core.pending_output().len);
		char[] frame = testutil::hex("E0 00");
		assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
		r.finish();
	}
	// a second CONNACK
	{
		Rig r;
		Config c = c311("a");
		r.start(&c);
		r.core.connect(r.clock.now)!!;
		r.core.output_done(r.core.pending_output().len);
		r.accept("20 02 00 00");
		char[] frame = testutil::hex("20 02 00 00");
		assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
		Event ev = r.take();
		assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::PROTOCOL_ERROR);
		r.finish();
	}
}

fn void packets_only_a_server_receives() @test
{
	String[4] frames = { "C0 00", "82 08 00 01 00 03 61 2F 23 01", "A2 07 00 02 00 03 61 2F 23", "10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61" };
	foreach (f : frames)
	{
		Rig r;
		Config c = c311("a");
		r.start(&c);
		r.core.connect(r.clock.now)!!;
		r.core.output_done(r.core.pending_output().len);
		r.accept("20 02 00 00");
		char[] frame = testutil::hex(f);
		assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::PROTOCOL_ERROR, "client-bound packet");
		r.finish();
	}
	// a DISCONNECT from the server is not a 3.1.1 packet
	Rig r;
	Config c = c311("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	r.accept("20 02 00 00");
	char[] frame = testutil::hex("E0 00");
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	r.finish();
}

fn void first_packet_must_be_connack() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	char[] frame = testutil::hex("D0 00");                      // PINGRESP before CONNACK
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::PROTOCOL_ERROR);
	harness::expect_out(&r.core, "E0 01 82");
	r.finish();
}

fn void server_disconnect_v5() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	r.accept("20 03 00 00 00");
	char[] frame = testutil::hex("E0 0B 9C 09 1C 00 06 68 6F 73 74 3A 31");
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::SERVER_DISCONNECTED);
	Event ev = r.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.by_server && ev.closed.reason == ReasonCode.USE_ANOTHER_SERVER);
	assert(ev.closed.server_reference == "host:1");
	r.finish();
}

fn void garbage_is_malformed() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	char[] frame = testutil::hex("00 00");
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::MALFORMED_PACKET);
	harness::expect_out(&r.core, "E0 01 81");
	// nothing is accepted after the connection ended
	assert(@catch(r.core.input(r.clock.now, frame)) == mqtt::NOT_CONNECTED);
	r.finish();
}

// ---- input limits ----

fn void inbound_packet_limit_is_checked_on_the_header() @test
{
	// `30 E8 07` announces a 1000 byte body: refused after three bytes, with a limit of 100
	{
		Rig r;
		Config c = c5("a");
		c.max_packet_size = 100;
		r.start(&c);
		r.core.connect(r.clock.now)!!;
		r.core.output_done(r.core.pending_output().len);
		r.accept("20 03 00 00 00");
		char[] hdr = testutil::hex("30 E8 07");
		assert(@catch(r.core.input(r.clock.now, hdr)) == mqtt::PACKET_TOO_LARGE);
		harness::expect_out(&r.core, "E0 01 95");
		Event ev = r.take();
		assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::PACKET_TOO_LARGE);
		r.finish();
	}
	{
		Rig r;
		Config c = c311("a");
		c.max_packet_size = 100;
		r.start(&c);
		r.core.connect(r.clock.now)!!;
		r.core.output_done(r.core.pending_output().len);
		r.accept("20 02 00 00");
		char[] hdr = testutil::hex("30 E8 07");
		assert(@catch(r.core.input(r.clock.now, hdr)) == mqtt::PACKET_TOO_LARGE);
		assert(r.core.pending_output().len == 0, "3.1.1 cannot tell the server");
		r.finish();
	}
}

fn void undelivered_input_is_bounded() @test
{
	Rig r;
	Config c = c5("a");
	c.max_packet_size = 100;
	c.max_in_buffer = 100;
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	char[] big = mem::temp_array(char, 101);
	big[..] = 0x00;
	assert(@catch(r.core.input(r.clock.now, big)) == mqtt::QUEUE_FULL);
	assert(r.core.state == State.CONNECTING, "nothing was consumed, the connection is still open");
	r.accept("20 03 00 00 00");
	r.finish();
}

// ---- DISCONNECT while connecting, closing ----

fn void connecting_only_auth_disconnect() @test
{
	Rig r;
	Config c = c5("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	r.core.output_done(r.core.pending_output().len);
	assert(r.core.state == State.CONNECTING);
	OutMessage msg = { .topic = "t" };
	assert(@catch(r.core.publish(r.clock.now, &msg)) == mqtt::NOT_CONNECTED);
	SubEntry[1] entries = { { .filter = "a/#" } };
	assert(@catch(r.core.subscribe(r.clock.now, entries[..], null)) == mqtt::NOT_CONNECTED);
	String[1] filters = { "a/#" };
	assert(@catch(r.core.unsubscribe(r.clock.now, filters[..], null)) == mqtt::NOT_CONNECTED);
	assert(r.core.pending_output().len == 0, "nothing was queued");
	// a DISCONNECT is allowed, and the connection ends when it has been written
	r.core.disconnect(r.clock.now, ReasonCode.NORMAL_DISCONNECTION, null)!!;
	assert(r.core.state == State.DISCONNECTING);
	harness::expect_out(&r.core, "E0 00");
	Event ev = r.take();
	assert(ev.kind == EventKind.CLOSED && !ev.closed.by_server);
	fault none;
	assert(ev.closed.cause == none && ev.closed.reason == ReasonCode.NORMAL_DISCONNECTION);
	assert(r.core.state == State.DISCONNECTED);
	r.core.transport_closed(r.clock.now);
	EventKind[] kinds = harness::drain(&r.core);
	assert(kinds.len == 0, "the orderly close is reported once");
	assert(@catch(r.core.disconnect(r.clock.now, ReasonCode.NORMAL_DISCONNECTION, null)) == mqtt::NOT_CONNECTED);
	r.finish();
}

fn void transport_closed_reports_once_and_drops_unwritten_bytes() @test
{
	Rig r;
	Config c = c311("a");
	r.start(&c);
	r.core.connect(r.clock.now)!!;
	assert(r.core.pending_output().len > 0);
	r.core.transport_closed(r.clock.now);
	assert(r.core.pending_output().len == 0);
	Event ev = r.take();
	assert(ev.kind == EventKind.CLOSED && ev.closed.cause == mqtt::CLOSED);
	r.core.transport_closed(r.clock.now);
	EventKind[] kinds = harness::drain(&r.core);
	assert(kinds.len == 0);
	// a fresh connection after the close
	r.core.connect(r.clock.now)!!;
	harness::expect_out(&r.core, "10 0D 00 04 4D 51 54 54 04 02 00 3C 00 01 61");
	r.finish();
}

// ---- memory ----

fn void core_releases_everything() @test
{
	Rig r;
	Config c = c5("");
	r.start(&c);
	for (int round = 0; round < 3; round++)
	{
		r.core.connect(r.clock.now)!!;
		r.core.output_done(r.core.pending_output().len);
		r.accept("20 0D 00 00 0A 12 00 04 61 62 63 64 13 00 05");
		r.core.transport_closed(r.clock.now);
		harness::drain(&r.core);
	}
	r.finish();
}

// the same check without free(): the tracking allocator must report what is left
fn void core_leak_check_has_teeth() @test
{
	TrackingAllocator t;
	t.init(mem);
	Core core;
	Config c = c5("a");
	core.init(&t, &c)!!;
	assert(t.allocation_count() > 0, "an unreleased core shows up as allocations");
	core.free();
	assert(t.allocation_count() == 0);
	t.free();
}
