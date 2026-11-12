module mqtt::core;
import mqtt, mqtt::packet, mqtt::props, mqtt::topic;
import std::core::dstring, std::collections::list, std::time;

// Enhanced authentication hook (5.0 section 4.12). The core never interprets auth data.
// The hook only has to turn the server's challenge into a response.
enum AuthAction : char
{
	CONTINUE,   // send AUTH (0x18, Continue) with `out`
	DONE,       // nothing to send; wait for CONNACK / AUTH(Success)
	FAIL,       // abort: core sends DISCONNECT and returns AUTH_FAILED
}

interface AuthHook
{
	// Fills out with the data of the initial CONNECT Authentication Data.
	fn void? initial(DString* out);
	// Called for each AUTH packet (reason 0x18) or re-authentication challenge.
	fn AuthAction? step(char[] server_data, DString* out);
}

// Zero value rule: a zero-initialised field means "the spec default or the documented default",
// so a Config built without default_config() is still safe. default_config() only sets
// version, client_id, clean_start = true and keep_alive = 60 (a zero `clean_start` is a real choice).
struct Config
{
	Version version;
	String client_id;               // must outlive the Core
	bool clean_start;
	ushort keep_alive;              // seconds, 0 = disabled
	bool has_username;              // set with set_credentials / set_password_only, not by hand
	String username;
	bool has_password;
	char[] password;                // Core.free overwrites its own copies only; this one is the caller's
	Will* will;                     // null = no will
	// v5 only:
	uint session_expiry;            // seconds, 0xFFFFFFFF = never
	ushort receive_maximum;         // inbound QoS>0 window we advertise; 0 = 65535
	uint max_packet_size;           // inbound limit, advertised in v5 CONNECT; 0 = 256 KiB; max 268_435_455
	ushort topic_alias_maximum;     // aliases we accept from the server; 0 = none
	bool request_response_info;
	bool omit_problem_info;         // true sends Request Problem Information 0 (zero value = spec default 1)
	String auth_method;             // empty = no enhanced auth
	char[] auth_data;
	AuthHook auth_hook;
	bool has_auth_hook;
	Properties user_props;          // extra CONNECT properties (user properties)
	// behaviour:
	ushort max_inflight;            // outbound QoS>0 window for 3.1.1 (v5 uses the server's); 0 = 20
	usz max_queued;                 // messages waiting for a free slot; 0 = 1024
	bool auto_topic_alias;          // allocate outbound aliases for repeated topics
	usz max_out_buffer;             // bytes of encoded output allowed to pile up; 0 = 1 MiB
	usz max_in_buffer;              // undelivered input bytes; 0 = max(4 MiB, max_packet_size); init faults if < max_packet_size
	ushort ping_after_pct;          // PINGREQ after this percent of keep_alive idle; 0 = 75
	ushort pong_timeout_pct;        // PINGRESP deadline, percent of keep_alive; 0 = 100
	bool validate_payload_utf8;     // v5: payload format 1 with bad UTF-8 -> DISCONNECT 0x99
}

const uint DEFAULT_MAX_PACKET_SIZE = 256 * 1024;
const usz DEFAULT_MAX_IN_BUFFER = 4 * 1024 * 1024;
const usz DEFAULT_MAX_OUT_BUFFER = 1024 * 1024;
const usz DEFAULT_MAX_QUEUED = 1024;
const ushort DEFAULT_MAX_INFLIGHT = 20;
const ushort DEFAULT_RECEIVE_MAXIMUM = 65_535;
const ushort DEFAULT_PING_AFTER_PCT = 75;
const ushort DEFAULT_PONG_TIMEOUT_PCT = 100;
const ushort DEFAULT_KEEP_ALIVE = 60;

// Sets version, client_id, clean_start = true, keep_alive = 60; all other fields stay zero (= defaults above).
fn Config default_config(Version v, String client_id) => { .version = v, .client_id = client_id, .clean_start = true, .keep_alive = DEFAULT_KEEP_ALIVE };
// Keeps the flags and values consistent. A 3.1.1 Config with an empty username and a password is
// rejected by Core.init (3.1.1 3.1.2.9); empty strings are legal in 5.0.
fn void Config.set_credentials(&self, String username, char[] password) { self.has_username = true; self.username = username; self.has_password = true; self.password = password; }
fn void Config.set_username_only(&self, String username) { self.has_username = true; self.username = username; self.has_password = false; self.password = {}; }
// 5.0 only (password without user name).
fn void Config.set_password_only(&self, char[] password) { self.has_username = false; self.username = ""; self.has_password = true; self.password = password; }

// The values the core works with: a zero field in Config stands for the documented default.
fn uint Config.effective_max_packet_size(&self) => self.max_packet_size == 0 ? DEFAULT_MAX_PACKET_SIZE : self.max_packet_size;
fn ushort Config.effective_max_inflight(&self) => self.max_inflight == 0 ? DEFAULT_MAX_INFLIGHT : self.max_inflight;
fn usz Config.effective_max_queued(&self) => self.max_queued == 0 ? DEFAULT_MAX_QUEUED : self.max_queued;
fn usz Config.effective_max_out_buffer(&self) => self.max_out_buffer == 0 ? DEFAULT_MAX_OUT_BUFFER : self.max_out_buffer;
fn ushort Config.effective_ping_after_pct(&self) => self.ping_after_pct == 0 ? DEFAULT_PING_AFTER_PCT : self.ping_after_pct;
fn ushort Config.effective_pong_timeout_pct(&self) => self.pong_timeout_pct == 0 ? DEFAULT_PONG_TIMEOUT_PCT : self.pong_timeout_pct;
fn ushort Config.effective_receive_maximum(&self) => self.receive_maximum == 0 ? DEFAULT_RECEIVE_MAXIMUM : self.receive_maximum;

// Undelivered input the core may hold: at least DEFAULT_MAX_IN_BUFFER, and never less than one packet.
fn usz Config.effective_max_in_buffer(&self)
{
	if (self.max_in_buffer != 0) return self.max_in_buffer;
	usz packet = self.effective_max_packet_size();
	return packet > DEFAULT_MAX_IN_BUFFER ? packet : DEFAULT_MAX_IN_BUFFER;
}

// Request Problem Information is sent as 1 unless omit_problem_info is set (the spec default is 1).
fn bool Config.requests_problem_info(&self) => !self.omit_problem_info;

enum State : char
{
	DISCONNECTED,   // no transport; session state may still be held
	CONNECTING,     // CONNECT queued/sent, waiting for CONNACK (or AUTH exchange)
	CONNECTED,
	DISCONNECTING,  // DISCONNECT queued; closing after it is flushed
}

enum EventKind : char
{
	CONNECTED,      // CONNACK accepted
	MESSAGE,        // inbound PUBLISH (QoS 0, or first delivery of QoS 1/2)
	PUBLISH_DONE,   // outbound QoS 1/2 finished (PUBACK or PUBCOMP) or failed (reason >= 0x80)
	SUBSCRIBED,     // SUBACK
	UNSUBSCRIBED,   // UNSUBACK
	AUTH,           // AUTH packet received, no hook (or hook returned CONTINUE)
	CLOSED,         // connection ended: server DISCONNECT, error, or our DISCONNECT flushed;
	// always delivered after every event queued before it
	PONG,           // PINGRESP (informational)
}

struct ConnectedInfo
{
	bool session_present;
	bool server_keep_alive_set;
	ushort keep_alive;              // effective keep alive
	ushort receive_maximum;         // server's limit on our QoS>0 window
	uint max_packet_size;           // 0 = none
	ushort topic_alias_maximum;
	QoS maximum_qos;
	bool retain_available;
	bool wildcard_available;
	bool subid_available;
	bool shared_available;
	String assigned_client_id;
	Properties props;
}

struct MessageInfo
{
	String topic;                   // topic alias already resolved
	char[] payload;
	QoS qos;
	bool retain;
	bool dup;
	ushort packet_id;
	Properties props;
}

struct DoneInfo
{
	ushort packet_id;
	ReasonCode reason;
	Properties props;
}

struct SubAckInfo
{
	ushort packet_id;
	char[] codes;                   // per filter: granted QoS 0..2 or failure (0x80, v5 >= 0x80)
	Properties props;
}

struct ClosedInfo
{
	bool by_server;                 // server DISCONNECT received
	ReasonCode reason;              // v5 reason; for local errors the one we sent
	String server_reference;        // redirect target (reason 0x9C / 0x9D), else empty
	fault cause;                    // local fault, or 0 when orderly
	bool session_kept;
}

struct AuthInfo
{
	ReasonCode reason;
	String method;
	char[] data;
}

// Acknowledgements (PUBACK, PUBREC) are queued inside input(), in arrival order, never at poll_event.
// Event data is borrowed from the core input buffer and stays valid until the first
// input() that follows the event queue being drained (poll_event returned false); undelivered events are never invalidated.
struct Event
{
	EventKind kind;
	union
	{
		ConnectedInfo connected;
		MessageInfo message;
		DoneInfo done;
		SubAckInfo suback;
		ClosedInfo closed;
		AuthInfo auth;
	}
}

// Message handed to publish(). Core copies everything it must keep for resends.
struct OutMessage
{
	String topic;
	char[] payload;
	QoS qos;
	bool retain;
	Properties props;               // v5: expiry, content type, response topic, topic_alias ...
}

// Sans-IO client core: no I/O, no threads, and it never reads the time itself. Every call that needs
// time gets `now`, a monotonic `std::time::Duration` since an arbitrary origin that never goes back
// (a value smaller than an earlier one is treated as equal to it).
struct Core
{
	Allocator allocator;
	Config config;
	State state;
	// The fields below are private by convention (C3 has no field privacy).
	List{char} in_buf;              // reassembly + frames still referenced by undelivered events
	sz in_consumed;                // bytes of in_buf already framed
	List{char} out_buf;             // encoded bytes waiting for the transport
	List{EventRec} events;          // queued events, in arrival order
	sz event_head;                 // events before this index were delivered
	List{Inflight} inflight;        // QoS 1/2 sent, not finished, in send order
	List{Inflight} queue;           // QoS 1/2 waiting for quota, FIFO
	List{PendingAck} pending;       // SUBSCRIBE / UNSUBSCRIBE awaiting ack
	List{ushort} in_qos2;           // inbound QoS 2 ids between PUBLISH and PUBREL
	List{AliasEntry} alias_in;      // server -> topic, owned copies
	List{AliasEntry} alias_out;     // topic -> alias, owned copies
	ushort next_id;
	Duration last_now;              // latest time seen, for the "never goes back" rule
	Duration last_tx;               // when a packet was last queued
	Duration last_rx;               // when bytes last arrived
	Duration ping_sent;
	bool ping_outstanding;
	Duration closed_at;
	bool closed_seen;               // CLOSED was emitted for the current connection
	bool reached_connected;         // the current connection got a CONNACK that accepted it
	Limits limits;                  // negotiated by CONNACK
	String assigned_id;             // owned copy of the server assigned client identifier
}

enum InflightState : char { WAIT_PUBACK, WAIT_PUBREC, WAIT_PUBCOMP, QUEUED }

// One allocation holds topic | payload | encoded properties (without Topic Alias).
struct Inflight
{
	ushort id;
	InflightState state;
	QoS qos;
	bool retain;
	Duration queued_at;             // for Message Expiry Interval
	uint expiry_s;                  // 0 = none
	char[] block;
	usz topic_len;
	usz payload_len;
}

enum PendingKind : char { SUBSCRIBE, UNSUBSCRIBE }
struct PendingAck { ushort id; PendingKind kind; usz count; }
struct AliasEntry { ushort alias_id; String topic; Duration last_used; }

// A queued event. The frame it came from stays in in_buf until the queue is drained.
struct EventRec
{
	EventKind kind;
	usz frame_off;
	usz frame_len;                  // 0 = no frame
	ReasonCode reason;              // CLOSED
	fault cause;                    // CLOSED
	bool by_server;                 // CLOSED
	bool session_kept;              // CLOSED
}

struct Limits
{
	ushort send_quota;              // server Receive Maximum (or config.max_inflight on 3.1.1)
	uint max_packet_size;           // server's, 0 = none
	ushort topic_alias_maximum;
	QoS maximum_qos;
	bool retain_available;
	bool wildcard_available;
	bool subid_available;
	bool shared_available;
	ushort keep_alive;              // effective, seconds
	bool server_keep_alive_set;
	uint session_expiry;            // effective, seconds
}

fn bool is_v5(Config* c) @private => c.version == Version.V5;

// All Config checks live here (and nowhere else). INVALID_ARGUMENT unless noted.
fn void? check_config(Config* c) @private
{
	if (c.version != Version.V311 && c.version != Version.V5) return mqtt::UNSUPPORTED_VERSION~;
	wire_check_string(c.client_id)!;
	if (!is_v5(c))
	{
		// 3.1.1: an empty client id needs a clean session, a password needs a user name, no enhanced authentication
		if (c.client_id.len == 0 && !c.clean_start) return mqtt::INVALID_ARGUMENT~;
		if (c.has_password && !c.has_username) return mqtt::INVALID_ARGUMENT~;
		if (c.auth_method.len > 0 || c.has_auth_hook) return mqtt::INVALID_ARGUMENT~;
	}
	if (c.has_auth_hook && c.auth_method.len == 0) return mqtt::INVALID_ARGUMENT~;
	if (c.will != null)
	{
		if (catch err = topic::validate_name(c.will.topic)) return mqtt::INVALID_ARGUMENT~;
	}
	if (c.effective_max_packet_size() > mqtt::MAX_REMAINING_LENGTH) return mqtt::INVALID_ARGUMENT~;
	if (c.max_in_buffer != 0 && c.max_in_buffer < c.effective_max_packet_size()) return mqtt::INVALID_ARGUMENT~;
	if (c.ping_after_pct > 100) return mqtt::INVALID_ARGUMENT~;
}

fn void? wire_check_string(String s) @private
{
	if (s.len > mqtt::MAX_STRING_LENGTH) return mqtt::INVALID_ARGUMENT~;
}

// Config strings and the Will must outlive the Core (borrowed, not copied).
// Faults: UNSUPPORTED_VERSION (no protocol version chosen), INVALID_ARGUMENT: empty client id with
// clean_start false on 3.1.1, 3.1.1 password without username, auth_method or hook on 3.1.1, will
// topic invalid, max_in_buffer < max_packet_size, packet limit above the protocol maximum.
fn void? Core.init(&self, Allocator allocator, Config* config)
{
	check_config(config)!;
	*self = {};
	self.allocator = allocator;
	self.config = *config;
	self.state = State.DISCONNECTED;
	self.in_buf.init(allocator, 1024);
	self.out_buf.init(allocator, 256);
	self.events.init(allocator, 8);
	self.inflight.init(allocator, 0);
	self.queue.init(allocator, 0);
	self.pending.init(allocator, 0);
	self.in_qos2.init(allocator, 0);
	self.alias_in.init(allocator, 0);
	self.alias_out.init(allocator, 0);
}

// Frees all owned memory. Held session state (inflight, queue) is lost.
fn void Core.free(&self)
{
	self.in_buf.free();
	self.out_buf.free();
	self.events.free();
	self.inflight.free();
	self.queue.free();
	self.pending.free();
	self.in_qos2.free();
	self.alias_in.free();
	self.alias_out.free();
	if (self.assigned_id.len > 0) self.assigned_id.free(self.allocator);
	self.assigned_id = "";
	self.state = State.DISCONNECTED;
}

// Moves the time forward, never back.
fn Duration Core.tick(&self, Duration now)
{
	if (now < self.last_now) return self.last_now;
	self.last_now = now;
	return now;
}

fn sz Core.pending_events(&self) => self.events.len() - self.event_head;

// ---- output ----

// Appends a packet to the output buffer; the limits of the buffer apply.
fn void? Core.queue_packet(&self, Duration now, Packet* p)
{
	usz size = packet::encoded_size(self.config.version, p)!;
	if ((usz)self.out_buf.len() + size > self.config.effective_max_out_buffer()) return mqtt::QUEUE_FULL~;
	self.out_buf.reserve((sz)size);
	char[] room = self.out_buf.entries[self.out_buf.size:size];
	usz n = packet::encode(self.config.version, p, room)!;
	self.out_buf.size += (sz)n;
	self.last_tx = now;
}

// Bytes the core wants written to the transport, in order. Stable until output_done.
fn char[] Core.pending_output(&self) => self.out_buf.array_view();

// Tell the core n bytes were written (n <= pending_output().len). When our DISCONNECT has been
// written the connection is over: CLOSED is queued (orderly).
fn void Core.output_done(&self, usz n)
{
	usz len = (usz)self.out_buf.len();
	if (n > len) n = len;
	if (n == len)
	{
		self.out_buf.clear();
	}
	else
	{
		mem::move(self.out_buf.entries, self.out_buf.entries + n, (sz)(len - n));
		self.out_buf.size -= (sz)n;
	}
	if (self.state == State.DISCONNECTING && self.out_buf.len() == 0)
	{
		fault none;                                    // orderly: no fault
		self.emit_closed(self.last_now, none, ReasonCode.NORMAL_DISCONNECTION, false, 0, 0);
	}
}

// ---- connect ----

// Queues CONNECT. Legal in DISCONNECTED. Re-uses the assigned client identifier of an earlier
// connection when the Config has none.
fn void? Core.connect(&self, Duration now)
{
	if (self.state != State.DISCONNECTED) return mqtt::ALREADY_CONNECTED~;
	Duration t = self.tick(now);
	self.out_buf.clear();
	self.in_buf.size = self.in_consumed;             // bytes of an earlier connection are void
	self.closed_seen = false;
	self.reached_connected = false;
	self.ping_outstanding = false;
	self.limits = {};
	Config* c = &self.config;
	Packet p = { .type = PacketType.CONNECT };
	Connect* k = &p.connect;
	k.client_id = c.client_id.len > 0 ? c.client_id : self.assigned_id;
	k.clean_start = c.clean_start;
	k.keep_alive = c.keep_alive;
	if (c.has_username)
	{
		k.has_username = true;
		k.username = c.username;
	}
	if (c.has_password)
	{
		k.has_password = true;
		k.password = c.password;
	}
	if (c.will != null)
	{
		k.has_will = true;
		k.will = *c.will;
	}
	if (is_v5(c))
	{
		Properties* pr = &k.props;
		pr.user = c.user_props.user;
		pr.user_raw = c.user_props.user_raw;
		if (c.session_expiry != 0)
		{
			pr.set(PropId.SESSION_EXPIRY_INTERVAL);
			pr.session_expiry = c.session_expiry;
		}
		if (c.effective_receive_maximum() != DEFAULT_RECEIVE_MAXIMUM)
		{
			pr.set(PropId.RECEIVE_MAXIMUM);
			pr.receive_maximum = c.effective_receive_maximum();
		}
		// always advertise the packet size limit, so a compliant server never exceeds it
		pr.set(PropId.MAXIMUM_PACKET_SIZE);
		pr.max_packet_size = c.effective_max_packet_size();
		if (c.topic_alias_maximum != 0)
		{
			pr.set(PropId.TOPIC_ALIAS_MAXIMUM);
			pr.topic_alias_maximum = c.topic_alias_maximum;
		}
		if (c.request_response_info)
		{
			pr.set(PropId.REQUEST_RESPONSE_INFORMATION);
			pr.request_response_info = 1;
		}
		if (c.omit_problem_info)
		{
			pr.set(PropId.REQUEST_PROBLEM_INFORMATION);
			pr.request_problem_info = 0;
		}
		if (c.auth_method.len > 0)
		{
			pr.set(PropId.AUTHENTICATION_METHOD);
			pr.auth_method = c.auth_method;
			if (c.auth_data.len > 0)
			{
				pr.set(PropId.AUTHENTICATION_DATA);
				pr.auth_data = c.auth_data;
			}
		}
	}
	self.queue_packet(t, &p)!;
	self.state = State.CONNECTING;
}

// ---- input ----

// Feed bytes read from the transport (any split, including mid-packet). Complete frames are
// processed in order. A fault means the connection is over: a CLOSED event was queued (and for 5.0 a
// DISCONNECT where the protocol asks for one); the caller flushes pending_output, closes the transport and
// calls transport_closed. QUEUE_FULL (undelivered input over max_in_buffer) consumes nothing: take the
// events, then feed the bytes again.
fn void? Core.input(&self, Duration now, char[] data)
{
	Duration t = self.tick(now);
	if (self.state == State.DISCONNECTED) return mqtt::NOT_CONNECTED~;
	if (self.pending_events() == 0 && self.in_consumed > 0)
	{
		// every earlier event was delivered: the frames they pointed into can go
		sz left = self.in_buf.len() - self.in_consumed;
		if (left > 0) mem::move(self.in_buf.entries, self.in_buf.entries + self.in_consumed, (sz)left);
		self.in_buf.size = left;
		self.in_consumed = 0;
	}
	if ((usz)self.in_buf.len() + data.len > self.config.effective_max_in_buffer()) return mqtt::QUEUE_FULL~;
	self.last_rx = t;
	self.in_buf.push_all(data);
	while (self.state != State.DISCONNECTED)
	{
		char[] avail = self.in_buf.array_view()[self.in_consumed..];
		usz? n = packet::frame_length(avail, self.config.effective_max_packet_size());
		if (catch err = n) return self.fail(t, err);
		if (n == 0) break;
		usz off = (usz)self.in_consumed;
		self.in_consumed += (sz)n;
		self.handle_frame(t, off, n)!;
	}
}

fn void? Core.handle_frame(&self, Duration now, usz off, usz n)
{
	char[] frame = self.in_buf.entries[off:n];
	Packet? decoded = packet::decode(self.config.version, frame);
	if (catch err = decoded) return self.fail(now, err);
	Packet* p = &decoded;
	// the first packet from the server must be CONNACK
	if (self.state == State.CONNECTING && p.type != PacketType.CONNACK) return self.fail(now, mqtt::PROTOCOL_ERROR);
	switch (p.type)
	{
		case PacketType.CONNACK:
			if (self.state != State.CONNECTING) return self.fail(now, mqtt::PROTOCOL_ERROR);
			self.handle_connack(now, off, n, p)!;
		case PacketType.PINGRESP:
			if (self.ping_outstanding)
			{
				self.ping_outstanding = false;
				self.events.push({ .kind = EventKind.PONG });
			}
		case PacketType.CONNECT:
		case PacketType.SUBSCRIBE:
		case PacketType.UNSUBSCRIBE:
		case PacketType.PINGREQ:
			return self.fail(now, mqtt::PROTOCOL_ERROR);   // packets only a server may receive
		case PacketType.DISCONNECT:
			if (!is_v5(&self.config)) return self.fail(now, mqtt::PROTOCOL_ERROR);
			self.emit_closed(now, mqtt::SERVER_DISCONNECTED, (ReasonCode)p.disconnect.reason, true, off, n);
			return mqtt::SERVER_DISCONNECTED~;
		default:
			// publications, acknowledgements and subscription replies are handled by the QoS flows
			break;
	}
}

fn void? Core.handle_connack(&self, Duration now, usz off, usz n, Packet* p)
{
	ConnAck* a = &p.connack;
	Config* c = &self.config;
	if (a.code != 0)
	{
		ReasonCode r = is_v5(c) ? (ReasonCode)a.code : mqtt::connack311_to_reason((ConnAckCode311)a.code);
		self.emit_closed(now, mqtt::CONNECTION_REFUSED, r, true, off, n);
		return mqtt::CONNECTION_REFUSED~;
	}
	// a server that reports a stored session after a clean start is broken
	if (a.session_present && c.clean_start) return self.fail(now, mqtt::PROTOCOL_ERROR);
	Limits l;
	l.keep_alive = c.keep_alive;
	l.session_expiry = c.session_expiry;
	if (is_v5(c))
	{
		Properties* pr = &a.props;
		l.send_quota = pr.has(PropId.RECEIVE_MAXIMUM) ? pr.receive_maximum : DEFAULT_RECEIVE_MAXIMUM;
		l.max_packet_size = pr.has(PropId.MAXIMUM_PACKET_SIZE) ? pr.max_packet_size : 0;
		l.topic_alias_maximum = pr.has(PropId.TOPIC_ALIAS_MAXIMUM) ? pr.topic_alias_maximum : 0;
		l.maximum_qos = pr.has(PropId.MAXIMUM_QOS) ? (QoS)pr.maximum_qos : QoS.EXACTLY_ONCE;
		l.retain_available = pr.has(PropId.RETAIN_AVAILABLE) ? pr.retain_available == 1 : true;
		l.wildcard_available = pr.has(PropId.WILDCARD_SUBSCRIPTION_AVAILABLE) ? pr.wildcard_sub_available == 1 : true;
		l.subid_available = pr.has(PropId.SUBSCRIPTION_IDENTIFIER_AVAILABLE) ? pr.subid_available == 1 : true;
		l.shared_available = pr.has(PropId.SHARED_SUBSCRIPTION_AVAILABLE) ? pr.shared_sub_available == 1 : true;
		if (pr.has(PropId.SERVER_KEEP_ALIVE))
		{
			l.keep_alive = pr.server_keep_alive;
			l.server_keep_alive_set = true;
		}
		if (pr.has(PropId.SESSION_EXPIRY_INTERVAL)) l.session_expiry = pr.session_expiry;
		if (pr.has(PropId.ASSIGNED_CLIENT_IDENTIFIER))
		{
			// kept for every later connection: session continuity needs the same identifier
			if (self.assigned_id.len > 0) self.assigned_id.free(self.allocator);
			self.assigned_id = pr.assigned_client_id.copy(self.allocator);
		}
	}
	else
	{
		l.send_quota = c.effective_max_inflight();
		l.maximum_qos = QoS.EXACTLY_ONCE;
		l.retain_available = true;
		l.wildcard_available = true;
		l.subid_available = true;
		l.shared_available = true;
	}
	self.limits = l;
	self.state = State.CONNECTED;
	self.reached_connected = true;
	self.ping_outstanding = false;
	self.events.push({ .kind = EventKind.CONNECTED, .frame_off = off, .frame_len = n });
}

// The connection ended with `cause`: queue CLOSED (once per connection) and stop.
fn void Core.emit_closed(&self, Duration now, fault cause, ReasonCode reason, bool by_server, usz off, usz n)
{
	self.state = State.DISCONNECTED;
	if (self.closed_seen) return;
	self.closed_seen = true;
	if (self.reached_connected) self.closed_at = now;
	bool kept = is_v5(&self.config) ? self.limits.session_expiry != 0 || (!self.reached_connected && self.config.session_expiry != 0) : !self.config.clean_start;
	self.events.push({
		.kind = EventKind.CLOSED,
		.frame_off = off,
		.frame_len = n,
		.reason = reason,
		.cause = cause,
		.by_server = by_server,
		.session_kept = kept,
	});
}

// The reason code 5.0 sends in DISCONNECT for a local fault.
fn ReasonCode reason_for(fault cause) @private
{
	if (cause == mqtt::PACKET_TOO_LARGE) return ReasonCode.PACKET_TOO_LARGE;
	if (cause == mqtt::PROTOCOL_ERROR || cause == mqtt::INVALID_PROPERTY) return ReasonCode.PROTOCOL_ERROR;
	if (cause == mqtt::INVALID_TOPIC_NAME) return ReasonCode.TOPIC_NAME_INVALID;
	if (cause == mqtt::UNSUPPORTED_VERSION) return ReasonCode.UNSUPPORTED_PROTOCOL_VERSION;
	return ReasonCode.MALFORMED_PACKET;
}

// A violation by the server: 5.0 gets a DISCONNECT with the matching reason, 3.1.1 just ends
// the connection. Always returns the fault.
fn void? Core.fail(&self, Duration now, fault cause)
{
	ReasonCode reason = reason_for(cause);
	if (is_v5(&self.config) && (self.state == State.CONNECTED || self.state == State.CONNECTING))
	{
		Packet d = { .type = PacketType.DISCONNECT };
		d.disconnect.reason = (char)reason;
		(void)self.queue_packet(now, &d);
	}
	self.emit_closed(now, cause, reason, false, 0, 0);
	self.in_buf.size = self.in_consumed;
	return cause~;
}

// ---- events ----

// Next event, false when none. The data of an Event is borrowed from the core input buffer and stays
// valid until the first input() that follows the event queue being drained (poll_event returned
// false); undelivered events are never invalidated.
fn bool Core.poll_event(&self, Event* ev)
{
	if (self.event_head >= self.events.len()) return false;
	EventRec rec = self.events[self.event_head];
	self.event_head++;
	if (self.event_head == self.events.len())
	{
		self.events.clear();
		self.event_head = 0;
	}
	*ev = { .kind = rec.kind };
	switch (rec.kind)
	{
		case EventKind.CONNECTED:
			Packet p = packet::decode(self.config.version, self.in_buf.entries[rec.frame_off:rec.frame_len])!!;
			Limits* l = &self.limits;
			ev.connected = {
				.session_present = p.connack.session_present,
				.server_keep_alive_set = l.server_keep_alive_set,
				.keep_alive = l.keep_alive,
				.receive_maximum = l.send_quota,
				.max_packet_size = l.max_packet_size,
				.topic_alias_maximum = l.topic_alias_maximum,
				.maximum_qos = l.maximum_qos,
				.retain_available = l.retain_available,
				.wildcard_available = l.wildcard_available,
				.subid_available = l.subid_available,
				.shared_available = l.shared_available,
				.assigned_client_id = p.connack.props.has(PropId.ASSIGNED_CLIENT_IDENTIFIER) ? self.assigned_id : "",
				.props = p.connack.props,
			};
		case EventKind.CLOSED:
			ev.closed = {
				.by_server = rec.by_server,
				.reason = rec.reason,
				.cause = rec.cause,
				.session_kept = rec.session_kept,
			};
			if (rec.frame_len > 0 && is_v5(&self.config))
			{
				Packet? p = packet::decode(self.config.version, self.in_buf.entries[rec.frame_off:rec.frame_len]);
				if (try q = p)
				{
					if (q.type == PacketType.CONNACK) ev.closed.server_reference = q.connack.props.server_reference;
					if (q.type == PacketType.DISCONNECT) ev.closed.server_reference = q.disconnect.props.server_reference;
				}
			}
		default:
			break;
	}
	return true;
}

// ---- timers ----

fn Duration Core.ping_period(&self)
{
	// seconds * percent / 100, in milliseconds, in 64 bit
	return time::ms((long)self.limits.keep_alive * 10 * (long)self.config.effective_ping_after_pct());
}

fn Duration Core.pong_period(&self)
{
	return time::ms((long)self.limits.keep_alive * 10 * (long)self.config.effective_pong_timeout_pct());
}

// When the reply to the outstanding PINGREQ is overdue: the period counts from the PINGREQ or from the
// last bytes received, whichever is later (any inbound data shows the link is alive).
fn Duration Core.pong_deadline(&self)
{
	Duration base = self.last_rx > self.ping_sent ? self.last_rx : self.ping_sent;
	return base + self.pong_period();
}

// Earliest time at which timeout() must be called; false if no timer is armed.
fn bool Core.next_deadline(&self, Duration* deadline)
{
	if (self.state != State.CONNECTED || self.limits.keep_alive == 0) return false;
	*deadline = self.ping_outstanding ? self.pong_deadline() : self.last_tx + self.ping_period();
	return true;
}

// Runs due timers: queues PINGREQ when the connection was idle for ping_after_pct of the keep alive;
// KEEPALIVE_TIMEOUT (and CLOSED) when the reply is overdue. Each due timer fires once per call.
fn void? Core.timeout(&self, Duration now)
{
	Duration t = self.tick(now);
	if (self.state != State.CONNECTED || self.limits.keep_alive == 0) return;
	if (self.ping_outstanding)
	{
		if (t >= self.pong_deadline())
		{
			self.emit_closed(t, mqtt::KEEPALIVE_TIMEOUT, ReasonCode.KEEP_ALIVE_TIMEOUT, false, 0, 0);
			return mqtt::KEEPALIVE_TIMEOUT~;
		}
		return;
	}
	if (t >= self.last_tx + self.ping_period())
	{
		Packet ping = { .type = PacketType.PINGREQ };
		self.queue_packet(t, &ping)!;
		self.ping_outstanding = true;
		self.ping_sent = t;
	}
}

// The transport ended (EOF, error, or after our DISCONNECT was written). Queues CLOSED if the
// connection had not been reported closed yet, and drops what was never written.
fn void Core.transport_closed(&self, Duration now)
{
	Duration t = self.tick(now);
	if (self.state != State.DISCONNECTED)
	{
		fault cause;                                   // none: an orderly close after our DISCONNECT
		if (self.state != State.DISCONNECTING) cause = mqtt::CLOSED;
		self.emit_closed(t, cause, ReasonCode.UNSPECIFIED_ERROR, false, 0, 0);
	}
	self.out_buf.clear();
	self.in_buf.size = self.in_consumed;
	self.ping_outstanding = false;
}

// ---- commands ----

// Queues DISCONNECT (allowed while connecting too). 3.1.1 ignores reason and props. The connection
// ends when pending_output has been written.
fn void? Core.disconnect(&self, Duration now, ReasonCode reason, Properties* props)
{
	if (self.state != State.CONNECTING && self.state != State.CONNECTED) return mqtt::NOT_CONNECTED~;
	Duration t = self.tick(now);
	Packet d = { .type = PacketType.DISCONNECT };
	if (is_v5(&self.config))
	{
		d.disconnect.reason = (char)reason;
		if (props != null) d.disconnect.props = *props;
	}
	self.queue_packet(t, &d)!;
	self.state = State.DISCONNECTING;
}

// Returns the packet id (0 for QoS 0; 0 is never a valid id, [5.0 2.2.1]).
// publish never touches in_buf, so it may be called while an Event is borrowed.
// Faults: NOT_CONNECTED, INVALID_TOPIC_NAME,
// NOT_SUPPORTED_BY_SERVER (QoS/retain above what CONNACK allowed), PACKET_TOO_LARGE,
// QUEUE_FULL. While the server's Receive Maximum is exhausted QoS>0 messages wait in the queue.
fn ushort? Core.publish(&self, Duration now, OutMessage* msg) { return mqtt::NOT_CONNECTED~; }
fn ushort? Core.subscribe(&self, Duration now, SubEntry[] entries, Properties* props) { return mqtt::NOT_CONNECTED~; }
fn ushort? Core.unsubscribe(&self, Duration now, String[] filters, Properties* props) { return mqtt::NOT_CONNECTED~; }
// Manual AUTH (5.0 3.15): continue or re-authenticate (reason 0x19).
fn void? Core.send_auth(&self, Duration now, ReasonCode reason, char[] data) { return mqtt::NOT_CONNECTED~; }
// Counts for monitoring and tests.
fn usz Core.inflight_count(&self) => (usz)self.inflight.len();
fn usz Core.queued_count(&self) => (usz)self.queue.len();
