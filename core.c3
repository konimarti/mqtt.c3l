module mqtt::core;
import mqtt, mqtt::packet, mqtt::props;
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
	// always delivered after every event queued before it (DESIGN 4.12)
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
// input() that follows the event queue being drained (poll_event returned false); undelivered events are never invalidated (DESIGN section 7).
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
// time gets `now`, a monotonic `std::time::Duration` since an arbitrary origin that never goes back.
struct Core
{
	Allocator allocator;
	Config config;
	State state;
	// The fields below are private by convention (C3 has no field privacy).
	List{char} in_buf;              // reassembly + frames still referenced by undelivered events
	usz in_consumed;                // bytes of in_buf already framed
	List{char} out_buf;             // encoded bytes waiting for the transport
	List{EventRec} events;          // queued events, in arrival order
	List{Inflight} inflight;        // QoS 1/2 sent, not finished, in send order
	List{Inflight} queue;           // QoS 1/2 waiting for quota, FIFO
	List{PendingAck} pending;       // SUBSCRIBE / UNSUBSCRIBE awaiting ack
	List{ushort} in_qos2;           // inbound QoS 2 ids between PUBLISH and PUBREL
	List{AliasEntry} alias_in;      // server -> topic, owned copies
	List{AliasEntry} alias_out;     // topic -> alias, owned copies
	ushort next_id;
	Duration last_tx;
	Duration ping_sent;
	bool ping_outstanding;
	Duration closed_at;
	bool closed_seen;
	Limits limits;                  // negotiated by CONNACK
	String assigned_id;             // owned copy
}

enum InflightState : char { WAIT_PUBACK, WAIT_PUBREC, WAIT_PUBCOMP, QUEUED }

// One allocation holds topic | payload | encoded properties (without Topic Alias).
struct Inflight
{
	ushort id;
	InflightState state;
	QoS qos;
	bool retain;
	Duration queued_at;             // for Message Expiry Interval (DESIGN 4.13)
	uint expiry_s;                  // 0 = none
	char[] block;
	usz topic_len;
	usz payload_len;
}

enum PendingKind : char { SUBSCRIBE, UNSUBSCRIBE }
struct PendingAck { ushort id; PendingKind kind; usz count; }
struct AliasEntry { ushort alias_id; String topic; Duration last_used; }
struct EventRec { EventKind kind; usz frame_off; usz frame_len; Event* small; }
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
	ushort keep_alive;
}

// Config strings and the Will must outlive the Core (borrowed, not copied).
// Faults INVALID_ARGUMENT: empty client id with clean_start false on 3.1.1, 3.1.1 password without
// username, auth_method on 3.1.1, will topic invalid, max_in_buffer < max_packet_size.
fn void? Core.init(&self, Allocator allocator, Config* config) { return mqtt::INVALID_ARGUMENT~; }
// Frees all owned memory. Held session state (inflight, queue) is lost.
fn void Core.free(&self) {}

// Queues CONNECT. Legal in DISCONNECTED. Re-uses held session state when clean_start is false.
fn void? Core.connect(&self, Duration now) { return mqtt::ALREADY_CONNECTED~; }
// Bytes the core wants written to the transport, in order. Stable until output_done.
fn char[] Core.pending_output(&self) => {};
// Tell the core n bytes were written (n <= pending_output().len).
fn void Core.output_done(&self, usz n) {}
// Feed bytes read from the transport (any split, including mid-packet). Faults when the
// stream is unrecoverable (a DISCONNECT was queued where the spec allows); the caller then
// closes the transport and calls transport_closed.
fn void? Core.input(&self, Duration now, char[] data) { return mqtt::MALFORMED_PACKET~; }
// Next event, false when none. See Event for lifetime.
fn bool Core.poll_event(&self, Event* ev) => false;
// Earliest time at which timeout() must be called; false if no timer is armed.
fn bool Core.next_deadline(&self, Duration* deadline) => false;
// Runs due timers: queues PINGREQ, detects a missing PINGRESP (fault KEEPALIVE_TIMEOUT).
fn void? Core.timeout(&self, Duration now) { return mqtt::KEEPALIVE_TIMEOUT~; }
// The transport ended (EOF, error or after our DISCONNECT). Keeps the session state
// (unless clean_start / session expired) and emits CLOSED if not yet emitted.
fn void Core.transport_closed(&self, Duration now) {}

// Returns the packet id (0 for QoS 0; 0 is never a valid id, [5.0 2.2.1]).
// publish never touches in_buf, so it may be called while an Event is borrowed.
// Faults: NOT_CONNECTED, INVALID_TOPIC_NAME,
// NOT_SUPPORTED_BY_SERVER (QoS/retain above what CONNACK allowed), PACKET_TOO_LARGE,
// QUEUE_FULL. While the server's Receive Maximum is exhausted QoS>0 messages wait in the queue.
fn ushort? Core.publish(&self, Duration now, OutMessage* msg) { return mqtt::NOT_CONNECTED~; }
fn ushort? Core.subscribe(&self, Duration now, SubEntry[] entries, Properties* props) { return mqtt::NOT_CONNECTED~; }
fn ushort? Core.unsubscribe(&self, Duration now, String[] filters, Properties* props) { return mqtt::NOT_CONNECTED~; }
// Queues DISCONNECT. v3.1.1 ignores reason and props. reason DISCONNECT_WITH_WILL keeps the will.
fn void? Core.disconnect(&self, Duration now, ReasonCode reason, Properties* props) { return mqtt::NOT_CONNECTED~; }
// Manual AUTH (5.0 3.15): continue or re-authenticate (reason 0x19).
fn void? Core.send_auth(&self, Duration now, ReasonCode reason, char[] data) { return mqtt::NOT_CONNECTED~; }
// Counts for monitoring and tests.
fn usz Core.inflight_count(&self) => 0;
fn usz Core.queued_count(&self) => 0;
