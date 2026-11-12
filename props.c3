module mqtt::props;
import mqtt, mqtt::wire;

// 5.0 section 2.2.2.2 property identifiers.
constdef PropId : char
{
	PAYLOAD_FORMAT_INDICATOR = 0x01,
	MESSAGE_EXPIRY_INTERVAL = 0x02,
	CONTENT_TYPE = 0x03,
	RESPONSE_TOPIC = 0x08,
	CORRELATION_DATA = 0x09,
	SUBSCRIPTION_IDENTIFIER = 0x0B,
	SESSION_EXPIRY_INTERVAL = 0x11,
	ASSIGNED_CLIENT_IDENTIFIER = 0x12,
	SERVER_KEEP_ALIVE = 0x13,
	AUTHENTICATION_METHOD = 0x15,
	AUTHENTICATION_DATA = 0x16,
	REQUEST_PROBLEM_INFORMATION = 0x17,
	WILL_DELAY_INTERVAL = 0x18,
	REQUEST_RESPONSE_INFORMATION = 0x19,
	RESPONSE_INFORMATION = 0x1A,
	SERVER_REFERENCE = 0x1C,
	REASON_STRING = 0x1F,
	RECEIVE_MAXIMUM = 0x21,
	TOPIC_ALIAS_MAXIMUM = 0x22,
	TOPIC_ALIAS = 0x23,
	MAXIMUM_QOS = 0x24,
	RETAIN_AVAILABLE = 0x25,
	USER_PROPERTY = 0x26,
	MAXIMUM_PACKET_SIZE = 0x27,
	WILDCARD_SUBSCRIPTION_AVAILABLE = 0x28,
	SUBSCRIPTION_IDENTIFIER_AVAILABLE = 0x29,
	SHARED_SUBSCRIPTION_AVAILABLE = 0x2A,
}

// Which packet (or the Will block) a property list belongs to; decides which ids are legal
// (table in 5.0 section 2.2.2.2 and the per-packet sections).
enum PropContext : char
{
	CONNECT, CONNACK, PUBLISH, WILL, PUBACK, PUBREC, PUBREL, PUBCOMP,
	SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, DISCONNECT, AUTH,
}

struct UserProperty
{
	String key;
	String value;
}

// Decoded property list. Strings and binaries borrow from the packet bytes (decode) or from
// the caller (encode). A field counts only when its bit is set in `present`.
// Re-encoding a decoded struct works: encode uses `user` / `subscription_ids` when non-empty and
// otherwise falls back to `user_raw` / `subid_raw`.
struct Properties
{
	ulong present;                  // bit (1 << id) for ids below 64
	char payload_format;            // 0 = bytes, 1 = UTF-8
	uint message_expiry;
	String content_type;
	String response_topic;
	char[] correlation_data;
	uint session_expiry;
	String assigned_client_id;
	ushort server_keep_alive;
	String auth_method;
	char[] auth_data;
	char request_problem_info;
	uint will_delay;
	char request_response_info;
	String response_info;
	String server_reference;
	String reason_string;
	ushort receive_maximum;
	ushort topic_alias_maximum;
	ushort topic_alias;
	char maximum_qos;
	char retain_available;
	uint max_packet_size;
	char wildcard_sub_available;
	char subid_available;
	char shared_sub_available;
	// Decode: the whole property block (the bytes after its length prefix), set only when the block
	// holds user properties / subscription identifiers; walk with user_props() / subscription_id_iter().
	char[] user_raw;
	char[] subid_raw;
	// Encode: caller provided lists.
	UserProperty[] user;
	uint[] subscription_ids;
}

fn bool Properties.has(&self, PropId id) => (self.present >> (uint)(char)id) & 1 != 0;
fn void Properties.set(&self, PropId id) { self.present |= 1UL << (uint)(char)id; }

// All 27 property identifiers, in ascending order.
const PropId[*] ALL_PROP_IDS = {
	PropId.PAYLOAD_FORMAT_INDICATOR, PropId.MESSAGE_EXPIRY_INTERVAL, PropId.CONTENT_TYPE,
	PropId.RESPONSE_TOPIC, PropId.CORRELATION_DATA, PropId.SUBSCRIPTION_IDENTIFIER,
	PropId.SESSION_EXPIRY_INTERVAL, PropId.ASSIGNED_CLIENT_IDENTIFIER, PropId.SERVER_KEEP_ALIVE,
	PropId.AUTHENTICATION_METHOD, PropId.AUTHENTICATION_DATA, PropId.REQUEST_PROBLEM_INFORMATION,
	PropId.WILL_DELAY_INTERVAL, PropId.REQUEST_RESPONSE_INFORMATION, PropId.RESPONSE_INFORMATION,
	PropId.SERVER_REFERENCE, PropId.REASON_STRING, PropId.RECEIVE_MAXIMUM,
	PropId.TOPIC_ALIAS_MAXIMUM, PropId.TOPIC_ALIAS, PropId.MAXIMUM_QOS, PropId.RETAIN_AVAILABLE,
	PropId.USER_PROPERTY, PropId.MAXIMUM_PACKET_SIZE, PropId.WILDCARD_SUBSCRIPTION_AVAILABLE,
	PropId.SUBSCRIPTION_IDENTIFIER_AVAILABLE, PropId.SHARED_SUBSCRIPTION_AVAILABLE,
};

// How a property value is laid out on the wire [5.0 2.2.2.2].
enum PropKind : char
{
	UNKNOWN,
	BYTE,
	U16,
	U32,
	VBI,
	STRING,
	BINARY,
	PAIR,
}

fn PropKind kind_of(char id)
{
	switch (id)
	{
		case 0x01: case 0x17: case 0x19: case 0x24: case 0x25: case 0x28: case 0x29: case 0x2A:
			return PropKind.BYTE;
		case 0x13: case 0x21: case 0x22: case 0x23:
			return PropKind.U16;
		case 0x02: case 0x11: case 0x18: case 0x27:
			return PropKind.U32;
		case 0x0B:
			return PropKind.VBI;
		case 0x03: case 0x08: case 0x12: case 0x15: case 0x1A: case 0x1C: case 0x1F:
			return PropKind.STRING;
		case 0x09: case 0x16:
			return PropKind.BINARY;
		case 0x26:
			return PropKind.PAIR;
		default:
			return PropKind.UNKNOWN;
	}
}

// Which packets (and the Will block) may carry each property: [5.0 2.2.2.2] table, one bit per
// PropContext (bit = 1 << context.ordinal). **verify** against the spec text before release.
struct PropRule
{
	char id;
	uint contexts;
}

const uint C_CONNECT = 1 << 0;
const uint C_CONNACK = 1 << 1;
const uint C_PUBLISH = 1 << 2;
const uint C_WILL = 1 << 3;
const uint C_PUBACK = 1 << 4;
const uint C_PUBREC = 1 << 5;
const uint C_PUBREL = 1 << 6;
const uint C_PUBCOMP = 1 << 7;
const uint C_SUBSCRIBE = 1 << 8;
const uint C_SUBACK = 1 << 9;
const uint C_UNSUBSCRIBE = 1 << 10;
const uint C_UNSUBACK = 1 << 11;
const uint C_DISCONNECT = 1 << 12;
const uint C_AUTH = 1 << 13;
const uint C_ACKS = C_PUBACK | C_PUBREC | C_PUBREL | C_PUBCOMP;

const PropRule[*] RULES = {
	{ 0x01, C_PUBLISH | C_WILL },                                   // Payload Format Indicator
	{ 0x02, C_PUBLISH | C_WILL },                                   // Message Expiry Interval
	{ 0x03, C_PUBLISH | C_WILL },                                   // Content Type
	{ 0x08, C_PUBLISH | C_WILL },                                   // Response Topic
	{ 0x09, C_PUBLISH | C_WILL },                                   // Correlation Data
	{ 0x0B, C_PUBLISH | C_SUBSCRIBE },                              // Subscription Identifier
	{ 0x11, C_CONNECT | C_CONNACK | C_DISCONNECT },                 // Session Expiry Interval
	{ 0x12, C_CONNACK },                                            // Assigned Client Identifier
	{ 0x13, C_CONNACK },                                            // Server Keep Alive
	{ 0x15, C_CONNECT | C_CONNACK | C_AUTH },                       // Authentication Method
	{ 0x16, C_CONNECT | C_CONNACK | C_AUTH },                       // Authentication Data
	{ 0x17, C_CONNECT },                                            // Request Problem Information
	{ 0x18, C_WILL },                                               // Will Delay Interval
	{ 0x19, C_CONNECT },                                            // Request Response Information
	{ 0x1A, C_CONNACK },                                            // Response Information
	{ 0x1C, C_CONNACK | C_DISCONNECT },                             // Server Reference
	{ 0x1F, C_CONNACK | C_ACKS | C_SUBACK | C_UNSUBACK | C_DISCONNECT | C_AUTH },   // Reason String
	{ 0x21, C_CONNECT | C_CONNACK },                                // Receive Maximum
	{ 0x22, C_CONNECT | C_CONNACK },                                // Topic Alias Maximum
	{ 0x23, C_PUBLISH },                                            // Topic Alias
	{ 0x24, C_CONNACK },                                            // Maximum QoS
	{ 0x25, C_CONNACK },                                            // Retain Available
	{ 0x26, 0x3FFF },                                               // User Property: every context
	{ 0x27, C_CONNECT | C_CONNACK },                                // Maximum Packet Size
	{ 0x28, C_CONNACK },                                            // Wildcard Subscription Available
	{ 0x29, C_CONNACK },                                            // Subscription Identifier Available
	{ 0x2A, C_CONNACK },                                            // Shared Subscription Available
};

// True if property id may appear in ctx.
fn bool allowed(PropContext ctx, PropId id)
{
	foreach (r : RULES)
	{
		if (r.id == (char)id) return r.contexts & (1U << ctx.ordinal) != 0;
	}
	return false;
}

// ---- value rules shared by decode and encode ----

// Byte-valued properties that are flags: only 0 and 1 are legal. Maximum QoS likewise (a server
// never sends 2). Returns true if the value is acceptable.
fn bool byte_value_ok(char id, char v) @private
{
	switch (id)
	{
		case 0x01: case 0x17: case 0x19: case 0x24: case 0x25: case 0x28: case 0x29: case 0x2A:
			return v <= 1;
		default:
			return true;
	}
}

// Values that must not be zero: Subscription Identifier, Receive Maximum, Topic Alias, Maximum Packet Size.
fn bool nonzero_ok(char id, uint v) @private
{
	switch (id)
	{
		case 0x0B: case 0x21: case 0x23: case 0x27:
			return v != 0;
		default:
			return true;
	}
}

// ---- decode ----

// Skips one value of the property `id` (used when walking a block for one kind of property).
// Skips one value of the property `id` (its identifier was read already).
fn void? skip_value(ByteReader* r, char id)
{
	switch (kind_of(id))
	{
		case PropKind.BYTE: r.u8()!;
		case PropKind.U16: r.u16()!;
		case PropKind.U32: r.u32()!;
		case PropKind.VBI: r.vbi()!;
		case PropKind.STRING: r.string()!;
		case PropKind.BINARY: r.binary()!;
		case PropKind.PAIR:
			r.string()!;
			r.string()!;
		default:
			return mqtt::MALFORMED_PACKET~;
	}
}

// Reads the property length (a Variable Byte Integer) and the properties after it, for a packet
// of kind ctx. The reader always works on a complete frame, so every overrun is MALFORMED_PACKET.
// Faults: MALFORMED_PACKET (bad length, overrun, unknown id), INVALID_UTF8, INVALID_PROPERTY
// (not allowed in ctx, duplicate of a single-use property, a zero or out-of-range value).
// A duplicate is detected at the second occurrence, so the work is linear in the block size.
fn Properties? ByteReader.properties(&self, PropContext ctx)
{
	uint? len = self.vbi();
	if (catch err = len)
	{
		return mqtt::MALFORMED_PACKET~;
	}
	if (len > self.remaining()) return mqtt::MALFORMED_PACKET~;
	char[] block = self.take(len)!;
	ByteReader r = wire::reader(block);
	Properties p;
	while (r.remaining() > 0)
	{
		char id = r.u8()!;
		if (kind_of(id) == PropKind.UNKNOWN) return mqtt::MALFORMED_PACKET~;
		PropId pid = (PropId)id;
		if (!allowed(ctx, pid)) return mqtt::INVALID_PROPERTY~;
		bool repeatable = id == 0x26 || (id == 0x0B && ctx == PropContext.PUBLISH);
		if (p.has(pid) && !repeatable) return mqtt::INVALID_PROPERTY~;
		if (catch err = read_value(&r, &p, id))
		{
			// a value that runs past the end of the block
			if (err == mqtt::INCOMPLETE) return mqtt::MALFORMED_PACKET~;
			return err~;
		}
		p.set(pid);
		if (id == 0x26) p.user_raw = block;
		if (id == 0x0B) p.subid_raw = block;
	}
	return p;
}

fn void? read_value(ByteReader* r, Properties* p, char id) @private
{
	switch (kind_of(id))
	{
		case PropKind.BYTE:
			char v = r.u8()!;
			if (!byte_value_ok(id, v)) return mqtt::INVALID_PROPERTY~;
			switch (id)
			{
				case 0x01: p.payload_format = v;
				case 0x17: p.request_problem_info = v;
				case 0x19: p.request_response_info = v;
				case 0x24: p.maximum_qos = v;
				case 0x25: p.retain_available = v;
				case 0x28: p.wildcard_sub_available = v;
				case 0x29: p.subid_available = v;
				default: p.shared_sub_available = v;
			}
		case PropKind.U16:
			ushort v = r.u16()!;
			if (!nonzero_ok(id, v)) return mqtt::INVALID_PROPERTY~;
			switch (id)
			{
				case 0x13: p.server_keep_alive = v;
				case 0x21: p.receive_maximum = v;
				case 0x22: p.topic_alias_maximum = v;
				default: p.topic_alias = v;
			}
		case PropKind.U32:
			uint v = r.u32()!;
			if (!nonzero_ok(id, v)) return mqtt::INVALID_PROPERTY~;
			switch (id)
			{
				case 0x02: p.message_expiry = v;
				case 0x11: p.session_expiry = v;
				case 0x18: p.will_delay = v;
				default: p.max_packet_size = v;
			}
		case PropKind.VBI:
			uint v = r.vbi()!;
			if (!nonzero_ok(id, v)) return mqtt::INVALID_PROPERTY~;   // value kept in the raw block
		case PropKind.STRING:
			String v = r.string()!;
			switch (id)
			{
				case 0x03: p.content_type = v;
				case 0x08: p.response_topic = v;
				case 0x12: p.assigned_client_id = v;
				case 0x15: p.auth_method = v;
				case 0x1A: p.response_info = v;
				case 0x1C: p.server_reference = v;
				default: p.reason_string = v;
			}
		case PropKind.BINARY:
			char[] v = r.binary()!;
			if (id == 0x09)
			{
				p.correlation_data = v;
			}
			else
			{
				p.auth_data = v;
			}
		case PropKind.PAIR:
			r.string()!;     // kept in the raw block, see user_props()
			r.string()!;
		default:
			return mqtt::MALFORMED_PACKET~;
	}
}

// Iterates the user properties of a decoded block (in order).
struct UserPropIter
{
	ByteReader r;
}

fn UserPropIter Properties.user_props(&self) => { wire::reader(self.user_raw) };

// false at the end; a fault only if the bytes were damaged after decode.
fn bool? UserPropIter.next(&self, UserProperty* out)
{
	while (self.r.remaining() > 0)
	{
		char id = self.r.u8()!;
		if (id == 0x26)
		{
			out.key = self.r.string()!;
			out.value = self.r.string()!;
			return true;
		}
		skip_value(&self.r, id)!;
	}
	return false;
}

// Iterates the Subscription Identifiers of a decoded PUBLISH / SUBSCRIBE block (in order).
struct SubIdIter
{
	ByteReader r;
}

fn SubIdIter Properties.subscription_id_iter(&self) => { wire::reader(self.subid_raw) };

fn bool? SubIdIter.next(&self, uint* out)
{
	while (self.r.remaining() > 0)
	{
		char id = self.r.u8()!;
		if (id == 0x0B)
		{
			*out = self.r.vbi()!;
			return true;
		}
		skip_value(&self.r, id)!;
	}
	return false;
}

// ---- encode ----

// Counts or writes: one code path for properties_size and ByteWriter.properties.
struct Emit @private
{
	ByteWriter* w;       // null = only count
	usz n;
}

fn void? Emit.u8(&self, char v)
{
	self.n += 1;
	if (self.w) self.w.u8(v)!;
}

fn void? Emit.u16(&self, ushort v)
{
	self.n += 2;
	if (self.w) self.w.u16(v)!;
}

fn void? Emit.u32(&self, uint v)
{
	self.n += 4;
	if (self.w) self.w.u32(v)!;
}

fn void? Emit.vbi(&self, uint v)
{
	usz size = wire::vbi_size(v);
	if (size == 0) return mqtt::INVALID_PROPERTY~;
	self.n += size;
	if (self.w) self.w.vbi(v)!;
}

fn void? Emit.string(&self, String s)
{
	wire::validate_utf8(s)!;
	self.n += 2 + s.len;
	if (self.w) self.w.string(s)!;
}

fn void? Emit.binary(&self, char[] b)
{
	if (b.len > mqtt::MAX_STRING_LENGTH) return mqtt::INVALID_PROPERTY~;
	self.n += 2 + b.len;
	if (self.w) self.w.binary(b)!;
}

fn void? Emit.head(&self, PropContext ctx, PropId id)
{
	if (!allowed(ctx, id)) return mqtt::INVALID_PROPERTY~;
	return self.u8((char)id);
}

fn void? Emit.byte_prop(&self, Properties* p, PropContext ctx, PropId id, char v)
{
	if (!p.has(id)) return;
	if (!byte_value_ok((char)id, v)) return mqtt::INVALID_PROPERTY~;
	self.head(ctx, id)!;
	self.u8(v)!;
}

fn void? Emit.u16_prop(&self, Properties* p, PropContext ctx, PropId id, ushort v)
{
	if (!p.has(id)) return;
	if (!nonzero_ok((char)id, v)) return mqtt::INVALID_PROPERTY~;
	self.head(ctx, id)!;
	self.u16(v)!;
}

fn void? Emit.u32_prop(&self, Properties* p, PropContext ctx, PropId id, uint v)
{
	if (!p.has(id)) return;
	if (!nonzero_ok((char)id, v)) return mqtt::INVALID_PROPERTY~;
	self.head(ctx, id)!;
	self.u32(v)!;
}

fn void? Emit.string_prop(&self, Properties* p, PropContext ctx, PropId id, String v)
{
	if (!p.has(id)) return;
	self.head(ctx, id)!;
	self.string(v)!;
}

fn void? Emit.binary_prop(&self, Properties* p, PropContext ctx, PropId id, char[] v)
{
	if (!p.has(id)) return;
	self.head(ctx, id)!;
	self.binary(v)!;
}

// Subscription identifiers: from `subscription_ids` if given, else from the raw block of a decoded struct.
fn void? Emit.subids(&self, Properties* p, PropContext ctx)
{
	if (p.subscription_ids.len > 0)
	{
		// a SUBSCRIBE carries at most one Subscription Identifier
		if (ctx == PropContext.SUBSCRIBE && p.subscription_ids.len > 1) return mqtt::INVALID_PROPERTY~;
		foreach (v : p.subscription_ids)
		{
			if (v == 0) return mqtt::INVALID_PROPERTY~;
			self.head(ctx, PropId.SUBSCRIPTION_IDENTIFIER)!;
			self.vbi(v)!;
		}
		return;
	}
	if (p.subid_raw.len == 0) return;
	SubIdIter it = p.subscription_id_iter();
	uint v;
	while (it.next(&v)!)
	{
		self.head(ctx, PropId.SUBSCRIPTION_IDENTIFIER)!;
		self.vbi(v)!;
	}
}

fn void? Emit.users(&self, Properties* p, PropContext ctx)
{
	if (p.user.len > 0)
	{
		foreach (u : p.user)
		{
			self.head(ctx, PropId.USER_PROPERTY)!;
			self.string(u.key)!;
			self.string(u.value)!;
		}
		return;
	}
	if (p.user_raw.len == 0) return;
	UserPropIter it = p.user_props();
	UserProperty u;
	while (it.next(&u)!)
	{
		self.head(ctx, PropId.USER_PROPERTY)!;
		self.string(u.key)!;
		self.string(u.value)!;
	}
}

// Properties in ascending identifier order, without the length prefix.
fn void? emit_body(Emit* e, Properties* p, PropContext ctx) @private
{
	e.byte_prop(p, ctx, PropId.PAYLOAD_FORMAT_INDICATOR, p.payload_format)!;
	e.u32_prop(p, ctx, PropId.MESSAGE_EXPIRY_INTERVAL, p.message_expiry)!;
	e.string_prop(p, ctx, PropId.CONTENT_TYPE, p.content_type)!;
	e.string_prop(p, ctx, PropId.RESPONSE_TOPIC, p.response_topic)!;
	e.binary_prop(p, ctx, PropId.CORRELATION_DATA, p.correlation_data)!;
	e.subids(p, ctx)!;
	e.u32_prop(p, ctx, PropId.SESSION_EXPIRY_INTERVAL, p.session_expiry)!;
	e.string_prop(p, ctx, PropId.ASSIGNED_CLIENT_IDENTIFIER, p.assigned_client_id)!;
	e.u16_prop(p, ctx, PropId.SERVER_KEEP_ALIVE, p.server_keep_alive)!;
	e.string_prop(p, ctx, PropId.AUTHENTICATION_METHOD, p.auth_method)!;
	e.binary_prop(p, ctx, PropId.AUTHENTICATION_DATA, p.auth_data)!;
	e.byte_prop(p, ctx, PropId.REQUEST_PROBLEM_INFORMATION, p.request_problem_info)!;
	e.u32_prop(p, ctx, PropId.WILL_DELAY_INTERVAL, p.will_delay)!;
	e.byte_prop(p, ctx, PropId.REQUEST_RESPONSE_INFORMATION, p.request_response_info)!;
	e.string_prop(p, ctx, PropId.RESPONSE_INFORMATION, p.response_info)!;
	e.string_prop(p, ctx, PropId.SERVER_REFERENCE, p.server_reference)!;
	e.string_prop(p, ctx, PropId.REASON_STRING, p.reason_string)!;
	e.u16_prop(p, ctx, PropId.RECEIVE_MAXIMUM, p.receive_maximum)!;
	e.u16_prop(p, ctx, PropId.TOPIC_ALIAS_MAXIMUM, p.topic_alias_maximum)!;
	e.u16_prop(p, ctx, PropId.TOPIC_ALIAS, p.topic_alias)!;
	e.byte_prop(p, ctx, PropId.MAXIMUM_QOS, p.maximum_qos)!;
	e.byte_prop(p, ctx, PropId.RETAIN_AVAILABLE, p.retain_available)!;
	e.users(p, ctx)!;
	e.u32_prop(p, ctx, PropId.MAXIMUM_PACKET_SIZE, p.max_packet_size)!;
	e.byte_prop(p, ctx, PropId.WILDCARD_SUBSCRIPTION_AVAILABLE, p.wildcard_sub_available)!;
	e.byte_prop(p, ctx, PropId.SUBSCRIPTION_IDENTIFIER_AVAILABLE, p.subid_available)!;
	e.byte_prop(p, ctx, PropId.SHARED_SUBSCRIPTION_AVAILABLE, p.shared_sub_available)!;
}

// Length of the properties alone, without the length prefix. Validates like encode.
fn usz? properties_body_size(Properties* p, PropContext ctx) @private
{
	Emit e = {};
	emit_body(&e, p, ctx)!;
	return e.n;
}

// Size in bytes of the block including its length prefix. Validates the properties like encode:
// INVALID_PROPERTY (not allowed in ctx, zero/out-of-range value), INVALID_UTF8,
// PACKET_TOO_LARGE (block above 268_435_455 bytes).
fn usz? properties_size(Properties* p, PropContext ctx)
{
	usz body = properties_body_size(p, ctx)!;
	usz prefix = wire::vbi_size((uint)body);
	if (body > mqtt::MAX_REMAINING_LENGTH || prefix == 0) return mqtt::PACKET_TOO_LARGE~;
	return prefix + body;
}

// Writes the length prefix and the properties, in ascending identifier order. The properties are
// validated and sized once. Nothing is written on a fault (BUFFER_TOO_SMALL included).
fn void? ByteWriter.properties(&self, Properties* p, PropContext ctx)
{
	usz body = properties_body_size(p, ctx)!;
	usz prefix = wire::vbi_size((uint)body);
	if (body > mqtt::MAX_REMAINING_LENGTH || prefix == 0) return mqtt::PACKET_TOO_LARGE~;
	if (self.remaining() < prefix + body) return mqtt::BUFFER_TOO_SMALL~;
	self.vbi((uint)body)!;
	Emit e = { .w = self };
	emit_body(&e, p, ctx)!;
}
