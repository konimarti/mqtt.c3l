module mqtt::packet;
import mqtt, mqtt::props, mqtt::wire;

// Packet structs. Decoded strings and payloads borrow from the frame that was decoded; encoded
// packets borrow from the caller. The layout of these structs is fixed: later steps add codec
// functions, not fields.

struct Will
{
	String topic;
	char[] payload;
	QoS qos;
	bool retain;
	Properties props;               // v5 only: will delay, expiry, content type, ...
}

struct Connect
{
	String client_id;
	bool clean_start;               // 3.1.1: Clean Session flag
	ushort keep_alive;
	bool has_username;
	String username;
	bool has_password;
	char[] password;
	bool has_will;
	Will will;
	Properties props;
}

struct ConnAck
{
	bool session_present;
	char code;                      // 3.1.1: return code 0..5; 5.0: reason code
	Properties props;
}

struct Publish
{
	bool dup;
	QoS qos;
	bool retain;
	String topic;                   // may be empty in v5 when props.topic_alias is set
	ushort packet_id;               // only for qos > 0
	Properties props;
	char[] payload;
}

// PUBACK, PUBREC, PUBREL, PUBCOMP.
struct Ack
{
	ushort packet_id;
	char reason;                    // v5 only; a short form (length 2 or 3) means SUCCESS
	Properties props;
}

struct SubEntry
{
	String filter;
	QoS qos;
	bool no_local;                  // v5 option bits
	bool retain_as_published;
	char retain_handling;           // 0, 1, 2
}

struct Subscribe
{
	ushort packet_id;
	Properties props;
	SubEntry[] entries;             // encode
	char[] raw;                     // decode: walked with Subscribe.next
}

struct Unsubscribe
{
	ushort packet_id;
	Properties props;
	String[] filters;               // encode
	char[] raw;                     // decode
}

// SUBACK / UNSUBACK. codes holds one byte per filter (a 3.1.1 UNSUBACK has none).
struct SubAck
{
	ushort packet_id;
	Properties props;
	char[] codes;
}

struct Disconnect
{
	char reason;                    // v5 only
	Properties props;
}

struct Auth
{
	char reason;                    // 0x00, 0x18, 0x19
	Properties props;
}

struct Packet
{
	PacketType type;
	union
	{
		Connect connect;
		ConnAck connack;
		Publish publish;
		Ack ack;                    // PUBACK, PUBREC, PUBREL, PUBCOMP
		Subscribe subscribe;
		Unsubscribe unsubscribe;
		SubAck suback;              // SUBACK, UNSUBACK
		Disconnect disconnect;
		Auth auth;
	}                               // PINGREQ / PINGRESP carry nothing
}

const char[*] PROTOCOL_NAME = { 'M', 'Q', 'T', 'T' };

// ---- framing ----

// Stream framing [3.1.1 2.2]: 0 = need more bytes, otherwise the total frame length (fixed
// header + remaining length). The limit is checked on the fixed header alone, before any body
// byte is needed: PACKET_TOO_LARGE if the frame would exceed max_packet (0 = no limit).
// MALFORMED_PACKET for packet type 0, a bad remaining length (a fifth byte, a non-minimal form).
fn usz? frame_length(char[] input, usz max_packet)
{
	if (input.len == 0) return 0;
	if (input[0] >> 4 == 0) return mqtt::MALFORMED_PACKET~;
	usz used;
	uint? rl = wire::vbi_decode(input[1..], &used);
	if (catch err = rl)
	{
		if (err == mqtt::INCOMPLETE) return 0;
		return err~;
	}
	usz total = 1 + used + (usz)rl;
	if (max_packet != 0 && total > max_packet) return mqtt::PACKET_TOO_LARGE~;
	if (input.len < total) return 0;
	return total;
}

// ---- helpers ----

fn void? check_topic_name(String topic) @private
{
	if (topic.len == 0) return mqtt::INVALID_TOPIC_NAME~;
	foreach (c : topic)
	{
		if (c == '+' || c == '#') return mqtt::INVALID_TOPIC_NAME~;
	}
}

fn void? check_binary(char[] b) @private
{
	if (b.len > mqtt::MAX_STRING_LENGTH) return mqtt::INVALID_ARGUMENT~;
}

fn void? check_filter(String filter) @private
{
	wire::validate_utf8(filter)!;
	if (filter.len == 0) return mqtt::INVALID_TOPIC_FILTER~;
}

fn char qos_bits(QoS q) @private => (char)q.ordinal;

fn QoS? qos_from_bits(char bits) @private
{
	switch (bits)
	{
		case 0: return QoS.AT_MOST_ONCE;
		case 1: return QoS.AT_LEAST_ONCE;
		case 2: return QoS.EXACTLY_ONCE;
		default: return mqtt::MALFORMED_PACKET~;
	}
}

// ---- reason codes ----

// The reason codes the specification allows in each 5.0 packet [5.0 2.4 and the packet's reason
// code table]. One place: a peer that sends other codes is handled by changing this function.
fn bool reason_allowed(PacketType t, char code)
{
	switch (t)
	{
		case PacketType.CONNACK:
			switch (code)
			{
				case 0x00: case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86:
				case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8C: case 0x90: case 0x95: case 0x97:
				case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9F:
					return true;
				default:
					return false;
			}
		case PacketType.PUBACK:
		case PacketType.PUBREC:
			switch (code)
			{
				case 0x00: case 0x10: case 0x80: case 0x83: case 0x87: case 0x90: case 0x91: case 0x97: case 0x99:
					return true;
				default:
					return false;
			}
		case PacketType.PUBREL:
		case PacketType.PUBCOMP:
			return code == 0x00 || code == 0x92;
		case PacketType.SUBACK:
			switch (code)
			{
				case 0x00: case 0x01: case 0x02: case 0x80: case 0x83: case 0x87: case 0x8F: case 0x91:
				case 0x97: case 0x9E: case 0xA1: case 0xA2:
					return true;
				default:
					return false;
			}
		case PacketType.UNSUBACK:
			switch (code)
			{
				case 0x00: case 0x11: case 0x80: case 0x83: case 0x87: case 0x8F: case 0x91:
					return true;
				default:
					return false;
			}
		case PacketType.DISCONNECT:
			switch (code)
			{
				case 0x00: case 0x04: case 0x80: case 0x81: case 0x82: case 0x83: case 0x87: case 0x89:
				case 0x8B: case 0x8D: case 0x8E: case 0x8F: case 0x90: case 0x93: case 0x94: case 0x95:
				case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D:
				case 0x9E: case 0x9F: case 0xA0: case 0xA1: case 0xA2:
					return true;
				default:
					return false;
			}
		case PacketType.AUTH:
			return code == 0x00 || code == 0x18 || code == 0x19;
		default:
			return false;
	}
}

fn PropContext context_of(PacketType t) @private
{
	switch (t)
	{
		case PacketType.CONNECT: return PropContext.CONNECT;
		case PacketType.CONNACK: return PropContext.CONNACK;
		case PacketType.PUBLISH: return PropContext.PUBLISH;
		case PacketType.PUBACK: return PropContext.PUBACK;
		case PacketType.PUBREC: return PropContext.PUBREC;
		case PacketType.PUBREL: return PropContext.PUBREL;
		case PacketType.PUBCOMP: return PropContext.PUBCOMP;
		case PacketType.SUBSCRIBE: return PropContext.SUBSCRIBE;
		case PacketType.SUBACK: return PropContext.SUBACK;
		case PacketType.UNSUBSCRIBE: return PropContext.UNSUBSCRIBE;
		case PacketType.UNSUBACK: return PropContext.UNSUBACK;
		case PacketType.DISCONNECT: return PropContext.DISCONNECT;
		default: return PropContext.AUTH;
	}
}

// ---- decode ----

// Decodes one complete frame (exactly the bytes frame_length reported) of the given protocol
// version. Strings, payloads and properties borrow from `frame`. Type 15 (AUTH) exists only in 5.0
// and is PROTOCOL_ERROR in 3.1.1.
fn Packet? decode(Version v, char[] frame)
{
	usz n = frame_length(frame, 0)!;
	if (n == 0 || n != frame.len) return mqtt::MALFORMED_PACKET~;
	if (v != Version.V311 && v != Version.V5) return mqtt::UNSUPPORTED_VERSION~;
	usz used;
	wire::vbi_decode(frame[1..], &used)!;
	char first = frame[0];
	char[] body = frame[1 + used..];
	Packet? p = decode_body(v, first, body);
	if (catch err = p)
	{
		// a frame that is complete but too short for its own fields is malformed
		if (err == mqtt::INCOMPLETE) return mqtt::MALFORMED_PACKET~;
		return err~;
	}
	return p;
}

fn Packet? decode_body(Version v, char first, char[] body) @private
{
	char type = first >> 4;
	char flags = first & 0x0F;
	Packet p;
	switch (type)
	{
		case 1:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.CONNECT;
			p.connect = decode_connect(v, body)!;
		case 2:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.CONNACK;
			p.connack = decode_connack(v, body)!;
		case 3:
			p.type = PacketType.PUBLISH;
			p.publish = decode_publish(v, flags, body)!;
		case 4:
		case 5:
		case 7:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = (PacketType)type;
			p.ack = decode_ack(v, p.type, body)!;
		case 6:
			if (flags != 2) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.PUBREL;
			p.ack = decode_ack(v, p.type, body)!;
		case 8:
			if (flags != 2) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.SUBSCRIBE;
			p.subscribe = decode_subscribe(v, body)!;
		case 9:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.SUBACK;
			p.suback = decode_suback(v, PacketType.SUBACK, body)!;
		case 10:
			if (flags != 2) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.UNSUBSCRIBE;
			p.unsubscribe = decode_unsubscribe(v, body)!;
		case 11:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.UNSUBACK;
			p.suback = decode_suback(v, PacketType.UNSUBACK, body)!;
		case 12:
		case 13:
			if (flags != 0 || body.len != 0) return mqtt::MALFORMED_PACKET~;
			p.type = (PacketType)type;
		case 14:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.DISCONNECT;
			Ack d = decode_reason_and_props(v, PacketType.DISCONNECT, body)!;
			p.disconnect = { .reason = d.reason, .props = d.props };
		case 15:
			if (v == Version.V311) return mqtt::PROTOCOL_ERROR~;      // reserved in 3.1.1
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.AUTH;
			Ack a = decode_reason_and_props(v, PacketType.AUTH, body)!;
			p.auth = { .reason = a.reason, .props = a.props };
		default:
			return mqtt::MALFORMED_PACKET~;
	}
	return p;
}

fn Connect? decode_connect(Version v, char[] body) @private
{
	ByteReader r = wire::reader(body);
	String name = r.string()!;
	if (name.len != PROTOCOL_NAME.len) return mqtt::MALFORMED_PACKET~;
	foreach (i, c : name)
	{
		if (c != PROTOCOL_NAME[i]) return mqtt::MALFORMED_PACKET~;
	}
	char level = r.u8()!;
	if (level != (v == Version.V5 ? 5 : 4)) return mqtt::UNSUPPORTED_VERSION~;
	char flags = r.u8()!;
	if (flags & 0x01 != 0) return mqtt::MALFORMED_PACKET~;            // reserved bit
	bool has_will = flags & 0x04 != 0;
	char will_qos = (flags >> 3) & 3;
	bool will_retain = flags & 0x20 != 0;
	if (!has_will && (will_qos != 0 || will_retain)) return mqtt::MALFORMED_PACKET~;
	bool has_pass = flags & 0x40 != 0;
	bool has_user = flags & 0x80 != 0;
	if (v == Version.V311 && has_pass && !has_user) return mqtt::MALFORMED_PACKET~;

	Connect c;
	c.clean_start = flags & 0x02 != 0;
	c.keep_alive = r.u16()!;
	if (v == Version.V5) c.props = r.properties(PropContext.CONNECT)!;
	c.client_id = r.string()!;
	if (has_will)
	{
		c.has_will = true;
		c.will.qos = qos_from_bits(will_qos)!;
		c.will.retain = will_retain;
		if (v == Version.V5) c.will.props = r.properties(PropContext.WILL)!;
		c.will.topic = r.string()!;
		check_topic_name(c.will.topic)!;
		c.will.payload = r.binary()!;
	}
	if (has_user)
	{
		c.has_username = true;
		c.username = r.string()!;
	}
	if (has_pass)
	{
		c.has_password = true;
		c.password = r.binary()!;
	}
	if (r.remaining() != 0) return mqtt::MALFORMED_PACKET~;
	return c;
}

fn ConnAck? decode_connack(Version v, char[] body) @private
{
	if (v == Version.V311 && body.len != 2) return mqtt::MALFORMED_PACKET~;
	ByteReader r = wire::reader(body);
	char flags = r.u8()!;
	char code = r.u8()!;
	if (flags & 0xFE != 0) return mqtt::MALFORMED_PACKET~;
	bool sp = flags & 1 != 0;
	if (sp && code != 0) return mqtt::MALFORMED_PACKET~;
	ConnAck a = { .session_present = sp, .code = code };
	if (v == Version.V311)
	{
		if (code > 5) return mqtt::MALFORMED_PACKET~;
		return a;
	}
	if (!reason_allowed(PacketType.CONNACK, code)) return mqtt::MALFORMED_PACKET~;
	a.props = r.properties(PropContext.CONNACK)!;
	if (r.remaining() != 0) return mqtt::MALFORMED_PACKET~;
	return a;
}

fn Publish? decode_publish(Version v, char flags, char[] body) @private
{
	Publish p;
	p.dup = flags & 0x08 != 0;
	p.retain = flags & 0x01 != 0;
	p.qos = qos_from_bits((flags >> 1) & 3)!;
	if (p.dup && p.qos == QoS.AT_MOST_ONCE) return mqtt::MALFORMED_PACKET~;
	ByteReader r = wire::reader(body);
	p.topic = r.string()!;
	if (p.qos != QoS.AT_MOST_ONCE)
	{
		p.packet_id = r.u16()!;
		if (p.packet_id == 0) return mqtt::MALFORMED_PACKET~;
	}
	if (v == Version.V5) p.props = r.properties(PropContext.PUBLISH)!;
	if (p.topic.len == 0 && v == Version.V5)
	{
		// only a Topic Alias may stand in for the topic name
		if (!p.props.has(PropId.TOPIC_ALIAS)) return mqtt::PROTOCOL_ERROR~;
	}
	else
	{
		check_topic_name(p.topic)!;
	}
	p.payload = r.rest();
	return p;
}

// PUBACK, PUBREC, PUBREL, PUBCOMP, and the shape DISCONNECT and AUTH share: in 5.0 the reason
// code and the properties may be left out (length 2 / 3 / more).
fn Ack? decode_ack(Version v, PacketType t, char[] body) @private
{
	if (v == Version.V311)
	{
		if (body.len != 2) return mqtt::MALFORMED_PACKET~;
		ushort id = (ushort)body[0] << 8 | (ushort)body[1];
		if (id == 0) return mqtt::MALFORMED_PACKET~;
		return { .packet_id = id };
	}
	ByteReader r = wire::reader(body);
	Ack a;
	a.packet_id = r.u16()!;
	if (a.packet_id == 0) return mqtt::MALFORMED_PACKET~;
	if (r.remaining() == 0) return a;
	a.reason = r.u8()!;
	if (!reason_allowed(t, a.reason)) return mqtt::MALFORMED_PACKET~;
	if (r.remaining() > 0) a.props = r.properties(context_of(t))!;
	if (r.remaining() != 0) return mqtt::MALFORMED_PACKET~;
	return a;
}

// DISCONNECT (5.0): no body = reason 0; a reason alone; or reason and properties. 3.1.1: no body.
// AUTH has the same shape.
fn Ack? decode_reason_and_props(Version v, PacketType t, char[] body) @private
{
	Ack a;
	if (v == Version.V311)
	{
		if (body.len != 0) return mqtt::MALFORMED_PACKET~;
		return a;
	}
	ByteReader r = wire::reader(body);
	if (r.remaining() == 0) return a;
	a.reason = r.u8()!;
	if (!reason_allowed(t, a.reason)) return mqtt::MALFORMED_PACKET~;
	if (r.remaining() > 0) a.props = r.properties(context_of(t))!;
	if (r.remaining() != 0) return mqtt::MALFORMED_PACKET~;
	return a;
}

fn ushort? read_id(ByteReader* r) @private
{
	ushort id = r.u16()!;
	if (id == 0) return mqtt::MALFORMED_PACKET~;
	return id;
}

fn Subscribe? decode_subscribe(Version v, char[] body) @private
{
	ByteReader r = wire::reader(body);
	Subscribe s;
	s.packet_id = read_id(&r)!;
	if (v == Version.V5) s.props = r.properties(PropContext.SUBSCRIBE)!;
	s.raw = r.rest();
	if (s.raw.len == 0) return mqtt::MALFORMED_PACKET~;           // at least one filter
	// check every entry now so that Subscribe.next cannot fail later
	usz cursor;
	SubEntry entry;
	while (s.next(&cursor, v, &entry)!) {}
	return s;
}

// SUBACK and UNSUBACK: 3.1.1 SUBACK has return codes, 3.1.1 UNSUBACK only the id; 5.0 has properties
// and one reason code per filter for both.
fn SubAck? decode_suback(Version v, PacketType t, char[] body) @private
{
	ByteReader r = wire::reader(body);
	SubAck s;
	s.packet_id = read_id(&r)!;
	if (v == Version.V311 && t == PacketType.UNSUBACK)
	{
		if (r.remaining() != 0) return mqtt::MALFORMED_PACKET~;
		return s;
	}
	if (v == Version.V5) s.props = r.properties(context_of(t))!;
	s.codes = r.rest();
	if (s.codes.len == 0) return mqtt::MALFORMED_PACKET~;
	foreach (c : s.codes)
	{
		if (v == Version.V311)
		{
			if (c > 2 && c != mqtt::SUBACK_FAILURE_311) return mqtt::MALFORMED_PACKET~;
		}
		else if (!reason_allowed(t, c))
		{
			return mqtt::MALFORMED_PACKET~;
		}
	}
	return s;
}

fn Unsubscribe? decode_unsubscribe(Version v, char[] body) @private
{
	ByteReader r = wire::reader(body);
	Unsubscribe u;
	u.packet_id = read_id(&r)!;
	if (v == Version.V5) u.props = r.properties(PropContext.UNSUBSCRIBE)!;
	u.raw = r.rest();
	if (u.raw.len == 0) return mqtt::MALFORMED_PACKET~;
	usz cursor;
	String f;
	while (u.next(&cursor, &f)!) {}
	return u;
}

// Walks the filters of a decoded SUBSCRIBE. The option byte holds the requested QoS in bits 0-1;
// in 5.0 also No Local (bit 2), Retain As Published (bit 3) and Retain Handling (bits 4-5); the
// remaining bits must be zero. Returns false at the end. Faults: MALFORMED_PACKET, INVALID_UTF8,
// INVALID_TOPIC_FILTER (empty).
fn bool? Subscribe.next(&self, usz* cursor, Version v, SubEntry* out)
{
	if (*cursor >= self.raw.len) return false;
	ByteReader r = { .data = self.raw, .pos = *cursor };
	String filter = r.string()!;
	if (filter.len == 0) return mqtt::INVALID_TOPIC_FILTER~;
	char opt = r.u8()!;
	SubEntry e = { .filter = filter, .qos = qos_from_bits(opt & 3)! };
	if (v == Version.V311)
	{
		if (opt & 0xFC != 0) return mqtt::MALFORMED_PACKET~;
	}
	else
	{
		if (opt & 0xC0 != 0) return mqtt::MALFORMED_PACKET~;
		e.no_local = opt & 0x04 != 0;
		e.retain_as_published = opt & 0x08 != 0;
		e.retain_handling = (opt >> 4) & 3;
		if (e.retain_handling == 3) return mqtt::MALFORMED_PACKET~;
	}
	*out = e;
	*cursor = r.pos;
	return true;
}

// Walks the filters of a decoded UNSUBSCRIBE. Returns false at the end.
fn bool? Unsubscribe.next(&self, usz* cursor, String* out)
{
	if (*cursor >= self.raw.len) return false;
	ByteReader r = { .data = self.raw, .pos = *cursor };
	String filter = r.string()!;
	if (filter.len == 0) return mqtt::INVALID_TOPIC_FILTER~;
	*out = filter;
	*cursor = r.pos;
	return true;
}

// ---- encode ----

// Exact encoded size of the whole frame; validates the packet (topics, strings, flags, ids,
// reason codes, properties). INVALID_ARGUMENT for contents the protocol forbids,
// PACKET_TOO_LARGE above the 268_435_455 limit. A SUBSCRIBE / UNSUBSCRIBE without `entries` /
// `filters` is encoded from its `raw` body, so a decoded packet encodes back to the same bytes.
// Reason codes and properties are left out when they have their default values (the short forms).
fn usz? encoded_size(Version v, Packet* p)
{
	usz rl = body_size(v, p)!;
	if (rl > mqtt::MAX_REMAINING_LENGTH) return mqtt::PACKET_TOO_LARGE~;
	return 1 + wire::vbi_size((uint)rl) + rl;
}

// 5.0 acknowledgements, DISCONNECT and AUTH: how much of "reason code, properties" is needed.
// 0 = nothing, 1 = reason code, 2 = reason code and properties.
fn int short_form(char reason, usz props_size) @private
{
	if (props_size > 1) return 2;             // a property block longer than its length byte: keep it
	return reason == 0 ? 0 : 1;
}

fn usz? props_size(Version v, Properties* props, PropContext ctx) @private
{
	if (v != Version.V5) return 0;
	return props::properties_size(props, ctx);
}

fn usz? body_size(Version v, Packet* p) @private
{
	if (v != Version.V311 && v != Version.V5) return mqtt::UNSUPPORTED_VERSION~;
	bool v5 = v == Version.V5;
	switch (p.type)
	{
		case PacketType.CONNECT:
			Connect* c = &p.connect;
			wire::validate_utf8(c.client_id)!;
			if (!v5 && c.client_id.len == 0 && !c.clean_start) return mqtt::INVALID_ARGUMENT~;
			if (!v5 && c.has_password && !c.has_username) return mqtt::INVALID_ARGUMENT~;
			usz n = 10 + 2 + c.client_id.len;
			n += props_size(v, &c.props, PropContext.CONNECT)!;
			if (c.has_will)
			{
				check_topic_name(c.will.topic)!;
				wire::validate_utf8(c.will.topic)!;
				check_binary(c.will.payload)!;
				n += props_size(v, &c.will.props, PropContext.WILL)!;
				n += 2 + c.will.topic.len + 2 + c.will.payload.len;
			}
			if (c.has_username)
			{
				wire::validate_utf8(c.username)!;
				n += 2 + c.username.len;
			}
			if (c.has_password)
			{
				check_binary(c.password)!;
				n += 2 + c.password.len;
			}
			return n;
		case PacketType.CONNACK:
			ConnAck* a = &p.connack;
			if (a.session_present && a.code != 0) return mqtt::INVALID_ARGUMENT~;
			if (v5)
			{
				if (!reason_allowed(PacketType.CONNACK, a.code)) return mqtt::INVALID_ARGUMENT~;
			}
			else if (a.code > 5)
			{
				return mqtt::INVALID_ARGUMENT~;
			}
			return 2 + props_size(v, &a.props, PropContext.CONNACK)!;
		case PacketType.PUBLISH:
			Publish* u = &p.publish;
			if (v5 && u.topic.len == 0)
			{
				if (!u.props.has(PropId.TOPIC_ALIAS)) return mqtt::INVALID_TOPIC_NAME~;
			}
			else
			{
				check_topic_name(u.topic)!;
			}
			wire::validate_utf8(u.topic)!;
			if (u.dup && u.qos == QoS.AT_MOST_ONCE) return mqtt::INVALID_ARGUMENT~;
			usz n = 2 + u.topic.len + u.payload.len;
			if (u.qos != QoS.AT_MOST_ONCE)
			{
				if (u.packet_id == 0) return mqtt::INVALID_ARGUMENT~;
				n += 2;
			}
			return n + props_size(v, &u.props, PropContext.PUBLISH)!;
		case PacketType.PUBACK:
		case PacketType.PUBREC:
		case PacketType.PUBREL:
		case PacketType.PUBCOMP:
			Ack* k = &p.ack;
			if (k.packet_id == 0) return mqtt::INVALID_ARGUMENT~;
			if (!v5) return 2;
			if (!reason_allowed(p.type, k.reason)) return mqtt::INVALID_ARGUMENT~;
			PropContext ctx = context_of(p.type);
			usz psz = props::properties_size(&k.props, ctx)!;
			switch (short_form(k.reason, psz))
			{
				case 0: return 2;
				case 1: return 3;
				default: return 3 + psz;
			}
		case PacketType.SUBSCRIBE:
			Subscribe* s = &p.subscribe;
			if (s.packet_id == 0) return mqtt::INVALID_ARGUMENT~;
			usz n = 2 + props_size(v, &s.props, PropContext.SUBSCRIBE)!;
			if (s.entries.len == 0)
			{
				// a decoded packet: encode the entries it carries (already validated by decode)
				if (s.raw.len == 0) return mqtt::INVALID_ARGUMENT~;
				return n + s.raw.len;
			}
			foreach (e : s.entries)
			{
				check_filter(e.filter)!;
				if (v5)
				{
					if (e.retain_handling > 2) return mqtt::INVALID_ARGUMENT~;
				}
				else if (e.no_local || e.retain_as_published || e.retain_handling != 0)
				{
					return mqtt::INVALID_ARGUMENT~;
				}
				n += 2 + e.filter.len + 1;
			}
			return n;
		case PacketType.SUBACK:
		case PacketType.UNSUBACK:
			SubAck* a = &p.suback;
			if (a.packet_id == 0) return mqtt::INVALID_ARGUMENT~;
			if (!v5 && p.type == PacketType.UNSUBACK) return 2;
			if (a.codes.len == 0) return mqtt::INVALID_ARGUMENT~;
			foreach (c : a.codes)
			{
				if (v5)
				{
					if (!reason_allowed(p.type, c)) return mqtt::INVALID_ARGUMENT~;
				}
				else if (c > 2 && c != mqtt::SUBACK_FAILURE_311)
				{
					return mqtt::INVALID_ARGUMENT~;
				}
			}
			return 2 + a.codes.len + props_size(v, &a.props, context_of(p.type))!;
		case PacketType.UNSUBSCRIBE:
			Unsubscribe* u = &p.unsubscribe;
			if (u.packet_id == 0) return mqtt::INVALID_ARGUMENT~;
			usz n = 2 + props_size(v, &u.props, PropContext.UNSUBSCRIBE)!;
			if (u.filters.len == 0)
			{
				if (u.raw.len == 0) return mqtt::INVALID_ARGUMENT~;
				return n + u.raw.len;
			}
			foreach (f : u.filters)
			{
				check_filter(f)!;
				n += 2 + f.len;
			}
			return n;
		case PacketType.PINGREQ:
		case PacketType.PINGRESP:
			return 0;
		case PacketType.DISCONNECT:
			if (!v5) return 0;
			Disconnect* d = &p.disconnect;
			if (!reason_allowed(PacketType.DISCONNECT, d.reason)) return mqtt::INVALID_ARGUMENT~;
			usz psz = props::properties_size(&d.props, PropContext.DISCONNECT)!;
			switch (short_form(d.reason, psz))
			{
				case 0: return 0;
				case 1: return 1;
				default: return 1 + psz;
			}
		case PacketType.AUTH:
			if (!v5) return mqtt::INVALID_ARGUMENT~;       // AUTH does not exist in 3.1.1
			Auth* a = &p.auth;
			if (!reason_allowed(PacketType.AUTH, a.reason)) return mqtt::INVALID_ARGUMENT~;
			usz psz = props::properties_size(&a.props, PropContext.AUTH)!;
			switch (short_form(a.reason, psz))
			{
				case 0: return 0;
				case 1: return 1;
				default: return 1 + psz;
			}
		default:
			return mqtt::INVALID_ARGUMENT~;
	}
}

// Encodes p into out and returns the number of bytes written. BUFFER_TOO_SMALL (nothing written)
// if out is short; the faults of encoded_size for an invalid packet.
fn usz? encode(Version v, Packet* p, char[] out)
{
	usz rl = body_size(v, p)!;
	if (rl > mqtt::MAX_REMAINING_LENGTH) return mqtt::PACKET_TOO_LARGE~;
	usz total = 1 + wire::vbi_size((uint)rl) + rl;
	if (out.len < total) return mqtt::BUFFER_TOO_SMALL~;
	ByteWriter w = wire::writer(out[:total]);
	bool v5 = v == Version.V5;
	switch (p.type)
	{
		case PacketType.CONNECT:
			encode_connect(v, &w, &p.connect, rl)!;
		case PacketType.CONNACK:
			w.u8(0x20)!;
			w.vbi((uint)rl)!;
			w.u8(p.connack.session_present ? 1 : 0)!;
			w.u8(p.connack.code)!;
			if (v5) w.properties(&p.connack.props, PropContext.CONNACK)!;
		case PacketType.PUBLISH:
			encode_publish(v, &w, &p.publish, rl)!;
		case PacketType.PUBACK:
			encode_ack(v, &w, p.type, 0x40, &p.ack, rl)!;
		case PacketType.PUBREC:
			encode_ack(v, &w, p.type, 0x50, &p.ack, rl)!;
		case PacketType.PUBREL:
			encode_ack(v, &w, p.type, 0x62, &p.ack, rl)!;
		case PacketType.PUBCOMP:
			encode_ack(v, &w, p.type, 0x70, &p.ack, rl)!;
		case PacketType.SUBSCRIBE:
			w.u8(0x82)!;
			w.vbi((uint)rl)!;
			w.u16(p.subscribe.packet_id)!;
			if (v5) w.properties(&p.subscribe.props, PropContext.SUBSCRIBE)!;
			if (p.subscribe.entries.len == 0) w.raw(p.subscribe.raw)!;
			foreach (e : p.subscribe.entries)
			{
				w.string(e.filter)!;
				char opt = qos_bits(e.qos);
				if (v5)
				{
					if (e.no_local) opt |= 0x04;
					if (e.retain_as_published) opt |= 0x08;
					opt |= e.retain_handling << 4;
				}
				w.u8(opt)!;
			}
		case PacketType.SUBACK:
			w.u8(0x90)!;
			w.vbi((uint)rl)!;
			w.u16(p.suback.packet_id)!;
			if (v5) w.properties(&p.suback.props, PropContext.SUBACK)!;
			w.raw(p.suback.codes)!;
		case PacketType.UNSUBSCRIBE:
			w.u8(0xA2)!;
			w.vbi((uint)rl)!;
			w.u16(p.unsubscribe.packet_id)!;
			if (v5) w.properties(&p.unsubscribe.props, PropContext.UNSUBSCRIBE)!;
			if (p.unsubscribe.filters.len == 0) w.raw(p.unsubscribe.raw)!;
			foreach (f : p.unsubscribe.filters) w.string(f)!;
		case PacketType.UNSUBACK:
			if (v5)
			{
				w.u8(0xB0)!;
				w.vbi((uint)rl)!;
				w.u16(p.suback.packet_id)!;
				w.properties(&p.suback.props, PropContext.UNSUBACK)!;
				w.raw(p.suback.codes)!;
			}
			else
			{
				w.u8(0xB0)!;
				w.vbi(2)!;
				w.u16(p.suback.packet_id)!;
			}
		case PacketType.PINGREQ:
			w.u8(0xC0)!;
			w.vbi(0)!;
		case PacketType.PINGRESP:
			w.u8(0xD0)!;
			w.vbi(0)!;
		case PacketType.DISCONNECT:
			w.u8(0xE0)!;
			w.vbi((uint)rl)!;
			if (v5 && rl > 0)
			{
				w.u8(p.disconnect.reason)!;
				if (rl > 1) w.properties(&p.disconnect.props, PropContext.DISCONNECT)!;
			}
		case PacketType.AUTH:
			w.u8(0xF0)!;
			w.vbi((uint)rl)!;
			if (rl > 0)
			{
				w.u8(p.auth.reason)!;
				if (rl > 1) w.properties(&p.auth.props, PropContext.AUTH)!;
			}
		default:
			return mqtt::INVALID_ARGUMENT~;
	}
	return w.pos;
}

fn void? encode_connect(Version v, ByteWriter* w, Connect* c, usz rl) @private
{
	bool v5 = v == Version.V5;
	char flags;
	if (c.clean_start) flags |= 0x02;
	if (c.has_will)
	{
		flags |= 0x04;
		flags |= qos_bits(c.will.qos) << 3;
		if (c.will.retain) flags |= 0x20;
	}
	if (c.has_password) flags |= 0x40;
	if (c.has_username) flags |= 0x80;
	w.u8(0x10)!;
	w.vbi((uint)rl)!;
	w.string("MQTT")!;
	w.u8(v5 ? 5 : 4)!;
	w.u8(flags)!;
	w.u16(c.keep_alive)!;
	if (v5) w.properties(&c.props, PropContext.CONNECT)!;
	w.string(c.client_id)!;
	if (c.has_will)
	{
		if (v5) w.properties(&c.will.props, PropContext.WILL)!;
		w.string(c.will.topic)!;
		w.binary(c.will.payload)!;
	}
	if (c.has_username) w.string(c.username)!;
	if (c.has_password) w.binary(c.password)!;
}

fn void? encode_publish(Version v, ByteWriter* w, Publish* u, usz rl) @private
{
	char first = 0x30 | qos_bits(u.qos) << 1;
	if (u.dup) first |= 0x08;
	if (u.retain) first |= 0x01;
	w.u8(first)!;
	w.vbi((uint)rl)!;
	w.string(u.topic)!;
	if (u.qos != QoS.AT_MOST_ONCE) w.u16(u.packet_id)!;
	if (v == Version.V5) w.properties(&u.props, PropContext.PUBLISH)!;
	w.raw(u.payload)!;
}

// PUBACK, PUBREC, PUBREL, PUBCOMP. 5.0: the shortest form that carries the content.
fn void? encode_ack(Version v, ByteWriter* w, PacketType t, char first, Ack* a, usz rl) @private
{
	w.u8(first)!;
	if (v == Version.V311)
	{
		w.vbi(2)!;
		w.u16(a.packet_id)!;
		return;
	}
	// rl was computed when the packet was sized: 2 = id only, 3 = id and reason, more = with properties
	w.vbi((uint)rl)!;
	w.u16(a.packet_id)!;
	if (rl == 2) return;
	w.u8(a.reason)!;
	if (rl > 3) w.properties(&a.props, context_of(t))!;
}
