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

fn bool is_ack_type(PacketType t) @private
{
	return t == PacketType.PUBACK || t == PacketType.PUBREC || t == PacketType.PUBREL || t == PacketType.PUBCOMP;
}

// ---- decode ----

// Decodes one complete frame (exactly the bytes frame_length reported). Strings and payloads
// borrow from `frame`. Only 3.1.1 is implemented in this step; 5.0 comes with the property codec.
fn Packet? decode(Version v, char[] frame)
{
	usz n = frame_length(frame, 0)!;
	if (n == 0 || n != frame.len) return mqtt::MALFORMED_PACKET~;
	if (v != Version.V311) return mqtt::UNSUPPORTED_VERSION~;
	usz used;
	wire::vbi_decode(frame[1..], &used)!;
	char first = frame[0];
	char[] body = frame[1 + used..];
	Packet? p = decode311(first, body);
	if (catch err = p)
	{
		// a frame that is complete but too short for its own fields is malformed
		if (err == mqtt::INCOMPLETE) return mqtt::MALFORMED_PACKET~;
		return err~;
	}
	return p;
}

fn Packet? decode311(char first, char[] body) @private
{
	char type = first >> 4;
	char flags = first & 0x0F;
	Packet p;
	switch (type)
	{
		case 1:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.CONNECT;
			p.connect = decode_connect(body)!;
		case 2:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.CONNACK;
			p.connack = decode_connack(body)!;
		case 3:
			p.type = PacketType.PUBLISH;
			p.publish = decode_publish(flags, body)!;
		case 4:
		case 5:
		case 7:
			if (flags != 0) return mqtt::MALFORMED_PACKET~;
			p.type = (PacketType)type;
			p.ack = decode_ack(body)!;
		case 6:
			if (flags != 2) return mqtt::MALFORMED_PACKET~;
			p.type = PacketType.PUBREL;
			p.ack = decode_ack(body)!;
		case 15:
			return mqtt::PROTOCOL_ERROR~;   // reserved in 3.1.1
		default:
			return mqtt::INVALID_ARGUMENT~; // packet types handled by the next codec step
	}
	return p;
}

fn Connect? decode_connect(char[] body) @private
{
	ByteReader r = wire::reader(body);
	String name = r.string()!;
	if (name.len != PROTOCOL_NAME.len) return mqtt::MALFORMED_PACKET~;
	foreach (i, c : name)
	{
		if (c != PROTOCOL_NAME[i]) return mqtt::MALFORMED_PACKET~;
	}
	char level = r.u8()!;
	if (level != 4) return mqtt::UNSUPPORTED_VERSION~;
	char flags = r.u8()!;
	if (flags & 0x01 != 0) return mqtt::MALFORMED_PACKET~;            // reserved bit
	bool has_will = flags & 0x04 != 0;
	char will_qos = (flags >> 3) & 3;
	bool will_retain = flags & 0x20 != 0;
	if (!has_will && (will_qos != 0 || will_retain)) return mqtt::MALFORMED_PACKET~;
	bool has_pass = flags & 0x40 != 0;
	bool has_user = flags & 0x80 != 0;
	if (has_pass && !has_user) return mqtt::MALFORMED_PACKET~;        // 3.1.1 only

	Connect c;
	c.clean_start = flags & 0x02 != 0;
	c.keep_alive = r.u16()!;
	c.client_id = r.string()!;
	if (has_will)
	{
		c.has_will = true;
		c.will.qos = qos_from_bits(will_qos)!;
		c.will.retain = will_retain;
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

fn ConnAck? decode_connack(char[] body) @private
{
	if (body.len != 2) return mqtt::MALFORMED_PACKET~;
	char flags = body[0];
	char code = body[1];
	if (flags & 0xFE != 0) return mqtt::MALFORMED_PACKET~;
	if (code > 5) return mqtt::MALFORMED_PACKET~;
	bool sp = flags & 1 != 0;
	if (sp && code != 0) return mqtt::MALFORMED_PACKET~;
	return { .session_present = sp, .code = code };
}

fn Publish? decode_publish(char flags, char[] body) @private
{
	Publish p;
	p.dup = flags & 0x08 != 0;
	p.retain = flags & 0x01 != 0;
	p.qos = qos_from_bits((flags >> 1) & 3)!;
	if (p.dup && p.qos == QoS.AT_MOST_ONCE) return mqtt::MALFORMED_PACKET~;
	ByteReader r = wire::reader(body);
	p.topic = r.string()!;
	check_topic_name(p.topic)!;
	if (p.qos != QoS.AT_MOST_ONCE)
	{
		p.packet_id = r.u16()!;
		if (p.packet_id == 0) return mqtt::MALFORMED_PACKET~;
	}
	p.payload = r.rest();
	return p;
}

fn Ack? decode_ack(char[] body) @private
{
	if (body.len != 2) return mqtt::MALFORMED_PACKET~;
	ushort id = (ushort)body[0] << 8 | (ushort)body[1];
	if (id == 0) return mqtt::MALFORMED_PACKET~;
	return { .packet_id = id };
}

// ---- encode ----

// Exact encoded size of the whole frame; validates the packet (topics, strings, flags, ids).
// INVALID_ARGUMENT for contents the protocol forbids, PACKET_TOO_LARGE above the 268_435_455 limit.
fn usz? encoded_size(Version v, Packet* p)
{
	usz rl = body_size(v, p)!;
	if (rl > mqtt::MAX_REMAINING_LENGTH) return mqtt::PACKET_TOO_LARGE~;
	return 1 + wire::vbi_size((uint)rl) + rl;
}

fn usz? body_size(Version v, Packet* p) @private
{
	if (v != Version.V311) return mqtt::UNSUPPORTED_VERSION~;
	switch (p.type)
	{
		case PacketType.CONNECT:
			Connect* c = &p.connect;
			wire::validate_utf8(c.client_id)!;
			if (c.client_id.len == 0 && !c.clean_start) return mqtt::INVALID_ARGUMENT~;
			if (c.has_password && !c.has_username) return mqtt::INVALID_ARGUMENT~;
			usz n = 10 + 2 + c.client_id.len;
			if (c.has_will)
			{
				check_topic_name(c.will.topic)!;
				wire::validate_utf8(c.will.topic)!;
				check_binary(c.will.payload)!;
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
			if (a.code > 5) return mqtt::INVALID_ARGUMENT~;
			if (a.session_present && a.code != 0) return mqtt::INVALID_ARGUMENT~;
			return 2;
		case PacketType.PUBLISH:
			Publish* u = &p.publish;
			check_topic_name(u.topic)!;
			wire::validate_utf8(u.topic)!;
			if (u.dup && u.qos == QoS.AT_MOST_ONCE) return mqtt::INVALID_ARGUMENT~;
			usz n = 2 + u.topic.len + u.payload.len;
			if (u.qos != QoS.AT_MOST_ONCE)
			{
				if (u.packet_id == 0) return mqtt::INVALID_ARGUMENT~;
				n += 2;
			}
			return n;
		case PacketType.PUBACK:
		case PacketType.PUBREC:
		case PacketType.PUBREL:
		case PacketType.PUBCOMP:
			if (p.ack.packet_id == 0) return mqtt::INVALID_ARGUMENT~;
			return 2;
		default:
			return mqtt::INVALID_ARGUMENT~;   // packet types handled by the next codec step
	}
}

// Encodes p into out and returns the number of bytes written. BUFFER_TOO_SMALL (nothing written)
// if out is short; the faults of encoded_size for an invalid packet.
fn usz? encode(Version v, Packet* p, char[] out)
{
	usz rl = body_size(v, p)!;
	usz total = encoded_size(v, p)!;
	if (out.len < total) return mqtt::BUFFER_TOO_SMALL~;
	ByteWriter w = wire::writer(out[:total]);
	switch (p.type)
	{
		case PacketType.CONNECT:
			encode_connect(&w, &p.connect, rl)!;
		case PacketType.CONNACK:
			w.u8(0x20)!;
			w.vbi((uint)rl)!;
			w.u8(p.connack.session_present ? 1 : 0)!;
			w.u8(p.connack.code)!;
		case PacketType.PUBLISH:
			encode_publish(&w, &p.publish, rl)!;
		case PacketType.PUBACK:
			encode_ack(&w, 0x40, p.ack.packet_id)!;
		case PacketType.PUBREC:
			encode_ack(&w, 0x50, p.ack.packet_id)!;
		case PacketType.PUBREL:
			encode_ack(&w, 0x62, p.ack.packet_id)!;
		case PacketType.PUBCOMP:
			encode_ack(&w, 0x70, p.ack.packet_id)!;
		default:
			return mqtt::INVALID_ARGUMENT~;
	}
	return w.pos;
}

fn void? encode_connect(ByteWriter* w, Connect* c, usz rl) @private
{
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
	w.u8(4)!;
	w.u8(flags)!;
	w.u16(c.keep_alive)!;
	w.string(c.client_id)!;
	if (c.has_will)
	{
		w.string(c.will.topic)!;
		w.binary(c.will.payload)!;
	}
	if (c.has_username) w.string(c.username)!;
	if (c.has_password) w.binary(c.password)!;
}

fn void? encode_publish(ByteWriter* w, Publish* u, usz rl) @private
{
	char first = 0x30 | qos_bits(u.qos) << 1;
	if (u.dup) first |= 0x08;
	if (u.retain) first |= 0x01;
	w.u8(first)!;
	w.vbi((uint)rl)!;
	w.string(u.topic)!;
	if (u.qos != QoS.AT_MOST_ONCE) w.u16(u.packet_id)!;
	w.raw(u.payload)!;
}

fn void? encode_ack(ByteWriter* w, char first, ushort id) @private
{
	w.u8(first)!;
	w.vbi(2)!;
	w.u16(id)!;
}
