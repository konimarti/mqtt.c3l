module mqtt;

// Naming convention: the FAULTS below are the library's error values and are always written
// `mqtt::NAME` (or returned from a `T?` function). The wire reason codes are `ReasonCode.NAME`.
// Three names exist in both (MALFORMED_PACKET, PROTOCOL_ERROR, PACKET_TOO_LARGE): the fault says
// "this call failed", the ReasonCode is the byte on the wire (0x81, 0x82, 0x95). The qualification
// always tells them apart; c3_refs rename_to works per namespace.

// Library faults. Parse and protocol faults are returned by the codec and the session core;
// CLOSED and TIMEOUT come from transports.
faultdef
	MALFORMED_PACKET,       // bytes do not parse (MQTT-5.0 4.13, 3.1.1 4.8)
	PROTOCOL_ERROR,         // well-formed but not allowed in this state
	PACKET_TOO_LARGE,       // exceeds a Maximum Packet Size (either side)
	BUFFER_TOO_SMALL,       // caller supplied output buffer is too small
	INCOMPLETE,             // reader ran out of bytes inside a frame
	INVALID_UTF8,           // string not well-formed UTF-8 or has U+0000 (3.1.1 1.5.3, 5.0 1.5.4)
	INVALID_TOPIC_NAME,
	INVALID_TOPIC_FILTER,
	INVALID_PROPERTY,       // unknown id, duplicate, or not allowed in this packet
	INVALID_ARGUMENT,       // bad Config or call argument
	UNSUPPORTED_VERSION,
	NOT_CONNECTED,
	ALREADY_CONNECTED,
	PACKET_ID_EXHAUSTED,    // all 65535 ids in flight
	SEND_QUOTA_EXHAUSTED,   // server Receive Maximum reached and queue full
	QUEUE_FULL,
	NOT_SUPPORTED_BY_SERVER, // QoS, retain, wildcard, shared, subscription id
	CONNECTION_REFUSED,     // CONNACK with non-zero code; see Event
	KEEPALIVE_TIMEOUT,
	RECEIVE_MAXIMUM_EXCEEDED, // the server sent more unfinished QoS 2 messages than our Receive Maximum
	PAYLOAD_FORMAT_INVALID, // payload marked as UTF-8 text is not (checked only when asked for)
	CLOSED,                 // transport: peer closed (EOF); same name in every plant library
	TIMEOUT,                // transport read/write timeout, and adapter wait expired
	AUTH_FAILED,
	SERVER_DISCONNECTED;    // server sent DISCONNECT; reason in the event

constdef Version : char
{
	V311 = 4,
	V5   = 5,
}

enum QoS : char
{
	AT_MOST_ONCE,
	AT_LEAST_ONCE,
	EXACTLY_ONCE,
}

constdef PacketType : char
{
	CONNECT = 1,
	CONNACK = 2,
	PUBLISH = 3,
	PUBACK = 4,
	PUBREC = 5,
	PUBREL = 6,
	PUBCOMP = 7,
	SUBSCRIBE = 8,
	SUBACK = 9,
	UNSUBSCRIBE = 10,
	UNSUBACK = 11,
	PINGREQ = 12,
	PINGRESP = 13,
	DISCONNECT = 14,
	AUTH = 15,
}

// 5.0 section 2.4. Duplicated values (0x00) are legal in constdef.
constdef ReasonCode : char
{
	SUCCESS = 0x00,
	NORMAL_DISCONNECTION = 0x00,
	GRANTED_QOS_0 = 0x00,
	GRANTED_QOS_1 = 0x01,
	GRANTED_QOS_2 = 0x02,
	DISCONNECT_WITH_WILL = 0x04,
	NO_MATCHING_SUBSCRIBERS = 0x10,
	NO_SUBSCRIPTION_EXISTED = 0x11,
	CONTINUE_AUTHENTICATION = 0x18,
	RE_AUTHENTICATE = 0x19,
	UNSPECIFIED_ERROR = 0x80,
	MALFORMED_PACKET = 0x81,
	PROTOCOL_ERROR = 0x82,
	IMPLEMENTATION_SPECIFIC_ERROR = 0x83,
	UNSUPPORTED_PROTOCOL_VERSION = 0x84,
	CLIENT_ID_NOT_VALID = 0x85,
	BAD_USER_NAME_OR_PASSWORD = 0x86,
	NOT_AUTHORIZED = 0x87,
	SERVER_UNAVAILABLE = 0x88,
	SERVER_BUSY = 0x89,
	BANNED = 0x8A,
	SERVER_SHUTTING_DOWN = 0x8B,
	BAD_AUTHENTICATION_METHOD = 0x8C,
	KEEP_ALIVE_TIMEOUT = 0x8D,
	SESSION_TAKEN_OVER = 0x8E,
	TOPIC_FILTER_INVALID = 0x8F,
	TOPIC_NAME_INVALID = 0x90,
	PACKET_IDENTIFIER_IN_USE = 0x91,
	PACKET_IDENTIFIER_NOT_FOUND = 0x92,
	RECEIVE_MAXIMUM_EXCEEDED = 0x93,
	TOPIC_ALIAS_INVALID = 0x94,
	PACKET_TOO_LARGE = 0x95,
	MESSAGE_RATE_TOO_HIGH = 0x96,
	QUOTA_EXCEEDED = 0x97,
	ADMINISTRATIVE_ACTION = 0x98,
	PAYLOAD_FORMAT_INVALID = 0x99,
	RETAIN_NOT_SUPPORTED = 0x9A,
	QOS_NOT_SUPPORTED = 0x9B,
	USE_ANOTHER_SERVER = 0x9C,
	SERVER_MOVED = 0x9D,
	SHARED_SUBSCRIPTIONS_NOT_SUPPORTED = 0x9E,
	CONNECTION_RATE_EXCEEDED = 0x9F,
	MAXIMUM_CONNECT_TIME = 0xA0,
	SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED = 0xA1,
	WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED = 0xA2,
}

// 3.1.1 section 3.2.2.3 CONNACK return codes (0..5).
constdef ConnAckCode311 : char
{
	ACCEPTED = 0,
	UNACCEPTABLE_PROTOCOL_VERSION = 1,
	IDENTIFIER_REJECTED = 2,
	SERVER_UNAVAILABLE = 3,
	BAD_USER_NAME_OR_PASSWORD = 4,
	NOT_AUTHORIZED = 5,
}

const SUBACK_FAILURE_311 = 0x80;
const usz MAX_REMAINING_LENGTH = 268_435_455;   // 2.2.3 / 5.0 1.5.5
const usz MAX_STRING_LENGTH = 65_535;           // 1.5.3 / 5.0 1.5.4

// Maps a 3.1.1 CONNACK return code to the 5.0 reason code used in events.
fn ReasonCode connack311_to_reason(ConnAckCode311 code)
{
	switch ((char)code)
	{
		case 0: return ReasonCode.SUCCESS;
		case 1: return ReasonCode.UNSUPPORTED_PROTOCOL_VERSION;
		case 2: return ReasonCode.CLIENT_ID_NOT_VALID;
		case 3: return ReasonCode.SERVER_UNAVAILABLE;
		case 4: return ReasonCode.BAD_USER_NAME_OR_PASSWORD;
		case 5: return ReasonCode.NOT_AUTHORIZED;
		default: return ReasonCode.UNSPECIFIED_ERROR;
	}
}

// The name of a reason code as the specification words it ("Not authorized"); "Unknown reason code"
// for values the specification does not define. 0x00 is "Success" (it is also Normal disconnection
// and Granted QoS 0 in the packets that use it that way).
fn String ReasonCode.describe(self)
{
	switch ((char)self)
	{
		case 0x00: return "Success";
		case 0x01: return "Granted QoS 1";
		case 0x02: return "Granted QoS 2";
		case 0x04: return "Disconnect with Will Message";
		case 0x10: return "No matching subscribers";
		case 0x11: return "No subscription existed";
		case 0x18: return "Continue authentication";
		case 0x19: return "Re-authenticate";
		case 0x80: return "Unspecified error";
		case 0x81: return "Malformed Packet";
		case 0x82: return "Protocol Error";
		case 0x83: return "Implementation specific error";
		case 0x84: return "Unsupported Protocol Version";
		case 0x85: return "Client Identifier not valid";
		case 0x86: return "Bad User Name or Password";
		case 0x87: return "Not authorized";
		case 0x88: return "Server unavailable";
		case 0x89: return "Server busy";
		case 0x8A: return "Banned";
		case 0x8B: return "Server shutting down";
		case 0x8C: return "Bad authentication method";
		case 0x8D: return "Keep Alive timeout";
		case 0x8E: return "Session taken over";
		case 0x8F: return "Topic Filter invalid";
		case 0x90: return "Topic Name invalid";
		case 0x91: return "Packet Identifier in use";
		case 0x92: return "Packet Identifier not found";
		case 0x93: return "Receive Maximum exceeded";
		case 0x94: return "Topic Alias invalid";
		case 0x95: return "Packet too large";
		case 0x96: return "Message rate too high";
		case 0x97: return "Quota exceeded";
		case 0x98: return "Administrative action";
		case 0x99: return "Payload format invalid";
		case 0x9A: return "Retain not supported";
		case 0x9B: return "QoS not supported";
		case 0x9C: return "Use another server";
		case 0x9D: return "Server moved";
		case 0x9E: return "Shared Subscriptions not supported";
		case 0x9F: return "Connection rate exceeded";
		case 0xA0: return "Maximum connect time";
		case 0xA1: return "Subscription Identifiers not supported";
		case 0xA2: return "Wildcard Subscriptions not supported";
		default: return "Unknown reason code";
	}
}
