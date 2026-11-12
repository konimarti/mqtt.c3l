module mqtt;

// Naming convention: the FAULTS below are the library's error values and are always written
// `mqtt::NAME` (or returned from a `T?` function). The wire reason codes are `ReasonCode.NAME`.
// Three names exist in both (MALFORMED_PACKET, PROTOCOL_ERROR, PACKET_TOO_LARGE): the fault says
// "this call failed", the ReasonCode is the byte on the wire (0x81, 0x82, 0x95). The qualification
// always tells them apart; c3_refs rename_to works per namespace.

// Faults: see DESIGN.md section 6.
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
