module mqtt::props;

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
// otherwise falls back to `user_raw` / `subid_raw` (tested in M4 and M5).
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
	// Decode: raw concatenated entries, walk with user_props() / subscription_ids().
	char[] user_raw;
	char[] subid_raw;
	// Encode: caller provided lists.
	UserProperty[] user;
	uint[] subscription_ids;
}

fn bool Properties.has(&self, PropId id) => (self.present >> (uint)(char)id) & 1 != 0;
fn void Properties.set(&self, PropId id) { self.present |= 1UL << (uint)(char)id; }
