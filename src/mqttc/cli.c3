module mqttc::cli;
import mqtt, mqtt::core, mqtt::client, mqtt::redirect, mqttc::args;
import std::io, std::io::file, std::core::env, std::time, libc;

// The parts of mqttc that decide something (credentials, redirects, what to tell the user about a failed
// connection), kept out of main so that they can be tested without a terminal or a network.

faultdef EMPTY_SECRET;

// May the credentials and the will that were meant for `original` be sent to `target`? Only to the same host
// (the names compare without regard to case): a server reference comes from the network and must not be able to collect
// the password for another machine.
fn bool redirect_allowed(String original, String target)
{
	if (original.len != target.len) return false;
	for (usz i = 0; i < original.len; i++)
	{
		if (lower(original[i]) != lower(target[i])) return false;
	}
	return true;
}

fn char lower(char c) @private => (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;

struct Secret
{
	char[] bytes;
	bool present;
	bool from_flag;                 // -P: the caller warns
	bool loose_permissions;         // the file can be read by others: the caller warns
}

// The password for the user named with -u: from --password-file, else from the environment value (MQTT_PASSWORD), else
// from -P. Without -u there is no password: a variable that is left in the environment is not sent to every broker.
// An empty password is an error. In a file one trailing line end (LF or CRLF) is dropped, nothing else.
fn Secret? resolve_secret(Allocator allocator, Args* a, String env_value, bool has_env)
{
	if (a.user.len == 0) return {};
	Secret s;
	if (a.password_file.len > 0)
	{
		char[] raw = file::load(allocator, a.password_file)!;
		usz n = raw.len;
		if (n > 0 && raw[n - 1] == '\n') n--;
		if (n > 0 && raw[n - 1] == '\r') n--;
		s.bytes = raw[:n];
		s.loose_permissions = readable_by_others(a.password_file);
	}
	else if (has_env)
	{
		s.bytes = (char[])env_value.copy(allocator);
	}
	else if (a.has_password_flag)
	{
		s.bytes = (char[])a.password_flag.copy(allocator);
		s.from_flag = true;
	}
	else
	{
		return {};
	}
	if (s.bytes.len == 0) return EMPTY_SECRET~;
	s.present = true;
	return s;
}

fn bool readable_by_others(String path)
{
	$if env::LINUX || env::DARWIN:
		libc::Stat st;
		if (libc::stat(path.zstr_tcopy(), &st) != 0) return false;
		return (uint)st.st_mode & 0o077 != 0;
	$else
		return false;
	$endif
}

// What a failed open or a closed connection comes to.
struct Failure
{
	bool redirected;
	String host;                    // owned by the allocator given
	int port;
	String reason;                  // the server's reason ("Not authorized"), empty when it sent none
}

// Reads the CLOSED event of the client (once: it is gone afterwards) and says whether the server asked for a redirect
// that may be followed, or why the connection ended.
fn Failure closed_event(Allocator allocator, Args* a, Client* c)
{
	Event ev;
	bool? got = c.next(&ev, time::DURATION_ZERO);
	if (catch got) return {};
	if (!got || ev.kind != EventKind.CLOSED) return {};
	return of_closed(allocator, a, &ev);
}

fn Failure of_closed(Allocator allocator, Args* a, Event* ev)
{
	Failure f = { .reason = ev.closed.reason.describe() };
	if (!a.follow_redirect || ev.closed.server_reference.len == 0) return f;
	String host;
	int port;
	if (!redirect::parse_server_reference(ev.closed.server_reference, &host, &port, args::DEFAULT_PORT)) return f;
	f.redirected = true;
	f.host = host.copy(allocator);
	f.port = port;
	return f;
}

// The text of a message for the terminal: bytes below 0x20 (the tab included) and 0x7F become \xNN, a backslash becomes \\, so that a
// payload cannot move the cursor, start an escape sequence or pass for a second field. Bytes of UTF-8 text above 0x7F stay.
fn String printable(Allocator allocator, String s)
{
	DString out;
	out.init(allocator);
	foreach (c : s)
	{
		if (c == '\\')
		{
			out.append("\\\\");
		}
		else if (c < 0x20 || c == 0x7F)
		{
			out.appendf("\\x%02x", c);
		}
		else
		{
			out.append_char(c);
		}
	}
	return out.str_view();
}

// The payload of pub: -m, or the content of -f. The empty-retained rule is applied to what was read.
fn char[]? payload_of(Allocator allocator, Args* a)
{
	char[] data = (char[])a.message;
	if (a.message_file.len > 0) data = file::load(allocator, a.message_file)!;
	if (data.len == 0 && a.retain && !a.allow_clear_retained) return args::REFUSED_CLEAR_RETAINED~;
	return data;
}

// One line for a message: the topic, a tab, the payload, both with control characters escaped. The text it builds is
// given back when it returns: a `sub` that runs for days must not grow with every message.
fn void? write_message(OutStream out, String topic, String payload)
{
	@pool()
	{
		io::fprintf(out, "%s\t%s\n", printable(tmem, topic), printable(tmem, payload))!;
	};
}
