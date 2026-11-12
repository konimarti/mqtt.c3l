module mqttc::args;
import mqtt, mqtt::topic;
import std::math::random, std::io::file, std::core::env;

// Command line of mqttc, parsed without touching the network, the environment or files, so the whole
// grammar can be tested.

faultdef
	UNKNOWN_COMMAND,        // first argument is not pub, sub, --version or --help
	UNKNOWN_FLAG,           // also a flag that belongs to the other command
	MISSING_VALUE,          // a flag that takes a value was the last argument
	BAD_VALUE,              // number out of range, unknown name, invalid topic
	MISSING_TOPIC,
	MISSING_MESSAGE,        // pub without -m
	REFUSED_CLEAR_RETAINED, // retained publish with an empty payload deletes the retained message
	WILL_INCOMPLETE,        // --will-topic and --will-msg go together
	BAD_COMBINATION;        // a flag the chosen protocol level does not have, or keep without an id

enum Mode : char
{
	HELP,
	VERSION,
	PUB,
	SUB,
}

const int DEFAULT_PORT = 1883;
const ushort DEFAULT_KEEP_ALIVE = 60;
const int MAX_HOPS = 3;                 // --follow-redirect gives up after this many redirects

struct Args
{
	Mode mode;
	String host;
	int port;
	String topic;
	String message;
	String message_file;            // pub: the payload is the content of this file
	bool has_message;
	QoS qos;
	bool retain;
	Version version;
	String client_id;               // empty: mqttc-<random>
	String user;
	String password_flag;           // -P value
	bool has_password_flag;
	String password_file;
	ushort keep_alive;
	String will_topic;
	String will_msg;
	bool follow_redirect;
	bool redirect_credentials;      // send user, password and will to the host of a redirect too
	bool verbose;
	bool allow_clear_retained;
	long count;                     // sub: stop after this many messages, 0 = no limit
	bool keep_session;              // sub: -C keep
	bool no_local;
	String bad;                     // the argument a fault is about
}

fn Args defaults()
{
	return { .host = "localhost", .port = DEFAULT_PORT, .version = Version.V5, .keep_alive = DEFAULT_KEEP_ALIVE };
}

// argv without the program name. On a fault `out.bad` names the argument.
fn void? parse(String[] argv, Args* out)
{
	Args a = defaults();
	*out = a;
	if (argv.len == 0) return;                       // usage
	String cmd = argv[0];
	switch (cmd)
	{
		case "--help":
			return;
		case "--version":
			out.mode = Mode.VERSION;
			return;
		case "pub":
			a.mode = Mode.PUB;
		case "sub":
			a.mode = Mode.SUB;
		default:
			out.bad = cmd;
			return UNKNOWN_COMMAND~;
	}
	bool pub = a.mode == Mode.PUB;
	bool has_will_topic;
	bool has_will_msg;
	bool has_topic;
	usz i = 1;
	while (i < argv.len)
	{
		String flag = argv[i++];
		out.bad = flag;
		switch (flag)
		{
			case "-h": a.host = take_text(argv, &i)!;
			case "-p": a.port = (int)number(take(argv, &i)!, 1, 65535)!;
			case "-t":
				a.topic = take_text(argv, &i)!;
				has_topic = true;
			case "-q": a.qos = (QoS)number(take(argv, &i)!, 0, 2)!;
			case "-i": a.client_id = take_text(argv, &i)!;
			case "-u": a.user = take_text(argv, &i)!;
			case "-P":
				a.password_flag = take(argv, &i)!;
				a.has_password_flag = true;
			case "--password-file": a.password_file = take(argv, &i)!;
			case "-k": a.keep_alive = (ushort)number(take(argv, &i)!, 0, 65535)!;
			case "--will-topic":
				a.will_topic = take_text(argv, &i)!;
				has_will_topic = true;
			case "--will-msg":
				a.will_msg = take(argv, &i)!;
				has_will_msg = true;
			case "--follow-redirect": a.follow_redirect = true;
			case "--redirect-credentials": a.redirect_credentials = true;
			case "-v": a.verbose = true;
			case "--v5": a.version = Version.V5;
			case "--v311": a.version = Version.V311;
			case "-m":
				if (!pub) return UNKNOWN_FLAG~;
				a.message = take(argv, &i)!;
				a.has_message = true;
			case "-f":
			case "--file":
				if (!pub) return UNKNOWN_FLAG~;
				a.message_file = take_text(argv, &i)!;
			case "-r":
				if (!pub) return UNKNOWN_FLAG~;
				a.retain = true;
			case "--allow-clear-retained":
				if (!pub) return UNKNOWN_FLAG~;
				a.allow_clear_retained = true;
			case "-c":
				if (pub) return UNKNOWN_FLAG~;
				a.count = number(take(argv, &i)!, 1, 2_147_483_647)!;
			case "-C":
				if (pub) return UNKNOWN_FLAG~;
				switch (take(argv, &i)!)
				{
					case "clean": a.keep_session = false;
					case "keep": a.keep_session = true;
					default: return BAD_VALUE~;
				}
			case "--no-local":
				if (pub) return UNKNOWN_FLAG~;
				a.no_local = true;
			default:
				return UNKNOWN_FLAG~;
		}
	}
	out.bad = "";
	if (!has_topic) return MISSING_TOPIC~;
	if (catch err = check_topic(&a))
	{
		out.bad = a.bad;
		return err~;
	}
	if (pub)
	{
		if (a.has_message && a.message_file.len > 0)
		{
			out.bad = "-f";
			return BAD_COMBINATION~;
		}
		if (!a.has_message && a.message_file.len == 0) return MISSING_MESSAGE~;
		// a payload from a file is checked once it is read
		if (a.retain && a.message_file.len == 0 && a.message.len == 0 && !a.allow_clear_retained) return REFUSED_CLEAR_RETAINED~;
	}
	if (has_will_topic != has_will_msg)
	{
		out.bad = has_will_topic ? "--will-topic" : "--will-msg";
		return WILL_INCOMPLETE~;
	}
	if (a.user.len == 0 && (a.password_file.len > 0 || a.has_password_flag))
	{
		out.bad = a.password_file.len > 0 ? "--password-file" : "-P";      // a password belongs to a user name
		return BAD_COMBINATION~;
	}
	if (a.no_local && a.version == Version.V311)
	{
		out.bad = "--no-local";
		return BAD_COMBINATION~;
	}
	if (a.keep_session && a.client_id.len == 0)
	{
		out.bad = "-C";                              // the session is found again by its id: a random one never is
		return BAD_COMBINATION~;
	}
	*out = a;
}

fn void? check_topic(Args* a) @private
{
	a.bad = a.topic;
	if (a.mode == Mode.PUB)
	{
		if (catch topic::validate_name(a.topic)) return BAD_VALUE~;
	}
	else if (catch topic::validate_filter(a.topic))
	{
		return BAD_VALUE~;
	}
	a.bad = a.will_topic;
	if (a.will_topic.len > 0)
	{
		if (catch topic::validate_name(a.will_topic)) return BAD_VALUE~;
	}
	a.bad = "";
}

// A value that must not be empty: an empty name would be dropped silently further on.
fn String? take_text(String[] argv, usz* i) @private
{
	String v = take(argv, i)!;
	if (v.len == 0) return BAD_VALUE~;
	return v;
}

fn String? take(String[] argv, usz* i) @private
{
	if (*i >= argv.len) return MISSING_VALUE~;
	return argv[(*i)++];
}

fn long? number(String s, long lo, long hi) @private
{
	long? v = s.to_long();
	if (catch v) return BAD_VALUE~;
	if (v < lo || v > hi) return BAD_VALUE~;
	return v;
}

fn String message(fault f)
{
	switch (f)
	{
		case UNKNOWN_COMMAND: return "unknown command";
		case UNKNOWN_FLAG: return "unknown flag";
		case MISSING_VALUE: return "missing value for";
		case BAD_VALUE: return "bad value";
		case MISSING_TOPIC: return "missing -t TOPIC";
		case MISSING_MESSAGE: return "missing -m MESSAGE";
		case REFUSED_CLEAR_RETAINED: return "an empty retained message deletes the retained message; add --allow-clear-retained if that is meant";
		case WILL_INCOMPLETE: return "--will-topic and --will-msg must be given together, missing";
		case BAD_COMBINATION: return "this flag does not fit the other options";
		default: return "error";
	}
}

const String USAGE =
	`usage:
  mqttc pub -h HOST [-p 1883] -t TOPIC -m MSG [-q 0|1|2] [-r] [--allow-clear-retained] [--v5|--v311] [-i ID] [-u USER]
  mqttc sub -h HOST [-p 1883] -t FILTER [-q N] [-c COUNT] [-C clean|keep] [--v5|--v311] [--no-local] [-i ID] [-u USER]
  pub reads the payload from a file with -f FILE instead of -m
values are taken as they are, also when they start with '-'; a flag given twice: the last one counts
common: -k KEEPALIVE, --will-topic T --will-msg M, --follow-redirect, -v
credentials: -u USER with --password-file FILE or the environment variable MQTT_PASSWORD (only used with -u);
  -P is accepted but visible in ps; --redirect-credentials sends them to another host after a redirect
  mqttc --version | --help`;

// mqttc-<16 hex digits> from a generator seeded from the OS entropy, so that two runs get different ids and do not take
// each other's session over.
fn String random_client_id(Allocator allocator)
{
	char[8] raw;
	ulong n;
	if (os_random(raw[..]))
	{
		n = bitcast(raw, ulong);
	}
	else
	{
		Sfc64Random rnd;
		random::seed_entropy(&rnd);               // best effort only: where the OS gives nothing
		n = rnd.next_long();
	}
	return string::format(allocator, "mqttc-%016x", n);
}

// Fills out with bytes from the operating system's generator (/dev/urandom); false where there is none.
fn bool os_random(char[] out)
{
	$if env::LINUX || env::DARWIN:
		File? f = file::open("/dev/urandom", "rb");
		if (catch f) return false;
		defer (void)f.close();
		sz? got = f.read(out);
		if (catch got) return false;
		return got == out.len;
	$else
		return false;
	$endif
}
