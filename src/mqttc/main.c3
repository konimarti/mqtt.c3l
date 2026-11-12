module mqttc;
import mqtt, mqtt::core, mqtt::client, mqtt::tcp, mqtt::transport, mqtt::redirect, mqttc::args;
import std::io, std::io::file, std::core::env, std::os::env, std::time;

const long CONNECT_SECONDS = 5;
const long WAIT_SECONDS = 10;
const String WARN_FLAG = "mqttc: warning: -P is visible in the process list; use --password-file or MQTT_PASSWORD";

// How one connection ended: done with a result code, or the server sent the client somewhere else.
struct Outcome
{
	int code;
	bool redirected;
	String host;                    // owned by mem
	int port;
}

fn int main(String[] argv)
{
	Args a;
	if (catch err = args::parse(argv[1..], &a))
	{
		if (a.bad.len > 0)
		{
			io::eprintfn("mqttc: %s %s", args::message(err), a.bad);
		}
		else
		{
			io::eprintfn("mqttc: %s", args::message(err));
		}
		io::eprintn(args::USAGE);
		return 2;
	}
	switch (a.mode)
	{
		case HELP:
			io::printn(args::USAGE);
			return 0;
		case VERSION:
			io::printfn("mqttc %s", env::PROJECT_VERSION);
			return 0;
		default:
			break;
	}
	return run(&a);
}

fn int run(Args* a)
{
	char[] secret;
	bool has_secret;
	if (catch err = load_secret(a, &secret, &has_secret))
	{
		io::eprintfn("mqttc: cannot read the credentials: %s", err);
		return 1;
	}
	defer foreach (&b : secret) *b = 0;
	String id = a.client_id.len > 0 ? a.client_id : args::random_client_id(mem);
	Config config = core::default_config(a.version, id);
	config.keep_alive = a.keep_alive;
	config.clean_start = !a.keep_session;
	if (a.user.len > 0 && has_secret)
	{
		config.set_credentials(a.user, secret);
	}
	else if (a.user.len > 0)
	{
		config.set_username_only(a.user);
	}
	else if (has_secret)
	{
		config.set_password_only(secret);
	}
	Will will;
	if (a.will_topic.len > 0)
	{
		will = { .topic = a.will_topic, .payload = (char[])a.will_msg };
		config.will = &will;
	}
	String host = a.host;
	int port = a.port;
	int hops;
	while (true)
	{
		if (a.verbose) io::eprintfn("connecting to %s:%d as %s", host, port, id);
		Outcome o = session(a, &config, host, port);
		if (!o.redirected) return o.code;
		if (++hops > args::MAX_HOPS)
		{
			io::eprintfn("mqttc: more than %d redirects", args::MAX_HOPS);
			return 1;
		}
		host = o.host;
		port = o.port;
	}
}

// -P is visible to every user of the machine: it is taken last, and with a warning.
fn void? load_secret(Args* a, char[]* secret, bool* has_secret)
{
	if (a.password_file.len > 0)
	{
		char[] raw = file::load(mem, a.password_file)!;
		usz n = raw.len;
		while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r')) n--;
		*secret = raw[:n];
		*has_secret = true;
		return;
	}
	String? from_env = env::get_var(mem, "MQTT_PASSWORD");
	if (try from_env)
	{
		*secret = (char[])from_env;
		*has_secret = true;
		return;
	}
	if (a.has_password_flag)
	{
		io::eprintn(WARN_FLAG);
		*secret = (char[])a.password_flag;
		*has_secret = true;
	}
}

fn Outcome session(Args* a, Config* config, String host, int port)
{
	TcpTransport? link = tcp::connect(host, port, time::sec(CONNECT_SECONDS));
	if (catch err = link)
	{
		io::eprintfn("mqttc: cannot connect to %s:%d: %s", host, port, err);
		return { .code = 1 };
	}
	TcpTransport t = link;
	defer (void)t.close();
	Client c;
	defer c.close();
	if (catch err = c.open(mem, (Transport)&t, config, time::sec(CONNECT_SECONDS)))
	{
		Outcome o = follow(a, &c);
		if (o.redirected) return o;
		if (err == mqtt::CONNECTION_REFUSED)
		{
			Event ev;
			if (try c.next(&ev, time::DURATION_ZERO) && ev.kind == EventKind.CLOSED)
			{
				io::eprintfn("mqttc: connection refused: %s", ev.closed.reason.describe());
				return { .code = 1 };
			}
		}
		io::eprintfn("mqttc: cannot connect to %s:%d: %s", host, port, err);
		return { .code = 1 };
	}
	if (a.verbose) io::eprintn("connected");
	if (a.mode == Mode.PUB) return publish(a, &c);
	return subscribe(a, &c);
}

// After a refused connection or a server DISCONNECT: the redirect target the server named, if asked to follow it.
fn Outcome follow(Args* a, Client* c)
{
	if (!a.follow_redirect) return {};
	Event ev;
	bool? got = c.next(&ev, time::DURATION_ZERO);
	if (catch got) return {};
	if (!got || ev.kind != EventKind.CLOSED) return {};
	return redirect_of(a, &ev);
}

fn Outcome redirect_of(Args* a, Event* ev)
{
	if (!a.follow_redirect || ev.closed.server_reference.len == 0) return {};
	String host;
	int port;
	if (!redirect::parse_server_reference(ev.closed.server_reference, &host, &port, args::DEFAULT_PORT))
	{
		io::eprintfn("mqttc: the server sent a redirect that cannot be used: %s", ev.closed.server_reference);
		return {};
	}
	return { .redirected = true, .host = host.copy(mem), .port = port };
}

fn Outcome publish(Args* a, Client* c)
{
	OutMessage m = { .topic = a.topic, .payload = (char[])a.message, .qos = a.qos, .retain = a.retain };
	int code;
	if (a.qos == QoS.AT_MOST_ONCE)
	{
		if (catch err = c.publish(&m, time::sec(WAIT_SECONDS)))
		{
			io::eprintfn("mqttc: publish failed: %s", err);
			return { .code = 1 };
		}
	}
	else
	{
		ReasonCode? r = c.publish_wait(&m, time::sec(WAIT_SECONDS));
		if (catch err = r)
		{
			io::eprintfn("mqttc: publish failed: %s", err);
			return { .code = 1 };
		}
		if (a.verbose) io::eprintfn("acknowledged: %s", r.describe());
		if ((char)r >= 0x80)
		{
			io::eprintfn("mqttc: the server refused the message: %s", r.describe());
			code = 1;
		}
	}
	(void)c.disconnect(ReasonCode.NORMAL_DISCONNECTION, time::sec(WAIT_SECONDS));
	return { .code = code };
}

fn Outcome subscribe(Args* a, Client* c)
{
	SubEntry[1] entries = { { .filter = a.topic, .qos = a.qos, .no_local = a.no_local } };
	char[1] granted;
	if (catch err = c.subscribe(entries[..], granted[..], time::sec(WAIT_SECONDS)))
	{
		io::eprintfn("mqttc: subscribe failed: %s", err);
		return { .code = 1 };
	}
	if (granted[0] >= 0x80)
	{
		io::eprintn("mqttc: the server refused the subscription");
		return { .code = 1 };
	}
	if (a.verbose) io::eprintfn("subscribed to %s, granted QoS %d", a.topic, granted[0]);
	long seen;
	Event ev;
	while (true)
	{
		bool? got = c.next(&ev, time::sec(1));
		if (catch err = got)
		{
			io::eprintfn("mqttc: connection lost: %s", err);
			return { .code = 1 };
		}
		if (!got) continue;                                  // idle: next keeps the connection alive meanwhile
		switch (ev.kind)
		{
			case MESSAGE:
				io::printfn("%s %s", ev.message.topic, (String)ev.message.payload);
				if (a.count > 0 && ++seen >= a.count)
				{
					(void)c.disconnect(ReasonCode.NORMAL_DISCONNECTION, time::sec(WAIT_SECONDS));
					return {};
				}
			case CLOSED:
				Outcome o = redirect_of(a, &ev);
				if (o.redirected) return o;
				io::eprintfn("mqttc: connection closed: %s", ev.closed.reason.describe());
				return { .code = 1 };
			default:
				break;
		}
	}
}
