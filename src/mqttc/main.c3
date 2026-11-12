module mqttc;
import mqtt, mqtt::core, mqtt::client, mqtt::tcp, mqtt::transport, mqttc::args, mqttc::cli;
import std::io, std::core::env, std::os::env, std::time;

const long CONNECT_SECONDS = 5;
const long WAIT_SECONDS = 10;
const String WARN_FLAG = "mqttc: warning: -P is visible in the process list; use --password-file or MQTT_PASSWORD";
const String WARN_LOOSE = "mqttc: warning: the file with the credentials can be read by other users";

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

// The connection settings; with `credentials` false the user name, password and will stay out (a redirect to another host).
fn Config settings(Args* a, String id, Secret* secret, Will* will, bool credentials)
{
	Config config = core::default_config(a.version, id);
	config.keep_alive = a.keep_alive;
	config.clean_start = !a.keep_session;
	if (!credentials) return config;
	if (a.user.len > 0 && secret.present)
	{
		config.set_credentials(a.user, secret.bytes);
	}
	else if (a.user.len > 0)
	{
		config.set_username_only(a.user);
	}
	if (a.will_topic.len > 0)
	{
		*will = { .topic = a.will_topic, .payload = (char[])a.will_msg };
		config.will = will;
	}
	return config;
}

fn int run(Args* a)
{
	String? from_env = env::get_var(mem, "MQTT_PASSWORD");
	Secret? found = cli::resolve_secret(mem, a, from_env ?? "", @ok(from_env));
	if (catch err = found)
	{
		if (err == cli::EMPTY_SECRET)
		{
			io::eprintn("mqttc: the secret you gave is empty");
		}
		else
		{
			io::eprintfn("mqttc: cannot read the credentials: %s", err);
		}
		return 1;
	}
	Secret secret = found;
	defer foreach (&b : secret.bytes) *b = 0;
	if (secret.from_flag) io::eprintn(WARN_FLAG);
	if (secret.loose_permissions) io::eprintn(WARN_LOOSE);
	// the payload is read, and refused if it must be, before anything goes to the network (and once, not per redirect)
	char[] payload;
	if (a.mode == Mode.PUB)
	{
		char[]? data = cli::payload_of(mem, a);
		if (catch err = data)
		{
			io::eprintfn("mqttc: cannot use the payload: %s", err == args::REFUSED_CLEAR_RETAINED ? args::message(err) : "the file cannot be read");
			return 2;
		}
		payload = data;
	}
	String id = a.client_id.len > 0 ? a.client_id : args::random_client_id(mem);
	Will will;
	String host = a.host;
	int port = a.port;
	int hops;
	long seen;                                     // messages of sub, over all the connections
	while (true)
	{
		bool same_host = hops == 0 || a.redirect_credentials || cli::redirect_allowed(a.host, host);
		Config config = settings(a, id, &secret, &will, same_host);
		if (a.verbose) io::eprintfn("connecting to %s:%d as %s", host, port, id);
		Outcome o = session(a, &config, host, port, &seen, payload);
		if (!o.redirected) return o.code;
		if (++hops > args::MAX_HOPS)
		{
			io::eprintfn("mqttc: more than %d redirects", args::MAX_HOPS);
			return 1;
		}
		if (!a.redirect_credentials && !cli::redirect_allowed(a.host, o.host))
		{
			io::eprintfn("mqttc: redirected to %s: the credentials and the will are not sent there (--redirect-credentials)", o.host);
		}
		host = o.host;
		port = o.port;
	}
}

fn Outcome session(Args* a, Config* config, String host, int port, long* seen, char[] payload)
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
		Failure f = cli::closed_event(mem, a, &c);
		if (f.redirected) return { .redirected = true, .host = f.host, .port = f.port };
		if (err == mqtt::CONNECTION_REFUSED && f.reason.len > 0)
		{
			io::eprintfn("mqttc: connection refused: %s", f.reason);
			return { .code = 1 };
		}
		io::eprintfn("mqttc: cannot connect to %s:%d: %s", host, port, err);
		return { .code = 1 };
	}
	if (a.verbose) io::eprintn("connected");
	if (a.mode == Mode.PUB) return publish(a, &c, payload);
	return subscribe(a, &c, seen);
}

fn Outcome publish(Args* a, Client* c, char[] data)
{
	OutMessage m = { .topic = a.topic, .payload = data, .qos = a.qos, .retain = a.retain };
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

fn Outcome subscribe(Args* a, Client* c, long* seen)
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
				if (catch cli::write_message(io::stdout(), ev.message.topic, (String)ev.message.payload))
				{
					io::eprintn("mqttc: cannot write to the standard output");
					return { .code = 1 };
				}
				if (a.count > 0 && ++(*seen) >= a.count)
				{
					(void)c.disconnect(ReasonCode.NORMAL_DISCONNECTION, time::sec(WAIT_SECONDS));
					return {};
				}
			case CLOSED:
				Failure f = cli::of_closed(mem, a, &ev);
				if (f.redirected) return { .redirected = true, .host = f.host, .port = f.port };
				io::eprintfn("mqttc: connection closed: %s", f.reason);
				return { .code = 1 };
			default:
				break;
		}
	}
}
