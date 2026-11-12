module mqtt::readme_example;
import mqtt, mqtt::client, mqtt::core, mqtt::tcp, mqtt::transport;
import std::io, std::time;

fn int run() @private
{
	TcpTransport t = tcp::connect("localhost", 1883, time::sec(5))!!;
	defer (void)t.close();
	Config config = core::default_config(Version.V5, "sensor-1");
	Client c;
	defer c.close();
	c.open(mem, (Transport)&t, &config, time::sec(5))!!;

	OutMessage m = { .topic = "plant/line1/temp", .payload = (char[])"21.5", .qos = QoS.AT_LEAST_ONCE };
	ReasonCode r = c.publish_wait(&m, time::sec(5))!!;
	io::printfn("done: %s", r.describe());

	SubEntry[1] entries = { { .filter = "plant/#", .qos = QoS.AT_LEAST_ONCE } };
	char[1] codes;
	c.subscribe(entries[..], codes[..], time::sec(5))!!;
	Event ev;
	while (c.next(&ev, time::sec(30))!!)
	{
		if (ev.kind == EventKind.CLOSED) break;
		if (ev.kind == EventKind.MESSAGE) io::printfn("%s: %s", ev.message.topic, (String)ev.message.payload);
	}
	return 0;
}
