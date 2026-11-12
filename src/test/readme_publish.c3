module mqtt::readme_publish;
import mqtt, mqtt::client, mqtt::core, mqtt::tcp, mqtt::transport;
import std::time;

fn void? publish_once() @private
{
	TcpTransport t = tcp::connect("localhost", 1883, time::sec(5))!;
	defer (void)t.close();
	Config config = core::default_config(Version.V5, "sensor-1");
	Client c;
	defer c.close();
	c.open(mem, (Transport)&t, &config, time::sec(5))!;
	OutMessage m = { .topic = "plant/line1/temp", .payload = (char[])"21.5", .qos = QoS.AT_LEAST_ONCE };
	c.publish_wait(&m, time::sec(5))!;
}
