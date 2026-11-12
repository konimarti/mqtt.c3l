module mqtt::redirect_test;
import mqtt::redirect;

struct Row
{
	String text;
	bool ok;
	String host;
	int port;
}

fn void server_reference_parse_table() @test
{
	Row[*] rows = {
		{ "example.org", true, "example.org", 1883 },
		{ "example.org:8883", true, "example.org", 8883 },
		{ "192.168.1.5:1884", true, "192.168.1.5", 1884 },
		{ "[::1]:1884", true, "::1", 1884 },
		{ "[2001:db8::7]", true, "2001:db8::7", 1883 },
		{ "a.example:1 b.example:2 c.example", true, "a.example", 1 },
		{ "  spaced.example:99", true, "spaced.example", 99 },
		{ "", false, "", 0 },
		{ "   ", false, "", 0 },
		{ "host:", false, "", 0 },
		{ ":1883", false, "", 0 },
		{ "host:0", false, "", 0 },
		{ "host:65536", false, "", 0 },
		{ "host:12a", false, "", 0 },
		{ "host:1:2", false, "", 0 },
		{ "::1", false, "", 0 },
		{ "[::1", false, "", 0 },
		{ "[]:80", false, "", 0 },
		{ "[::1]x", false, "", 0 },
		{ "[::1]:", false, "", 0 },
	};
	foreach (row : rows)
	{
		String host;
		int port;
		bool ok = redirect::parse_server_reference(row.text, &host, &port, 1883);
		assert(ok == row.ok, "accepted or refused as expected");
		if (ok) assert(host == row.host && port == row.port, "host and port");
	}
}

// a reference that is refused leaves the outputs untouched, and control characters are not part of a host
fn void server_reference_failure_does_not_touch_the_outputs() @test
{
	String[*] bad = { "[::1]x", "[::1]:99999", "host:99999", "host\t:80", "[::1]:", "bad\x00host" };
	foreach (text : bad)
	{
		String host = "untouched";
		int port = 4242;
		bool ok = redirect::parse_server_reference(text, &host, &port, 1883);
		assert(!ok, "refused");
		assert(host == "untouched" && port == 4242, "outputs unchanged after a refusal");
	}
	String host;
	int port;
	assert(!redirect::parse_server_reference("host\x7F", &host, &port, 1883), "DEL in a host");
	assert(!redirect::parse_server_reference("ho\x01st", &host, &port, 1883), "control character in a host");
}
