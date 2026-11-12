module mqttc::cli_test;
import mqtt, mqtt::core, mqtt::client, mqtt::transport, mqttc::args, mqttc::cli, mqtt::client_test, mqtt::testutil;
import std::io::file, std::time;

fn Args parsed(String[] argv)
{
	Args a;
	args::parse(argv, &a)!!;
	return a;
}

fn void mqttc_cli_redirect_keeps_credentials_at_the_same_host() @test
{
	assert(cli::redirect_allowed("broker.example", "broker.example"));
	assert(cli::redirect_allowed("Broker.Example", "broker.EXAMPLE"), "names compare without regard to case");
	assert(!cli::redirect_allowed("broker.example", "evil.example"));
	assert(!cli::redirect_allowed("broker.example", "broker.example.evil"));
	assert(!cli::redirect_allowed("127.0.0.1", ""));
}

fn void mqttc_cli_secret_needs_a_user_and_is_never_empty() @test
{
	// the variable alone is not sent to a broker without -u
	Args none = parsed({ "sub", "-t", "a" });
	assert(!cli::resolve_secret(tmem, &none, "from-env", true)!!.present);
	Args user = parsed({ "sub", "-t", "a", "-u", "kim" });
	Secret s = cli::resolve_secret(tmem, &user, "from-env", true)!!;
	assert(s.present && (String)s.bytes == "from-env" && !s.from_flag);
	assert(!cli::resolve_secret(tmem, &user, "", false)!!.present, "a user without any password");
	assert(@catch(cli::resolve_secret(tmem, &user, "", true)) == cli::EMPTY_SECRET, "an empty variable is an error");
}

fn void mqttc_cli_secret_order_file_then_environment_then_flag() @test
{
	String path = "mqttc_secret_test.tmp";
	file::save(path, "from-file\r\n")!!;
	defer (void)file::delete(path);
	Args both = parsed({ "sub", "-t", "a", "-u", "kim", "--password-file", path, "-P", "from-flag" });
	Secret s = cli::resolve_secret(tmem, &both, "from-env", true)!!;
	assert((String)s.bytes == "from-file", "one line end is dropped, the file wins");
	Args flag = parsed({ "sub", "-t", "a", "-u", "kim", "-P", "from-flag" });
	s = cli::resolve_secret(tmem, &flag, "from-env", true)!!;
	assert((String)s.bytes == "from-env" && !s.from_flag, "the variable beats -P");
	s = cli::resolve_secret(tmem, &flag, "", false)!!;
	assert((String)s.bytes == "from-flag" && s.from_flag);
	file::save(path, "ends-with-two\n\n")!!;
	s = cli::resolve_secret(tmem, &both, "", false)!!;
	assert((String)s.bytes == "ends-with-two\n", "only one line end is removed");
	file::save(path, "\n")!!;
	assert(@catch(cli::resolve_secret(tmem, &both, "", false)) == cli::EMPTY_SECRET, "an empty file");
}

fn void mqttc_cli_secret_file_permissions() @test
{
	$if env::LINUX || env::DARWIN:
		String path = "mqttc_secret_mode.tmp";
		file::save(path, "pw")!!;
		defer (void)file::delete(path);
		Args a = parsed({ "sub", "-t", "a", "-u", "kim", "--password-file", path });
		file::chmod(path, FilePermission.USER_READ | FilePermission.USER_WRITE)!!;
		assert(!cli::resolve_secret(tmem, &a, "", false)!!.loose_permissions);
		file::chmod(path, FilePermission.USER_READ | FilePermission.USER_WRITE | FilePermission.GROUP_READ)!!;
		assert(cli::resolve_secret(tmem, &a, "", false)!!.loose_permissions, "readable by the group");
	$endif
}

fn void mqttc_cli_printable_escapes_control_bytes() @test
{
	assert(cli::printable(tmem, "plain text ü") == "plain text ü");
	assert(cli::printable(tmem, "a\nb\tc") == "a\\x0ab\\x09c");
	assert(cli::printable(tmem, "\x1b[2J") == "\\x1b[2J");
	assert(cli::printable(tmem, "a\\b\x7f") == "a\\\\b\\x7f");
}

fn void mqttc_cli_empty_file_is_not_a_retained_clear() @test
{
	String path = "mqttc_payload_test.tmp";
	file::save(path, "")!!;
	defer (void)file::delete(path);
	Args a = parsed({ "pub", "-t", "a", "-r", "-f", path });
	assert(@catch(cli::payload_of(tmem, &a)) == args::REFUSED_CLEAR_RETAINED, "the length of the file counts, not -m");
	Args ok = parsed({ "pub", "-t", "a", "-r", "-f", path, "--allow-clear-retained" });
	assert(cli::payload_of(tmem, &ok)!!.len == 0);
	file::save(path, "x")!!;
	assert((String)cli::payload_of(tmem, &a)!! == "x");
}

fn Failure refused_by(String connack_hex, Args* a)
{
	client_test::Script s;
	Client c;
	Config cf = core::default_config(Version.V5, "x");
	s.on_write(0x10, connack_hex);
	c.use_clock(&client_test::script_clock, &s);
	assert(@catch(c.open(mem, (Transport)&s, &cf, time::sec(5))) == mqtt::CONNECTION_REFUSED);
	Failure f = cli::closed_event(tmem, a, &c);
	c.close();
	return f;
}

fn void mqttc_cli_refusal_keeps_its_reason_with_follow_redirect() @test
{
	Args a = parsed({ "pub", "-t", "a", "-m", "x", "--follow-redirect" });
	Failure f = refused_by("20 03 00 87 00", &a);
	assert(!f.redirected && f.reason == "Not authorized", "the reason was lost");
}

fn void mqttc_cli_redirect_from_a_refusal() @test
{
	// Use Another Server (0x9C) with Server Reference "other:1883"
	String connack = "20 10 00 9C 0D 1C 00 0A 6F 74 68 65 72 3A 31 38 38 33";
	Args follow = parsed({ "pub", "-t", "a", "-m", "x", "--follow-redirect" });
	Failure f = refused_by(connack, &follow);
	assert(f.redirected && f.host == "other" && f.port == 1883);
	Args plain = parsed({ "pub", "-t", "a", "-m", "x" });
	f = refused_by(connack, &plain);
	assert(!f.redirected, "not asked to follow");
}
