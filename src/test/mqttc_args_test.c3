module mqttc::args_test;
import mqtt, mqttc::args;
import std::core::env;

fn bool fails_with(String[] argv, fault expected, String bad)
{
	Args a;
	fault f = @catch(args::parse(argv, &a));
	return f == expected && a.bad == bad;
}

fn void mqttc_args_no_arguments_and_commands() @test
{
	Args a;
	args::parse({}, &a)!!;
	assert(a.mode == Mode.HELP);
	args::parse({ "--version" }, &a)!!;
	assert(a.mode == Mode.VERSION);
	args::parse({ "--help" }, &a)!!;
	assert(a.mode == Mode.HELP);
	assert(fails_with({ "push" }, args::UNKNOWN_COMMAND, "push"));
}

fn void mqttc_args_pub_every_flag() @test
{
	Args a;
	String[] argv = { "pub", "-h", "broker", "-p", "8883", "-t", "plant/a", "-m", "21.5", "-q", "2", "-r", "--v311", "-i", "me",
		"-u", "kim", "-k", "30", "--will-topic", "plant/lwt", "--will-msg", "gone", "--follow-redirect", "-v" };
	args::parse(argv, &a)!!;
	assert(a.mode == Mode.PUB && a.host == "broker" && a.port == 8883 && a.topic == "plant/a" && a.message == "21.5");
	assert(a.qos == QoS.EXACTLY_ONCE && a.retain && a.version == Version.V311 && a.client_id == "me" && a.user == "kim");
	assert(a.keep_alive == 30 && a.will_topic == "plant/lwt" && a.will_msg == "gone" && a.follow_redirect && a.verbose);
	assert(!a.has_password_flag && a.password_file == "");
}

fn void mqttc_args_sub_every_flag() @test
{
	Args a;
	String[] argv = { "sub", "-t", "plant/#", "-q", "1", "-c", "3", "-C", "keep", "-i", "me", "--v5", "--no-local",
		"-u", "kim", "--password-file", "/x/pw", "-P", "secret" };
	args::parse(argv, &a)!!;
	assert(a.mode == Mode.SUB && a.topic == "plant/#" && a.qos == QoS.AT_LEAST_ONCE && a.count == 3);
	assert(a.keep_session && a.version == Version.V5 && a.no_local);
	assert(a.password_file == "/x/pw" && a.has_password_flag && a.password_flag == "secret");
	// defaults
	args::parse({ "sub", "-t", "a" }, &a)!!;
	assert(a.host == "localhost" && a.port == 1883 && a.qos == QoS.AT_MOST_ONCE && a.version == Version.V5);
	assert(a.keep_alive == 60 && !a.keep_session && a.count == 0 && a.client_id == "");
}

fn void mqttc_args_missing_value() @test
{
	assert(fails_with({ "pub", "-t", "a", "-m" }, args::MISSING_VALUE, "-m"));
	assert(fails_with({ "sub", "-t" }, args::MISSING_VALUE, "-t"));
	assert(fails_with({ "sub", "-t", "a", "-p" }, args::MISSING_VALUE, "-p"));
	assert(fails_with({ "sub", "-t", "a", "--password-file" }, args::MISSING_VALUE, "--password-file"));
}

fn void mqttc_args_unknown_flag() @test
{
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "--bogus" }, args::UNKNOWN_FLAG, "--bogus"));
	assert(fails_with({ "sub", "-t", "a", "-z" }, args::UNKNOWN_FLAG, "-z"));
	assert(fails_with({ "sub", "-t", "a", "-m", "x" }, args::UNKNOWN_FLAG, "-m"), "-m belongs to pub");
	assert(fails_with({ "sub", "-t", "a", "-r" }, args::UNKNOWN_FLAG, "-r"));
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "-c", "2" }, args::UNKNOWN_FLAG, "-c"), "-c belongs to sub");
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "--no-local" }, args::UNKNOWN_FLAG, "--no-local"));
}

fn void mqttc_args_pub_without_topic_or_message() @test
{
	assert(fails_with({ "pub", "-m", "x" }, args::MISSING_TOPIC, ""));
	assert(fails_with({ "sub" }, args::MISSING_TOPIC, ""));
	assert(fails_with({ "pub", "-t", "a" }, args::MISSING_MESSAGE, ""));
}

fn void mqttc_args_retained_empty_guard() @test
{
	assert(fails_with({ "pub", "-t", "a", "-r", "-m", "" }, args::REFUSED_CLEAR_RETAINED, ""));
	Args a;
	args::parse({ "pub", "-t", "a", "-r", "-m", "", "--allow-clear-retained" }, &a)!!;
	assert(a.retain && a.message == "" && a.allow_clear_retained);
	args::parse({ "pub", "-t", "a", "-m", "" }, &a)!!;               // empty, not retained: an ordinary message
	args::parse({ "pub", "-t", "a", "-r", "-m", "x" }, &a)!!;
}

fn void mqttc_args_bad_values() @test
{
	assert(fails_with({ "sub", "-t", "a", "-p", "0" }, args::BAD_VALUE, "-p"));
	assert(fails_with({ "sub", "-t", "a", "-p", "65536" }, args::BAD_VALUE, "-p"));
	assert(fails_with({ "sub", "-t", "a", "-p", "x" }, args::BAD_VALUE, "-p"));
	assert(fails_with({ "sub", "-t", "a", "-q", "3" }, args::BAD_VALUE, "-q"));
	assert(fails_with({ "sub", "-t", "a", "-k", "70000" }, args::BAD_VALUE, "-k"));
	assert(fails_with({ "sub", "-t", "a", "-c", "0" }, args::BAD_VALUE, "-c"));
	assert(fails_with({ "sub", "-t", "a", "-C", "sometimes" }, args::BAD_VALUE, "-C"));
	assert(fails_with({ "pub", "-t", "a/+", "-m", "x" }, args::BAD_VALUE, "a/+"), "a wildcard is not a topic name");
	assert(fails_with({ "sub", "-t", "a/#/b" }, args::BAD_VALUE, "a/#/b"));
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "--will-topic", "w/#", "--will-msg", "m" }, args::BAD_VALUE, "w/#"));
}

fn void mqttc_args_will_and_version_combinations() @test
{
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "--will-topic", "w" }, args::WILL_INCOMPLETE, "--will-topic"));
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "--will-msg", "w" }, args::WILL_INCOMPLETE, "--will-msg"));
	assert(fails_with({ "sub", "-t", "a", "--v311", "--no-local" }, args::BAD_COMBINATION, "--no-local"));
	assert(fails_with({ "sub", "-t", "a", "-C", "keep" }, args::BAD_COMBINATION, "-C"), "a kept session needs a fixed id");
}

fn void mqttc_args_random_client_ids_differ() @test
{
	String a = args::random_client_id(tmem);
	String b = args::random_client_id(tmem);
	assert(a.starts_with("mqttc-") && a.len == 6 + 16);
	assert(a != b, "two runs must not take each other over");
}

fn void mqttc_args_empty_values_are_refused() @test
{
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "-u", "" }, args::BAD_VALUE, "-u"));
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "-i", "" }, args::BAD_VALUE, "-i"));
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "-h", "" }, args::BAD_VALUE, "-h"));
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "--will-topic", "", "--will-msg", "m" }, args::BAD_VALUE, "--will-topic"));
	assert(fails_with({ "pub", "-t", "", "-m", "x" }, args::BAD_VALUE, "-t"), "the empty topic is named");
}

fn void mqttc_args_password_needs_a_user() @test
{
	assert(fails_with({ "sub", "-t", "a", "--password-file", "/x" }, args::BAD_COMBINATION, "--password-file"));
	assert(fails_with({ "sub", "-t", "a", "-P", "x" }, args::BAD_COMBINATION, "-P"));
	Args a;
	args::parse({ "sub", "-t", "a", "-u", "kim", "-P", "x" }, &a)!!;
}

fn void mqttc_args_payload_from_a_file() @test
{
	Args a;
	args::parse({ "pub", "-t", "a", "-f", "payload.bin" }, &a)!!;
	assert(a.message_file == "payload.bin" && !a.has_message);
	args::parse({ "pub", "-t", "a", "--file", "p", "--redirect-credentials" }, &a)!!;
	assert(a.redirect_credentials);
	assert(fails_with({ "pub", "-t", "a", "-m", "x", "-f", "p" }, args::BAD_COMBINATION, "-f"));
	assert(fails_with({ "sub", "-t", "a", "-f", "p" }, args::UNKNOWN_FLAG, "-f"));
}

fn void mqttc_args_ids_come_from_the_operating_system() @test
{
	$if env::LINUX || env::DARWIN:
		char[16] a;
		char[16] b;
		assert(args::os_random(a[..]) && args::os_random(b[..]));
		assert(a != b, "two reads of the system generator differ");
	$endif
}
