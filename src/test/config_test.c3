module mqtt::config_test;
import mqtt, mqtt::core;

// A zero Config (with the version chosen) is usable: every zero field stands for its documented default.
fn void config_zero_value_defaults() @test
{
	Config c = { .version = Version.V5 };
	assert(c.client_id.len == 0 && !c.clean_start && c.keep_alive == 0);
	assert(!c.has_username && !c.has_password && c.will == null);
	assert(c.session_expiry == 0);
	assert(!c.request_response_info);
	assert(!c.has_auth_hook && c.auth_method.len == 0);
	assert(!c.auto_topic_alias && !c.validate_payload_utf8);

	assert(c.effective_receive_maximum() == 65_535, "receive maximum 0 means 65535");
	assert(c.effective_max_packet_size() == 256 * 1024, "inbound packet limit 0 means 256 KiB");
	assert(c.effective_max_inflight() == 20);
	assert(c.effective_max_queued() == 1024);
	assert(c.effective_max_out_buffer() == 1024 * 1024);
	assert(c.effective_max_in_buffer() == 4 * 1024 * 1024);
	assert(c.effective_ping_after_pct() == 75);
	assert(c.effective_pong_timeout_pct() == 100);
	assert(c.requests_problem_info(), "Request Problem Information defaults to 1");
	assert(c.topic_alias_maximum == 0, "no aliases accepted unless asked for");
}

fn void config_explicit_values_win() @test
{
	Config c = { .version = Version.V311 };
	c.receive_maximum = 5;
	c.max_packet_size = 1000;
	c.max_inflight = 3;
	c.max_queued = 7;
	c.max_out_buffer = 9000;
	c.max_in_buffer = 12_345;
	c.ping_after_pct = 50;
	c.pong_timeout_pct = 200;
	c.omit_problem_info = true;
	assert(c.effective_receive_maximum() == 5);
	assert(c.effective_max_packet_size() == 1000);
	assert(c.effective_max_inflight() == 3);
	assert(c.effective_max_queued() == 7);
	assert(c.effective_max_out_buffer() == 9000);
	assert(c.effective_max_in_buffer() == 12_345);
	assert(c.effective_ping_after_pct() == 50);
	assert(c.effective_pong_timeout_pct() == 200);
	assert(!c.requests_problem_info());
}

fn void config_in_buffer_follows_packet_limit() @test
{
	Config c = { .version = Version.V5 };
	c.max_packet_size = 8 * 1024 * 1024;
	assert(c.effective_max_in_buffer() == 8 * 1024 * 1024, "never less than one packet");
	c.max_packet_size = 1000;
	assert(c.effective_max_in_buffer() == 4 * 1024 * 1024);
}

// default_config sets exactly version, client id, clean_start and keep_alive.
fn void config_default_config() @test
{
	Config c = core::default_config(Version.V5, "mqttc-1");
	assert(c.version == Version.V5 && c.client_id == "mqttc-1");
	assert(c.clean_start && c.keep_alive == 60);
	assert(!c.has_username && c.username.len == 0 && !c.has_password && c.password.len == 0);
	assert(c.will == null);
	assert(c.session_expiry == 0 && c.receive_maximum == 0 && c.max_packet_size == 0 && c.topic_alias_maximum == 0);
	assert(!c.request_response_info && !c.omit_problem_info);
	assert(c.auth_method.len == 0 && c.auth_data.len == 0 && !c.has_auth_hook);
	assert(c.user_props.present == 0);
	assert(c.max_inflight == 0 && c.max_queued == 0 && !c.auto_topic_alias);
	assert(c.max_out_buffer == 0 && c.max_in_buffer == 0);
	assert(c.ping_after_pct == 0 && c.pong_timeout_pct == 0 && !c.validate_payload_utf8);
	Config d = core::default_config(Version.V311, "");
	assert(d.version == Version.V311 && d.client_id.len == 0 && d.clean_start && d.keep_alive == 60);
}

fn void config_credentials_helpers() @test
{
	Config c = core::default_config(Version.V311, "id");
	c.set_credentials("user", (char[]){ 1, 2 });
	assert(c.has_username && c.username == "user" && c.has_password && c.password.len == 2);
	c.set_username_only("other");
	assert(c.has_username && c.username == "other" && !c.has_password && c.password.len == 0);
	c.set_password_only((char[]){ 9 });
	assert(!c.has_username && c.username.len == 0 && c.has_password && c.password == (char[]){ 9 });
	// an empty user name and password are legal values, not "unset"
	c.set_credentials("", {});
	assert(c.has_username && c.has_password && c.username.len == 0 && c.password.len == 0);
}
