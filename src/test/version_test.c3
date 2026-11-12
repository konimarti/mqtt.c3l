module mqtt::version_test;
import mqtt, std::core::env;

// In the library's own test build the library is the top-level project, so PROJECT_VERSION is its project.json version.
fn void version_matches_project_json() @test
{
	assert(mqtt::VERSION == env::PROJECT_VERSION, "mqtt::VERSION and project.json differ: use tools/bump_version.c3");
}
