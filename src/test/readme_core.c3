module mqtt::readme_core;
import mqtt, mqtt::core;
import std::time;

fn void? step(Allocator allocator, Core* core, Duration now, char[] from_network)
{
	// once: Config config = core::default_config(Version.V5, "sensor-1"); core.init(allocator, &config)!; core.connect(now)!;
	core.input(now, from_network)!;                      // bytes you read from the socket (at most core.input_room())
	Event ev;
	while (core.poll_event(&ev))
	{
		if (ev.kind == EventKind.MESSAGE) { /* ev.message.topic, ev.message.payload: valid until the next input */ }
	}
	Duration due;
	if (core.next_deadline(&due) && due <= now) core.timeout(now)!;   // keep alive, ping timeout
	char[] out = core.pending_output();                  // write these bytes to the socket,
	core.output_done(out.len);                           // then say how many went out
}
