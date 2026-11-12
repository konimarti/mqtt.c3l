module mqtt::harness;
import mqtt, mqtt::core, mqtt::testutil, std::time;

// Helpers for tests that drive the session core from the outside: virtual monotonic time, a hex
// script for what the core must write, and bytes fed to it in pieces. No sockets, no real time.

// Virtual monotonic time. The core never reads the time itself; tests move this one forward.
struct VirtualClock
{
	Duration now;
}

// Moves time forward by ms (never backward) and returns the new time.
fn Duration VirtualClock.advance_ms(&self, long ms)
{
	assert(ms >= 0, "virtual time only moves forward");
	self.now = self.now + time::ms(ms);
	return self.now;
}

// Splits a byte slice into pieces of `size` bytes (the last one may be shorter); size 0 means one piece.
struct Pieces
{
	char[] data;
	usz size;
	usz pos;
}

fn Pieces pieces(char[] data, usz size) => { .data = data, .size = size == 0 ? data.len : size };

// Next piece; false when everything was handed out.
fn bool Pieces.next(&self, char[]* out)
{
	if (self.pos >= self.data.len) return false;
	usz n = self.data.len - self.pos;
	if (n > self.size) n = self.size;
	*out = self.data[self.pos:n];
	self.pos += n;
	return true;
}

// Feeds the bytes of `hex` to the core, `piece` bytes at a time (0 = all at once).
fn void feed(Core* core, VirtualClock* clock, String hex, usz piece = 0)
{
	Pieces p = pieces(testutil::hex(hex), piece);
	char[] chunk;
	while (p.next(&chunk)) core.input(clock.now, chunk)!!;
}

// The bytes the core wants written must equal `hex`; they are then taken as written.
fn void expect_out(Core* core, String hex)
{
	char[] expected = testutil::hex(hex);
	char[] got = core.pending_output();
	assert(got == expected, "bytes the core wants to write");
	core.output_done(got.len);
}

// The core has nothing to write.
fn void expect_no_out(Core* core)
{
	assert(core.pending_output().len == 0, "the core wants to write nothing");
}

// Takes every queued event and returns their kinds, in order (at most 64).
fn EventKind[] drain(Core* core)
{
	EventKind[] kinds = mem::temp_array(EventKind, 64);
	usz n;
	Event ev;
	while (core.poll_event(&ev) && n < kinds.len) kinds[n++] = ev.kind;
	return kinds[:n];
}
