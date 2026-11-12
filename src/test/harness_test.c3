module mqtt::harness_test;
import mqtt, mqtt::harness, mqtt::testutil, std::time;

fn void harness_hex() @test
{
	assert(testutil::hex("") == {});
	assert(testutil::hex("00") == (char[]){ 0x00 });
	char[] b = testutil::hex("80 01 ff Ab  7f");
	assert(b.len == 5 && b[0] == 0x80 && b[1] == 0x01 && b[2] == 0xFF && b[3] == 0xAB && b[4] == 0x7F);
	char[] c = testutil::hex("10 0D00");
	assert(c.len == 3 && c[1] == 0x0D && c[2] == 0x00, "spaces are optional");
}

fn void harness_split_feed() @test
{
	char[] data = testutil::hex("01 02 03 04 05 06 07");
	char[] chunk;
	// all at once
	Pieces whole = harness::pieces(data, 0);
	assert(whole.next(&chunk) && chunk == data);
	assert(!whole.next(&chunk));
	// byte by byte
	Pieces single = harness::pieces(data, 1);
	int n;
	while (single.next(&chunk))
	{
		assert(chunk.len == 1 && chunk[0] == data[n]);
		n++;
	}
	assert(n == 7);
	// three at a time: 3, 3, 1
	Pieces three = harness::pieces(data, 3);
	assert(three.next(&chunk) && chunk.len == 3 && chunk[0] == 1);
	assert(three.next(&chunk) && chunk.len == 3 && chunk[0] == 4);
	assert(three.next(&chunk) && chunk.len == 1 && chunk[0] == 7);
	assert(!three.next(&chunk));
	// larger than the data
	Pieces big = harness::pieces(data, 100);
	assert(big.next(&chunk) && chunk.len == 7);
	assert(!big.next(&chunk));
	// nothing to hand out
	Pieces none = harness::pieces({}, 4);
	assert(!none.next(&chunk));
}

fn void harness_clock() @test
{
	VirtualClock clock;
	Duration start = clock.now;
	Duration t1 = clock.advance_ms(0);
	assert(t1 == start, "zero advance keeps the time");
	Duration t2 = clock.advance_ms(1500);
	assert(t2 > t1 && t2 - t1 == time::ms(1500));
	Duration t3 = clock.advance_ms(1);
	assert(t3 > t2 && clock.now == t3, "time never goes back");
	assert(clock.advance_ms(60_000) - t3 == time::ms(60_000));
}
