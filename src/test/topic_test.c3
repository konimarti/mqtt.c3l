module mqtt::topic_test;
import mqtt, mqtt::topic, std::io;

struct Row
{
	String input;
	bool valid;
}

struct MRow
{
	String filter;
	String name;
	bool match;
}

// TEST-VECTORS 8.1, same row order (rows with a NUL or 65535 bytes are generated below).
Row[*] name_rows = {
	{ "a", true },
	{ "a/b", true },
	{ "/", true },
	{ "/a", true },
	{ "a/", true },
	{ "a//b", true },
	{ "$SYS/broker/uptime", true },
	{ "", false },
	{ "a/+", false },
	{ "a/#", false },
	{ "#", false },
	{ "+", false },
	{ "a\0b", false },
};

// 8.2, same row order. `$share/g/` is invalid: its filter part is empty.
Row[*] filter_rows = {
	{ "#", true }, { "+", true }, { "+/+", true }, { "/+", true }, { "a/#", true },
	{ "a/+/b", true }, { "+/a/#", true }, { "sport/tennis/#", true },
	{ "sport/+/player1", true },
	{ "", false },
	{ "sport+", false }, { "sport/+tennis", false }, { "+sport", false }, { "a/b+", false },
	{ "sport/#/ranking", false }, { "#/a", false },
	{ "sport#", false }, { "a/#b", false }, { "#a", false },
	{ "##", false }, { "a/##", false }, { "++", false },
	{ "$share/g/a/b", true },
	{ "$share/g/#", true }, { "$share/g/+/x", true },
	{ "$share/g", false },
	{ "$share//a", false },
	{ "$share/g+/a", false }, { "$share/g#/a", false }, { "$share/+/a", false },
	{ "$share/g/", false },
	{ "$SYS/#", true }, { "$SYS/+", true },
};

// 8.3, same row order. The row with the empty name is n/a (the name is invalid) and is not in the table.
MRow[*] match_rows = {
	{ "sport/tennis/player1/#", "sport/tennis/player1", true },
	{ "sport/tennis/player1/#", "sport/tennis/player1/ranking", true },
	{ "sport/tennis/player1/#", "sport/tennis/player1/score/wimbledon", true },
	{ "sport/#", "sport", true },
	{ "sport/tennis/+", "sport/tennis/player1", true },
	{ "sport/tennis/+", "sport/tennis/player2", true },
	{ "sport/tennis/+", "sport/tennis/player1/ranking", false },
	{ "sport/+", "sport", false },
	{ "sport/+", "sport/", true },
	{ "+", "finance", true },
	{ "+", "/finance", false },
	{ "/+", "/finance", true },
	{ "+/+", "/finance", true },
	{ "#", "a/b/c", true },
	{ "#", "/", true },
	{ "#", "$SYS/x", false },
	{ "+/monitor/Clients", "$SYS/monitor/Clients", false },
	{ "$SYS/#", "$SYS/monitor/Clients", true },
	{ "$SYS/monitor/+", "$SYS/monitor/Clients", true },
	{ "+/#", "$a/b", false },
	{ "a/+/c", "a/b/c", true },
	{ "a/+/c", "a//c", true },
	{ "a/+/c", "a/b/d", false },
	{ "a/b", "a/b/c", false },
	{ "a/b/c", "a/b", false },
	{ "a/b/#", "a/b/", true },
	{ "A/b", "a/b", false },
	{ "a/b", "a/b ", false },
	{ "a/#", "ab", false },
	{ "$share/g/a/+", "a/b", true },
	{ "$share/g/#", "$SYS/x", false },
};

fn void name_table() @test
{
	foreach (i, r : name_rows)
	{
		bool ok = @ok(topic::validate_name(r.input));
		assert(ok == r.valid, "name row");
	}
	io::printfn("topic names: %d rows", name_rows.len);
	assert(name_rows.len == 13);
}

fn void name_length_limit() @test
{
	char[] big = mem::temp_array(char, 65536);
	big[..] = 'a';
	assert(@ok(topic::validate_name((String)big[:65535])), "65535 bytes");
	assert(@catch(topic::validate_name((String)big)) == mqtt::INVALID_TOPIC_NAME, "65536 bytes");
}

fn void filter_table() @test
{
	foreach (i, r : filter_rows)
	{
		bool ok = @ok(topic::validate_filter(r.input));
		assert(ok == r.valid, "filter row");
	}
	io::printfn("topic filters: %d rows", filter_rows.len);
	assert(filter_rows.len == 33);
	assert(@catch(topic::validate_filter("a/#/b")) == mqtt::INVALID_TOPIC_FILTER);
}

fn void shared_split() @test
{
	assert(topic::is_shared("$share/g/a/b"));
	assert(!topic::is_shared("$SYS/a"));
	String g, f;
	topic::split_shared("$share/grp/a/+/b", &g, &f)!!;
	assert(g == "grp" && f == "a/+/b");
	assert(@catch(topic::split_shared("a/b", &g, &f)) == mqtt::INVALID_TOPIC_FILTER);
	assert(@catch(topic::split_shared("$share/g/", &g, &f)) == mqtt::INVALID_TOPIC_FILTER);
}

fn void match_table() @test
{
	foreach (i, r : match_rows)
	{
		assert(topic::matches(r.filter, r.name) == r.match, "match row");
	}
	io::printfn("topic matches: %d rows", match_rows.len);
	assert(match_rows.len == 31);
}

// ---- slow reference: split into levels, recurse ----

fn bool ref_levels(String[] f, String[] n, bool first)
{
	if (f.len == 0) return n.len == 0;
	if (f[0] == "#") return !(first && n.len > 0 && n[0].len > 0 && n[0][0] == '$');
	if (n.len == 0) return false;
	if (first && n[0].len > 0 && n[0][0] == '$' && f[0] == "+") return false;
	if (f[0] != "+" && f[0] != n[0]) return false;
	return ref_levels(f[1..], n[1..], false);
}

fn bool ref_match(String filter, String name)
{
	return ref_levels(filter.tsplit("/"), name.tsplit("/"), true);
}

struct Rng
{
	ulong state;
}

fn uint Rng.next(&self)
{
	self.state = self.state * 6364136223846793005 + 1442695040888963407;
	return (uint)(self.state >> 33);
}

fn String gen(Rng* rng, usz maxlen)
{
	String alphabet = "ab/+#$";
	usz len = rng.next() % (maxlen + 1);
	char[] s = mem::temp_array(char, (sz)len);
	foreach (&c : s) *c = alphabet[rng.next() % alphabet.len];
	return (String)s;
}

fn void random_match() @test
{
	Rng rng = { 12345 };
	usz cases, compared;
	for (usz i = 0; i < 2000; i++)
	{
		@pool()
		{
			String filter = gen(&rng, 8);
			String name = gen(&rng, 8);
			// only valid pairs have a defined result
			if (@ok(topic::validate_filter(filter)) && @ok(topic::validate_name(name)))
			{
				assert(topic::matches(filter, name) == ref_match(filter, name), "matches disagrees with reference");
				compared++;
			}
			cases++;
		};
	}
	io::printfn("topic random: %d cases, %d valid pairs compared", cases, compared);
	assert(cases == 2000);
	assert(compared > 100, "too few valid pairs");
}

fn void stress_65535() @test
{
	// filter of 65535 bytes: 32767 x "+/" then "#" ; name of 65535 bytes: "a/" x 32767 then "a"
	char[] f = mem::temp_array(char, 65535);
	char[] n = mem::temp_array(char, 65535);
	for (usz i = 0; i + 1 < 65535; i += 2)
	{
		f[i] = '+';
		f[i + 1] = '/';
		n[i] = 'a';
		n[i + 1] = '/';
	}
	f[65534] = '#';
	n[65534] = 'a';
	String filter = (String)f;
	String name = (String)n;
	assert(@ok(topic::validate_filter(filter)), "valid filter");
	assert(@ok(topic::validate_name(name)), "valid name");
	usz steps;
	assert(topic::matches_counted(filter, name, &steps), "matches");
	assert(steps <= 2 * (filter.len + name.len), "linear steps");

	// all "+" levels, same shape, no '#': 32767 levels + "+" = 65535 bytes
	f[65534] = '+';
	steps = 0;
	assert(topic::matches_counted(filter, name, &steps), "plus only");
	assert(steps <= 2 * (filter.len + name.len), "linear steps");

	// mismatch in the last level
	n[65534] = 'b';
	f[65534] = 'a';
	steps = 0;
	assert(!topic::matches_counted(filter, name, &steps), "mismatch");
	assert(steps <= 2 * (filter.len + name.len), "linear steps");

	// a longer name than the filter with trailing '#' dropped
	steps = 0;
	f[65533] = 'x';
	assert(!topic::matches_counted(filter, name, &steps), "level mismatch");
	assert(steps <= 2 * (filter.len + name.len), "linear steps");
	io::printfn("topic stress: 65535-byte filter, steps %d", steps);
}
