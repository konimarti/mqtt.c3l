module mqtt::topic;
import mqtt, mqtt::wire;

// Topic names, topic filters and matching: [3.1.1 4.7][5.0 4.7, 4.8.2]. Pure functions that take no
// memory from anywhere: one pass over each input, no recursion.

const String SHARE_PREFIX = "$share/";

// A topic name: non-empty, well-formed UTF-8 without U+0000, at most 65535 bytes, no wildcards.
// (A v5 PUBLISH with a Topic Alias may carry an empty name on the wire; that is the core's business.)
fn void? validate_name(String name)
{
	if (name.len == 0) return mqtt::INVALID_TOPIC_NAME~;
	if (catch wire::validate_utf8(name)) return mqtt::INVALID_TOPIC_NAME~;
	foreach (c : name)
	{
		if (c == '+' || c == '#') return mqtt::INVALID_TOPIC_NAME~;
	}
}

// A topic filter, plain or `$share/<group>/<filter>`.
fn void? validate_filter(String filter)
{
	if (is_shared(filter))
	{
		String group, inner;
		split_shared(filter, &group, &inner)!;
		return;
	}
	check_plain_filter(filter)!;
}

// True when the filter starts with `$share/` (it may still be invalid: see split_shared).
fn bool is_shared(String filter) => filter.starts_with(SHARE_PREFIX);

// Splits `$share/<group>/<filter>`: group is non-empty and has no `/`, `+`, `#`; the inner filter must be
// a valid plain filter (so `$share/g/` and `$share/g` are invalid). Both outputs slice the input.
fn void? split_shared(String filter, String* group, String* inner)
{
	if (!is_shared(filter)) return mqtt::INVALID_TOPIC_FILTER~;
	String rest = filter[SHARE_PREFIX.len..];
	usz slash = find_slash(rest, 0);
	if (slash == rest.len || slash == 0) return mqtt::INVALID_TOPIC_FILTER~;
	String g = rest[:slash];
	foreach (c : g)
	{
		if (c == '+' || c == '#') return mqtt::INVALID_TOPIC_FILTER~;
	}
	String f = rest[slash + 1..];
	check_plain_filter(f)!;
	*group = g;
	*inner = f;
}

// Does the filter (plain or shared) match the topic name? Neither is validated here.
// Names starting with `$` do not match filters whose first level is a wildcard.
fn bool matches(String filter, String name) => matches_counted(filter, name, null);

// As matches; adds the number of bytes visited to *steps (when not null), for the linear-time test.
fn bool matches_counted(String filter, String name, usz* steps)
{
	if (is_shared(filter))
	{
		String group, inner;
		if (catch split_shared(filter, &group, &inner)) return false;
		filter = inner;
	}
	if (filter.len == 0) return false;
	if (name.len > 0 && name[0] == '$' && (filter[0] == '+' || filter[0] == '#')) return false;
	usz fi, ni;
	while (true)
	{
		usz fe = find_slash(filter, fi);
		usz ne = find_slash(name, ni);
		if (steps) *steps += (fe - fi) + (ne - ni) + 2;
		String fl = filter[fi:fe - fi];
		if (fl == "#") return true;
		if (fl != "+" && fl != name[ni:ne - ni]) return false;
		bool fdone = fe == filter.len;
		bool ndone = ne == name.len;
		if (fdone && ndone) return true;
		if (ndone)
		{
			// the name ended: only a trailing `#` still matches ("a/#" matches "a")
			return filter[fe + 1..] == "#";
		}
		if (fdone) return false;
		fi = fe + 1;
		ni = ne + 1;
	}
}

<*
 Index of the next '/' at or after from, or s.len.
*>
fn usz find_slash(String s, usz from) @private
{
	usz i = from;
	while (i < s.len && s[i] != '/') i++;
	return i;
}

fn void? check_plain_filter(String filter) @private
{
	if (filter.len == 0) return mqtt::INVALID_TOPIC_FILTER~;
	if (catch wire::validate_utf8(filter)) return mqtt::INVALID_TOPIC_FILTER~;
	usz i;
	while (true)
	{
		usz e = find_slash(filter, i);
		String level = filter[i:e - i];
		foreach (c : level)
		{
			if ((c == '+' || c == '#') && level.len > 1) return mqtt::INVALID_TOPIC_FILTER~;
		}
		if (level == "#" && e != filter.len) return mqtt::INVALID_TOPIC_FILTER~;
		if (e == filter.len) return;
		i = e + 1;
	}
}
