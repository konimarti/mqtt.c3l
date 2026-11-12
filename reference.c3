module mqtt::redirect;

// Server Reference [5.0 3.2.2.3.16, 4.11]: where a server asks the client to connect instead. The text is
// "host", "host:port", "[ipv6]:port" (or "[ipv6]"), or a list of those separated by spaces; the first one is
// used. host borrows from `reference`; port is default_port when the reference names none.
// Returns false for anything else (an empty host, a port that is not 1..65535, an IPv6 address without
// brackets, an unterminated bracket, a space-less control character). host and port are written only when the
// reference was accepted.
fn bool parse_server_reference(String reference, String* host, int* port, int default_port)
{
	String h;
	int p;
	if (!parse_first(reference, &h, &p, default_port)) return false;
	*host = h;
	*port = p;
	return true;
}

fn bool parse_first(String reference, String* host, int* port, int default_port) @private
{
	usz start;
	while (start < reference.len && reference[start] == ' ') start++;
	usz end = start;
	while (end < reference.len && reference[end] != ' ') end++;
	String first = reference[start:end - start];
	if (first.len == 0) return false;

	String rest;
	if (first[0] == '[')
	{
		usz close;
		bool found;
		for (usz i = 1; i < first.len; i++)
		{
			if (first[i] == ']')
			{
				close = i;
				found = true;
				break;
			}
		}
		if (!found || close == 1) return false;
		*host = first[1:close - 1];
		if (!plain(*host)) return false;
		rest = first[close + 1..];
		if (rest.len == 0)
		{
			*port = default_port;
			return true;
		}
		if (rest[0] != ':') return false;
		rest = rest[1..];
	}
	else
	{
		usz colons;
		usz at;
		for (usz i = 0; i < first.len; i++)
		{
			if (first[i] == ':')
			{
				colons++;
				at = i;
			}
		}
		if (colons > 1) return false;                      // an IPv6 address needs its brackets
		if (colons == 0)
		{
			*host = first;
			if (!plain(*host)) return false;
			*port = default_port;
			return true;
		}
		if (at == 0) return false;
		*host = first[:at];
		if (!plain(*host)) return false;
		rest = first[at + 1..];
	}
	if (rest.len == 0 || rest.len > 5) return false;
	int value;
	foreach (c : rest)
	{
		if (c < '0' || c > '9') return false;
		value = value * 10 + (c - '0');
	}
	if (value < 1 || value > 65_535) return false;
	*port = value;
	return true;
}

// No control characters (below 0x21, or DEL) in a host.
fn bool plain(String host) @private
{
	foreach (c : host)
	{
		if (c < 0x21 || c == 0x7F) return false;
	}
	return true;
}
