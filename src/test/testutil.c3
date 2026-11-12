module mqtt::testutil;

// Test helper: "80 01 FF" -> bytes. Hex pairs, anything else (spaces) is skipped. Temp allocator.
fn char[] hex(String s)
{
	char[] out = mem::temp_array(char, s.len / 2 + 1);
	usz n;
	int hi = -1;
	foreach (c : s)
	{
		int v;
		if (c >= '0' && c <= '9')
		{
			v = c - '0';
		}
		else if (c >= 'A' && c <= 'F')
		{
			v = c - 'A' + 10;
		}
		else if (c >= 'a' && c <= 'f')
		{
			v = c - 'a' + 10;
		}
		else
		{
			continue;
		}
		if (hi < 0) { hi = v; continue; }
		out[n++] = (char)(hi * 16 + v);
		hi = -1;
	}
	return out[:n];
}

