module mqtt::wire;
import mqtt;

// Variable Byte Integer: [5.0 1.5.5], [3.1.1 2.2.3]. Seven value bits per byte, the high bit says
// "another byte follows", at most four bytes, least significant group first.

// Number of bytes needed for value (1..4); 0 when value exceeds 268_435_455.
fn usz vbi_size(uint value)
{
	if (value > mqtt::MAX_REMAINING_LENGTH) return 0;
	if (value < 128) return 1;
	if (value < 16_384) return 2;
	if (value < 2_097_152) return 3;
	return 4;
}

// Writes value at the start of out and returns the number of bytes written.
// INVALID_ARGUMENT above 268_435_455, BUFFER_TOO_SMALL if out is short.
fn usz? vbi_encode(uint value, char[] out)
{
	usz n = vbi_size(value);
	if (n == 0) return mqtt::INVALID_ARGUMENT~;
	if (out.len < n) return mqtt::BUFFER_TOO_SMALL~;
	uint v = value;
	for (usz i = 0; i < n; i++)
	{
		char b = (char)(v & 0x7F);
		v >>= 7;
		if (v != 0) b |= 0x80;
		out[i] = b;
	}
	return n;
}

// Reads one integer from the start of input; consumed gets the number of bytes read.
// INCOMPLETE if the input ends inside the integer (the caller needs more bytes).
// MALFORMED_PACKET if the fourth byte still has the continuation bit (rejected right there,
// without waiting for a fifth byte), or if the encoding is not minimal (a last byte of 0 after
// at least one continuation byte, for example `80 00`).
fn uint? vbi_decode(char[] input, usz* consumed)
{
	uint value = 0;
	for (usz i = 0; i < 4; i++)
	{
		if (i >= input.len) return mqtt::INCOMPLETE~;
		char b = input[i];
		value |= (uint)(b & 0x7F) << (7 * i);
		if (b & 0x80 == 0)
		{
			if (i > 0 && b == 0) return mqtt::MALFORMED_PACKET~;
			*consumed = i + 1;
			return value;
		}
	}
	return mqtt::MALFORMED_PACKET~;
}

// UTF-8 as MQTT defines it: well-formed (shortest form, no surrogates U+D800..U+DFFF, nothing
// above U+10FFFF), no U+0000, at most 65535 bytes. [3.1.1 1.5.3], [5.0 1.5.4].
// U+0001..U+001F, U+007F..U+009F and the non-characters are "SHOULD NOT" in the spec and are accepted.
// A byte order mark is an ordinary U+FEFF and is not treated specially.
fn void? validate_utf8(String s)
{
	if (s.len > mqtt::MAX_STRING_LENGTH) return mqtt::INVALID_UTF8~;
	return check_utf8(s, false);
}

// Well-formed UTF-8 of any length, for message payloads that announce themselves as text
// (Payload Format Indicator 1). U+0000 is accepted: only a UTF-8 Encoded String forbids it.
fn void? validate_utf8_text(String s)
{
	return check_utf8(s, true);
}

fn void? check_utf8(String s, bool allow_nul) @private
{
	usz i = 0;
	while (i < s.len)
	{
		char c = s[i];
		if (c == 0 && !allow_nul) return mqtt::INVALID_UTF8~;
		if (c < 0x80)
		{
			i++;
			continue;
		}
		usz extra;
		char lo = 0x80;   // allowed range of the first continuation byte
		char hi = 0xBF;
		if (c >= 0xC2 && c <= 0xDF)
		{
			extra = 1;
		}
		else if (c >= 0xE0 && c <= 0xEF)
		{
			extra = 2;
			if (c == 0xE0) lo = 0xA0;      // no overlong 3-byte form
			if (c == 0xED) hi = 0x9F;      // no surrogates
		}
		else if (c >= 0xF0 && c <= 0xF4)
		{
			extra = 3;
			if (c == 0xF0) lo = 0x90;      // no overlong 4-byte form
			if (c == 0xF4) hi = 0x8F;      // nothing above U+10FFFF
		}
		else
		{
			return mqtt::INVALID_UTF8~;     // continuation byte as lead, C0, C1, F5..FF
		}
		if (i + extra >= s.len) return mqtt::INVALID_UTF8~;
		char c1 = s[i + 1];
		if (c1 < lo || c1 > hi) return mqtt::INVALID_UTF8~;
		for (usz k = 2; k <= extra; k++)
		{
			char ck = s[i + k];
			if (ck < 0x80 || ck > 0xBF) return mqtt::INVALID_UTF8~;
		}
		i += extra + 1;
	}
}

// Bounds-checked cursor over a borrowed byte slice. Never allocates, never reads past the end.
struct ByteReader
{
	char[] data;
	usz pos;
}

fn ByteReader reader(char[] data) => { .data = data };

fn usz ByteReader.remaining(&self) => self.data.len - self.pos;

fn char? ByteReader.u8(&self)
{
	if (self.remaining() < 1) return mqtt::INCOMPLETE~;
	return self.data[self.pos++];
}

fn ushort? ByteReader.u16(&self)
{
	if (self.remaining() < 2) return mqtt::INCOMPLETE~;
	ushort v = (ushort)self.data[self.pos] << 8 | (ushort)self.data[self.pos + 1];
	self.pos += 2;
	return v;
}

fn uint? ByteReader.u32(&self)
{
	if (self.remaining() < 4) return mqtt::INCOMPLETE~;
	uint v;
	for (usz i = 0; i < 4; i++) v = v << 8 | (uint)self.data[self.pos + i];
	self.pos += 4;
	return v;
}

// Variable Byte Integer; faults as vbi_decode.
fn uint? ByteReader.vbi(&self)
{
	usz used;
	uint v = vbi_decode(self.data[self.pos..], &used)!;
	self.pos += used;
	return v;
}

// n raw bytes, borrowed from the input.
fn char[]? ByteReader.take(&self, usz n)
{
	if (self.remaining() < n) return mqtt::INCOMPLETE~;
	char[] r = self.data[self.pos:n];
	self.pos += n;
	return r;
}

// u16 length prefix and raw bytes (binary data); the slice points into the input.
fn char[]? ByteReader.binary(&self)
{
	if (self.remaining() < 2) return mqtt::INCOMPLETE~;
	usz n = (usz)((ushort)self.data[self.pos] << 8 | (ushort)self.data[self.pos + 1]);
	if (self.remaining() < 2 + n) return mqtt::INCOMPLETE~;
	self.pos += 2;
	return self.take(n);
}

// u16 length prefix and a validated UTF-8 string; the slice points into the input. On a fault
// nothing is consumed.
fn String? ByteReader.string(&self)
{
	usz start = self.pos;
	char[] b = self.binary()!;
	String s = (String)b;
	if (catch err = validate_utf8(s))
	{
		self.pos = start;
		return err~;
	}
	return s;
}

fn char[] ByteReader.rest(&self) => self.data[self.pos..];

// Cursor over a caller owned output buffer. Fails with BUFFER_TOO_SMALL, never grows. A failed
// call writes nothing.
struct ByteWriter
{
	char[] buf;
	usz pos;
}

fn ByteWriter writer(char[] buf) => { .buf = buf };

fn usz ByteWriter.remaining(&self) => self.buf.len - self.pos;

fn void? ByteWriter.u8(&self, char v)
{
	if (self.remaining() < 1) return mqtt::BUFFER_TOO_SMALL~;
	self.buf[self.pos++] = v;
}

fn void? ByteWriter.u16(&self, ushort v)
{
	if (self.remaining() < 2) return mqtt::BUFFER_TOO_SMALL~;
	self.buf[self.pos] = (char)(v >> 8);
	self.buf[self.pos + 1] = (char)(v & 0xFF);
	self.pos += 2;
}

fn void? ByteWriter.u32(&self, uint v)
{
	if (self.remaining() < 4) return mqtt::BUFFER_TOO_SMALL~;
	for (usz i = 0; i < 4; i++) self.buf[self.pos + i] = (char)(v >> (24 - 8 * i));
	self.pos += 4;
}

// Variable Byte Integer; faults as vbi_encode.
fn void? ByteWriter.vbi(&self, uint v)
{
	usz n = vbi_encode(v, self.buf[self.pos..])!;
	self.pos += n;
}

fn void? ByteWriter.raw(&self, char[] b)
{
	if (self.remaining() < b.len) return mqtt::BUFFER_TOO_SMALL~;
	self.buf[self.pos:b.len] = b[..];
	self.pos += b.len;
}

// u16 length prefix and raw bytes. INVALID_ARGUMENT above 65535 bytes.
fn void? ByteWriter.binary(&self, char[] b)
{
	if (b.len > mqtt::MAX_STRING_LENGTH) return mqtt::INVALID_ARGUMENT~;
	if (self.remaining() < 2 + b.len) return mqtt::BUFFER_TOO_SMALL~;
	self.u16((ushort)b.len)!;
	self.raw(b)!;
}

// u16 length prefix and a validated UTF-8 string (INVALID_UTF8 when invalid or too long).
fn void? ByteWriter.string(&self, String s)
{
	validate_utf8(s)!;
	self.binary((char[])s)!;
}

fn char[] ByteWriter.written(&self) => self.buf[:self.pos];
