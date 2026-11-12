module mqtt::transport;
import mqtt;
import std::time;

// Byte stream under the blocking client. One shape in every sibling library, so a type from
// another library (a TLS transport, a test double) can be passed in through an explicit interface
// cast. Faults: mqtt::TIMEOUT and mqtt::CLOSED.
//  - read waits at most `timeout` (zero = poll once) and returns 1..buf.len bytes. TIMEOUT means
//    nothing arrived and the link is still usable; CLOSED means the peer closed (EOF); any other
//    fault means a dead link. A layer that buffers decoded bytes returns them before it waits.
//  - write writes all of data or faults (TIMEOUT, CLOSED). After a fault the stream may hold a
//    partial packet, so the caller must treat it as fatal and close.
//  - close is idempotent.
//  - one reader and one writer at a time; no thread safety is promised.
interface Transport
{
	fn usz? read(char[] buf, Duration timeout);
	fn void? write(char[] data, Duration timeout);
	fn void? close();
}
