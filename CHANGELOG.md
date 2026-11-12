# Changelog

## 0.1.0

First version.

- MQTT 3.1.1 and 5.0 client in one library: codec, topic validation and matching, a sans-IO core with sessions, QoS 0/1/2, keep
  alive, flow control, topic aliases, enhanced authentication through a hook and server redirects, and a blocking client over a
  `Transport` with a TCP transport.
- `mqttc`, a command line `pub` and `sub`.
- `itest` and `tools/peer.py`: scenarios against a live broker (run against the Paho interoperability broker).
- Known gaps are listed in the README.
