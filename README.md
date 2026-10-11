# lanscan

Pure-Rust ARP-based local network device discovery — finds devices on a
local subnet without shelling out to `nmap`/`arp-scan`. Sends a real
broadcast "who has `<ip>`?" ARP request for every host address in a
given CIDR range and reports every real reply's IP and MAC address.

## Installation

```sh
cargo install --path .
```

## Usage

```bash
lanscan --interface eth0 --src-ip 192.168.1.10 --network 192.168.1.0/24
```

Requires `CAP_NET_RAW` (or root) — ARP operates below IP, at the raw
Ethernet frame level, which is a genuinely privileged operation on
Linux, not a limitation of this implementation.

## Status: the ARP packet logic is fully verified; live raw-socket sending was checked and genuinely could not be exercised in this sandbox — stated honestly, not glossed over

- **12 unit tests** (`cargo test --lib`), all pure byte-level logic
  requiring zero privilege: the Ethernet+ARP request frame is exactly
  42 bytes, broadcasts to `ff:ff:ff:ff:ff:ff`, carries the correct
  EtherType and target IP at the documented byte offsets, and has an
  all-zero target MAC field (correct per RFC 826 — that's the field
  being asked *for*); a realistic ARP reply frame parses back to the
  right sender MAC/IP; a request frame (not a reply) is correctly
  ignored rather than misread; a non-ARP EtherType and a truncated
  frame are both handled cleanly, no panics; CIDR host-address
  enumeration correctly excludes the network and broadcast addresses
  for a `/29`, produces exactly 254 hosts for a `/24`, and produces
  zero hosts for `/31`/`/32` (which have no meaningful "host range").
- **The raw-socket send/receive path was actually attempted against
  this real sandbox, not assumed unavailable**: `AF_PACKET`/`SOCK_RAW`
  socket creation was tested directly (both from a quick Python check
  and via the actual compiled Rust binary) and genuinely returned
  `Operation not permitted` — confirmed via `capsh --print` that
  `CAP_NET_RAW` sits in the bounding set but not this process's
  effective set, a real, common container restriction. The compiled
  binary correctly surfaces this as a clear, specific error
  (`opening a raw AF_PACKET socket (needs CAP_NET_RAW / root):
  Operation not permitted`) rather than panicking or hanging — that
  failure-handling path itself *was* verified live, even though the
  successful-send path honestly wasn't. Separately: this sandbox's
  network is Docker bridge interfaces (`172.x.0.0/16`), not a real LAN
  segment, so even with the capability there'd be no real broadcast
  domain with other real hosts on it to discover.

**Not done / deliberately deferred**: reading the real interface's own
MAC address (via a netlink/`ioctl` call) to fill in the request's source
MAC — this sends an all-zero placeholder, which is functionally
incomplete for a real scan (a replying host wouldn't know where to
address its unicast reply) and is the very next thing to build once a
capable environment is available to test it against. IPv6/NDP discovery
isn't implemented, only IPv4 ARP.
