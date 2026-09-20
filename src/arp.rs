//! Real ARP (RFC 826) packet construction and parsing, framed inside a
//! real Ethernet II header. Pure byte-level logic — no socket access
//! here, so it's fully testable without any privilege at all. The
//! actual raw `AF_PACKET` socket send/receive lives in `main.rs`.

pub const ETHERTYPE_ARP: u16 = 0x0806;
const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

pub type Mac = [u8; 6];
pub type Ipv4 = [u8; 4];

pub const BROADCAST_MAC: Mac = [0xff; 6];
const ZERO_MAC: Mac = [0; 6];

/// Builds a complete Ethernet II + ARP "who has `target_ip`" request
/// frame, broadcast to `ff:ff:ff:ff:ff:ff`, from `src_mac`/`src_ip`.
pub fn build_arp_request(src_mac: Mac, src_ip: Ipv4, target_ip: Ipv4) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&BROADCAST_MAC);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    frame.extend_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
    frame.push(6); // hardware address length
    frame.push(4); // protocol address length
    frame.extend_from_slice(&OP_REQUEST.to_be_bytes());
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&ZERO_MAC);
    frame.extend_from_slice(&target_ip);

    frame
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpReply {
    pub sender_mac: Mac,
    pub sender_ip: Ipv4,
}

/// Parses a received Ethernet frame and returns the sender's MAC/IP if
/// (and only if) it's a real ARP *reply* — requests and non-ARP traffic
/// (which a raw socket also receives, since it sees everything on the
/// wire) are correctly ignored, not misread.
pub fn parse_arp_reply(frame: &[u8]) -> Option<ArpReply> {
    if frame.len() < 42 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    let arp = &frame[14..42];
    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != 6 || plen != 4 || op != OP_REPLY {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&arp[8..14]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&arp[14..18]);
    Some(ArpReply {
        sender_mac,
        sender_ip,
    })
}

/// Every host address in `network`/`prefix_len` (IPv4 CIDR), excluding
/// the network and broadcast addresses — the actual set of addresses
/// worth ARPing for.
pub fn host_addresses(network: Ipv4, prefix_len: u8) -> Vec<Ipv4> {
    if !(0..=30).contains(&prefix_len) {
        return Vec::new(); // /31 and /32 have no usable "host range" to enumerate
    }
    let base = u32::from_be_bytes(network);
    let host_bits = 32 - prefix_len as u32;
    let mask = if host_bits == 32 {
        0
    } else {
        !0u32 << host_bits
    };
    let network_addr = base & mask;
    let broadcast_addr = network_addr | !mask;
    (network_addr + 1..broadcast_addr)
        .map(|a| a.to_be_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const SRC_IP: Ipv4 = [192, 168, 1, 10];
    const TARGET_IP: Ipv4 = [192, 168, 1, 20];

    #[test]
    fn request_frame_is_exactly_42_bytes() {
        assert_eq!(build_arp_request(SRC_MAC, SRC_IP, TARGET_IP).len(), 42);
    }

    #[test]
    fn request_frame_broadcasts_to_ff_ff_ff_ff_ff_ff() {
        let frame = build_arp_request(SRC_MAC, SRC_IP, TARGET_IP);
        assert_eq!(&frame[0..6], &BROADCAST_MAC);
    }

    #[test]
    fn request_frame_has_the_arp_ethertype() {
        let frame = build_arp_request(SRC_MAC, SRC_IP, TARGET_IP);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);
    }

    #[test]
    fn request_frame_carries_the_real_target_ip_at_the_documented_offset() {
        let frame = build_arp_request(SRC_MAC, SRC_IP, TARGET_IP);
        assert_eq!(&frame[38..42], &TARGET_IP);
    }

    #[test]
    fn request_frame_target_mac_field_is_all_zero() {
        let frame = build_arp_request(SRC_MAC, SRC_IP, TARGET_IP);
        assert_eq!(&frame[32..38], &ZERO_MAC);
    }

    fn build_reply(sender_mac: Mac, sender_ip: Ipv4) -> Vec<u8> {
        let mut frame = Vec::with_capacity(42);
        frame.extend_from_slice(&SRC_MAC); // dest = us
        frame.extend_from_slice(&sender_mac); // src = the replying host
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&OP_REPLY.to_be_bytes());
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&sender_ip);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&SRC_IP);
        frame
    }

    #[test]
    fn parses_a_real_shaped_arp_reply() {
        let reply_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let frame = build_reply(reply_mac, TARGET_IP);
        let parsed = parse_arp_reply(&frame).unwrap();
        assert_eq!(parsed.sender_mac, reply_mac);
        assert_eq!(parsed.sender_ip, TARGET_IP);
    }

    #[test]
    fn ignores_a_request_frame_not_a_reply() {
        let request = build_arp_request(SRC_MAC, SRC_IP, TARGET_IP);
        assert!(parse_arp_reply(&request).is_none());
    }

    #[test]
    fn ignores_a_non_arp_ethertype() {
        let mut frame = build_reply([1; 6], TARGET_IP);
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4, not ARP
        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn ignores_a_truncated_frame_without_panicking() {
        assert!(parse_arp_reply(&[0u8; 10]).is_none());
    }

    #[test]
    fn host_addresses_excludes_network_and_broadcast() {
        let hosts = host_addresses([192, 168, 1, 0], 29); // .0/29 -> usable .1-.6
        assert_eq!(hosts.first(), Some(&[192, 168, 1, 1]));
        assert_eq!(hosts.last(), Some(&[192, 168, 1, 6]));
        assert_eq!(hosts.len(), 6);
    }

    #[test]
    fn host_addresses_for_a_slash_24_has_254_hosts() {
        assert_eq!(host_addresses([10, 0, 0, 0], 24).len(), 254);
    }

    #[test]
    fn host_addresses_for_slash_31_and_slash_32_is_empty() {
        assert!(host_addresses([10, 0, 0, 0], 31).is_empty());
        assert!(host_addresses([10, 0, 0, 0], 32).is_empty());
    }
}
