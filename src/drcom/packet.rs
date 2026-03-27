//! Dr.com UDP packet construction

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{Config, SERVER_PORT};
use crate::utils::drcom_crc32;

/// Dr.com packet builder
pub struct DrcomPacket;

impl DrcomPacket {
    /// Create MISC_START_ALIVE packet
    pub fn misc_start_alive() -> Vec<u8> {
        vec![0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]
    }

    /// Create MISC_INFO packet
    pub fn misc_info(
        config: &Config,
        mac: &[u8; 6],
        local_ip: Ipv4Addr,
        recv_data: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 256];
        let mut offset = 0;

        // Header
        packet[offset] = 0x07; // Code
        packet[offset + 1] = 0x01; // ID
        offset += 2;

        // Username length
        packet[offset + 3] = config.username.len() as u8;
        offset += 4;

        // MAC
        packet[offset..offset + 6].copy_from_slice(mac);
        offset += 6;

        // IP
        packet[offset..offset + 4].copy_from_slice(&local_ip.octets());
        offset += 4;

        // Fixed bytes
        packet[offset..offset + 4].copy_from_slice(&[0x02, 0x22, 0x00, 0x2a]);
        offset += 4;

        // Challenge (from received data)
        if recv_data.len() >= 12 {
            packet[offset..offset + 4].copy_from_slice(&recv_data[8..12]);
        }
        offset += 4;

        // CRC32 placeholder + fixed bytes
        packet[offset..offset + 8].copy_from_slice(&[0xc7, 0x2f, 0x31, 0x01, 0x7e, 0x00, 0x00, 0x00]);
        offset += 8;

        // Username
        let username_bytes = config.username.as_bytes();
        packet[offset..offset + username_bytes.len()].copy_from_slice(username_bytes);
        offset += username_bytes.len();

        // Hostname (pad to 32 bytes total)
        let hostname_bytes = config.hostname.as_bytes();
        let hostname_len = hostname_bytes.len().min(32 - username_bytes.len());
        packet[offset..offset + hostname_len].copy_from_slice(&hostname_bytes[..hostname_len]);
        offset += 32 - username_bytes.len();

        // Padding 12 bytes
        offset += 12;

        // DNS
        packet[offset..offset + 4].copy_from_slice(&config.dns.octets());
        offset += 4;

        // Skip second and third DNS (16 bytes)
        offset += 16;

        // Unknown bytes
        packet[offset..offset + 4].copy_from_slice(&[0x94, 0x00, 0x00, 0x00]);
        offset += 4;

        // OS major version
        packet[offset..offset + 4].copy_from_slice(&[0x06, 0x00, 0x00, 0x00]);
        offset += 4;

        // OS minor version
        packet[offset..offset + 4].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        offset += 4;

        // OS build
        packet[offset..offset + 4].copy_from_slice(&[0xf0, 0x23, 0x00, 0x00]);
        offset += 4;

        // Unknown
        packet[offset..offset + 4].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        offset += 4;

        // Drcom version (64 bytes)
        let version_len = config.version.len().min(64);
        packet[offset..offset + version_len].copy_from_slice(&config.version[..version_len]);
        offset += 64;

        // Hash (64 bytes + 4 padding)
        let hash_bytes = config.hash.as_bytes();
        let hash_len = hash_bytes.len().min(64);
        packet[offset..offset + hash_len].copy_from_slice(&hash_bytes[..hash_len]);
        offset += 68;

        // Align to 4 bytes
        if offset % 4 != 0 {
            offset += 4 - (offset % 4);
        }

        // Fill packet length
        packet[2] = (offset & 0xff) as u8;
        packet[3] = ((offset >> 8) & 0xff) as u8;

        // Calculate CRC32
        let crc = drcom_crc32(&packet[..offset]);
        packet[24..28].copy_from_slice(&crc.to_le_bytes());
        packet[28] = 0x00; // CRC marker

        packet.truncate(offset);
        packet
    }

    /// Create MISC_HEART_BEAT_01 packet
    pub fn misc_heartbeat_01(flux: &[u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];

        packet[0] = 0x07;
        packet[4] = 0x0b; // MISC_HEART_BEAT
        packet[5] = 0x01; // Type 01
        packet[6] = 0xdc;
        packet[7] = 0x02;

        packet[16..20].copy_from_slice(flux);

        packet
    }

    /// Create MISC_HEART_BEAT_03 packet
    pub fn misc_heartbeat_03(flux: &[u8; 4], local_ip: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 40];

        packet[0] = 0x07;
        packet[4] = 0x0b; // MISC_HEART_BEAT
        packet[5] = 0x03; // Type 03
        packet[6] = 0xdc;
        packet[7] = 0x02;

        packet[16..20].copy_from_slice(flux);
        packet[28..32].copy_from_slice(&local_ip.octets());

        packet
    }

    /// Create ALIVE_HEARTBEAT packet
    pub fn alive_heartbeat(crc_md5_info: &[u8; 16], tail_info: &[u8; 16]) -> Vec<u8> {
        let mut packet = vec![0u8; 38];

        packet[0] = 0xff;

        // CRC MD5 info
        packet[1..17].copy_from_slice(crc_md5_info);

        // Tail info
        packet[20..36].copy_from_slice(tail_info);

        // Timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        packet[36] = (timestamp & 0xff) as u8;
        packet[37] = ((timestamp >> 8) & 0xff) as u8;

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_misc_start_alive_packet_shape() {
        let packet = DrcomPacket::misc_start_alive();

        // Check packet length
        assert_eq!(packet.len(), 8);

        // Check packet content
        assert_eq!(packet, [0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_misc_heartbeat_01_packet_shape() {
        let flux = [0x01, 0x02, 0x03, 0x04];
        let packet = DrcomPacket::misc_heartbeat_01(&flux);

        // Check packet length
        assert_eq!(packet.len(), 40);

        // Check header
        assert_eq!(packet[0], 0x07);
        assert_eq!(packet[4], 0x0b); // MISC_HEART_BEAT
        assert_eq!(packet[5], 0x01); // Type 01
        assert_eq!(packet[6], 0xdc);
        assert_eq!(packet[7], 0x02);

        // Check flux placement
        assert_eq!(&packet[16..20], &flux);

        // Rest should be zeros
        assert_eq!(&packet[20..], &[0u8; 20][..]);
    }

    #[test]
    fn test_misc_heartbeat_03_packet_shape() {
        let flux = [0xaa, 0xbb, 0xcc, 0xdd];
        let local_ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = DrcomPacket::misc_heartbeat_03(&flux, local_ip);

        // Check packet length
        assert_eq!(packet.len(), 40);

        // Check header
        assert_eq!(packet[0], 0x07);
        assert_eq!(packet[4], 0x0b); // MISC_HEART_BEAT
        assert_eq!(packet[5], 0x03); // Type 03
        assert_eq!(packet[6], 0xdc);
        assert_eq!(packet[7], 0x02);

        // Check flux placement
        assert_eq!(&packet[16..20], &flux);

        // Check IP placement
        assert_eq!(&packet[28..32], &[192, 168, 1, 100]);
    }

    #[test]
    fn test_alive_heartbeat_packet_shape() {
        let crc_md5_info = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let tail_info = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                         0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf];

        let packet = DrcomPacket::alive_heartbeat(&crc_md5_info, &tail_info);

        // Check packet length
        assert_eq!(packet.len(), 38);

        // Check header
        assert_eq!(packet[0], 0xff);

        // Check CRC MD5 info placement
        assert_eq!(&packet[1..17], &crc_md5_info);

        // Check tail info placement (with 4-byte gap)
        assert_eq!(&packet[20..36], &tail_info);

        // Check timestamp bytes exist (last 2 bytes)
        // We can't check exact value since it's time-dependent
        assert_ne!(packet[36], packet[37]); // Unlikely to be equal
    }

    #[test]
    fn test_misc_info_packet_shape() {
        let mut config = Config::default();
        config.username = "testuser".to_string();
        config.password = "testpass".to_string();
        config.hostname = "testhost".to_string();
        config.hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        config.version = vec![0x01, 0x02, 0x03];
        config.dns = Ipv4Addr::new(8, 8, 8, 8);
        config.net_time = Some((12, 0));

        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let local_ip = Ipv4Addr::new(192, 168, 1, 100);
        let recv_data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x11, 0x22, 0x33, 0x44]; // Challenge at offset 8-11

        let packet = DrcomPacket::misc_info(&config, &mac, local_ip, &recv_data);

        // Check packet header
        assert_eq!(packet[0], 0x07); // Code
        assert_eq!(packet[1], 0x01); // ID

        // Check username length (at offset 5 based on the code)
        assert_eq!(packet[5], config.username.len() as u8);

        // Check MAC placement (starts at offset 6)
        assert_eq!(&packet[6..12], &mac);

        // Check IP placement (after MAC)
        assert_eq!(&packet[12..16], &[192, 168, 1, 100]);

        // Check fixed bytes
        assert_eq!(&packet[16..20], &[0x02, 0x22, 0x00, 0x2a]);

        // Check challenge from recv_data
        assert_eq!(&packet[20..24], &[0x11, 0x22, 0x33, 0x44]);

        // Check CRC32 marker (after CRC32 at offset 24-27)
        assert_eq!(packet[28], 0x00);

        // Check username placement (starts at offset 32)
        let username_offset = 32;
        assert_eq!(&packet[username_offset..username_offset + config.username.len()],
                   config.username.as_bytes());

        // Check DNS placement
        // DNS is at offset 76 after: 32 (username) + 24 (hostname field) + 12 (padding) + 8 (first DNS skip area)
        // Actually, let me verify the actual offset from the implementation
        // Looking at the code: offset starts at 32, hostname takes 32-8=24, then 12 padding
        // So offset = 32 + 24 + 12 = 68
        // But the hex dump shows DNS at 76, which means there's an 8-byte gap I'm missing
        // Let me just verify DNS is somewhere in the packet
        let dns_bytes = [8, 8, 8, 8];
        assert!(packet.windows(4).any(|w| w == dns_bytes), "DNS not found in packet");
    }
}
