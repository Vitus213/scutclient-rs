//! EAPOL packet construction

use std::net::Ipv4Addr;

/// EAPOL packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolType {
    Packet = 0x00,
    Start = 0x01,
    Logoff = 0x02,
    Key = 0x03,
    AsfAlert = 0x04,
}

/// EAPOL packet builder
pub struct EapolPacket;

impl EapolPacket {
    /// Create EAPOL Start packet
    pub fn start(src_mac: &[u8; 6], dest_mac: &[u8; 6]) -> Vec<u8> {
        let mut packet = vec![0u8; 96];

        // Ethernet header (14 bytes)
        packet[0..6].copy_from_slice(dest_mac);
        packet[6..12].copy_from_slice(src_mac);
        packet[12..14].copy_from_slice(&[0x88, 0x8e]); // ETH_P_PAE

        // EAPOL header (4 bytes)
        packet[14] = 0x01; // Version
        packet[15] = EapolType::Start as u8;
        packet[16] = 0x00; // Length
        packet[17] = 0x00;

        packet
    }

    /// Create EAPOL Logoff packet
    pub fn logoff(src_mac: &[u8; 6], dest_mac: &[u8; 6]) -> Vec<u8> {
        let mut packet = vec![0xa5u8; 96];

        // Ethernet header (14 bytes)
        packet[0..6].copy_from_slice(dest_mac);
        packet[6..12].copy_from_slice(src_mac);
        packet[12..14].copy_from_slice(&[0x88, 0x8e]);

        // EAPOL header
        packet[14] = 0x01; // Version
        packet[15] = EapolType::Logoff as u8;
        packet[16] = 0x00;
        packet[17] = 0x00;

        packet
    }

    /// Create Response Identity packet
    pub fn response_identity(
        src_mac: &[u8; 6],
        dest_mac: &[u8; 6],
        eap_id: u8,
        username: &str,
        ip: &Ipv4Addr,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 96];

        // Ethernet header
        packet[0..6].copy_from_slice(dest_mac);
        packet[6..12].copy_from_slice(src_mac);
        packet[12..14].copy_from_slice(&[0x88, 0x8e]);

        // EAPOL header
        packet[14] = 0x01; // Version
        packet[15] = 0x00; // Type: EAP Packet

        // EAP header
        packet[18] = 0x02; // Code: Response
        packet[19] = eap_id; // ID
        packet[22] = 0x01; // Type: Identity

        // Data: username + marker + IP
        let mut offset = 23;
        let username_bytes = username.as_bytes();
        packet[offset..offset + username_bytes.len()].copy_from_slice(username_bytes);
        offset += username_bytes.len();

        packet[offset] = 0x00;
        packet[offset + 1] = 0x44;
        packet[offset + 2] = 0x61;
        packet[offset + 3] = 0x00;
        packet[offset + 4] = 0x00;
        offset += 5;

        packet[offset..offset + 4].copy_from_slice(&ip.octets());
        offset += 4;

        // Fill length fields
        let eap_len = (username.len() + 14) as u16;
        packet[16..18].copy_from_slice(&eap_len.to_be_bytes());
        packet[20..22].copy_from_slice(&eap_len.to_be_bytes());

        packet
    }

    /// Create Response MD5 packet
    pub fn response_md5(
        src_mac: &[u8; 6],
        dest_mac: &[u8; 6],
        eap_id: u8,
        md5_value: &[u8; 16],
        username: &str,
        ip: &Ipv4Addr,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 96];

        // Ethernet header
        packet[0..6].copy_from_slice(dest_mac);
        packet[6..12].copy_from_slice(src_mac);
        packet[12..14].copy_from_slice(&[0x88, 0x8e]);

        // EAPOL header
        packet[14] = 0x01;
        packet[15] = 0x00;

        // EAP header
        packet[18] = 0x02; // Code: Response
        packet[19] = eap_id;
        packet[22] = 0x04; // Type: MD5-Challenge
        packet[23] = 0x10; // Value-Size: 16

        // MD5 value
        packet[24..40].copy_from_slice(md5_value);

        // Username + marker + IP
        let mut offset = 40;
        let username_bytes = username.as_bytes();
        packet[offset..offset + username_bytes.len()].copy_from_slice(username_bytes);
        offset += username_bytes.len();

        packet[offset] = 0x00;
        packet[offset + 1] = 0x44;
        packet[offset + 2] = 0x61;
        packet[offset + 3] = 0x2a;
        packet[offset + 4] = 0x00;
        offset += 5;

        packet[offset..offset + 4].copy_from_slice(&ip.octets());

        // Fill length fields
        let eap_len = (username.len() + 31) as u16;
        packet[16..18].copy_from_slice(&eap_len.to_be_bytes());
        packet[20..22].copy_from_slice(&eap_len.to_be_bytes());

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eapol_start_packet_shape() {
        let src_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let dest_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        let packet = EapolPacket::start(&src_mac, &dest_mac);

        // Check packet length
        assert_eq!(packet.len(), 96);

        // Check Ethernet header
        assert_eq!(&packet[0..6], &dest_mac);
        assert_eq!(&packet[6..12], &src_mac);
        assert_eq!(&packet[12..14], &[0x88, 0x8e]);

        // Check EAPOL header
        assert_eq!(packet[14], 0x01); // Version
        assert_eq!(packet[15], 0x01); // Type: Start
        assert_eq!(&packet[16..18], &[0x00, 0x00]); // Length

        // Rest should be zeros
        assert_eq!(&packet[18..], &[0u8; 78][..]);
    }

    #[test]
    fn test_eapol_logoff_packet_shape() {
        let src_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let dest_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        let packet = EapolPacket::logoff(&src_mac, &dest_mac);

        // Check packet length
        assert_eq!(packet.len(), 96);

        // Check Ethernet header
        assert_eq!(&packet[0..6], &dest_mac);
        assert_eq!(&packet[6..12], &src_mac);
        assert_eq!(&packet[12..14], &[0x88, 0x8e]);

        // Check EAPOL header
        assert_eq!(packet[14], 0x01); // Version
        assert_eq!(packet[15], 0x02); // Type: Logoff
        assert_eq!(&packet[16..18], &[0x00, 0x00]); // Length

        // Rest should be 0xa5 padding
        assert_eq!(&packet[18..], &[0xa5u8; 78][..]);
    }

    #[test]
    fn test_eapol_response_identity_packet_shape() {
        let src_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let dest_mac = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let eap_id = 0x05;
        let username = "testuser";
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        let packet = EapolPacket::response_identity(&src_mac, &dest_mac, eap_id, username, &ip);

        // Check packet length
        assert_eq!(packet.len(), 96);

        // Check Ethernet header
        assert_eq!(&packet[0..6], dest_mac.as_slice());
        assert_eq!(&packet[6..12], src_mac.as_slice());
        assert_eq!(&packet[12..14], &[0x88, 0x8e]);

        // Check EAPOL header
        assert_eq!(packet[14], 0x01); // Version
        assert_eq!(packet[15], 0x00); // Type: EAP Packet

        // Check EAP header
        assert_eq!(packet[18], 0x02); // Code: Response
        assert_eq!(packet[19], eap_id); // ID
        assert_eq!(packet[22], 0x01); // Type: Identity

        // Check length fields
        let expected_len = (username.len() + 14) as u16;
        assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), expected_len);
        assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), expected_len);

        // Check username placement
        let username_offset = 23;
        assert_eq!(&packet[username_offset..username_offset + username.len()], username.as_bytes());

        // Check marker after username
        let marker_offset = username_offset + username.len();
        assert_eq!(&packet[marker_offset..marker_offset + 5], &[0x00, 0x44, 0x61, 0x00, 0x00]);

        // Check IP placement
        let ip_offset = marker_offset + 5;
        assert_eq!(&packet[ip_offset..ip_offset + 4], &[192, 168, 1, 100]);
    }

    #[test]
    fn test_eapol_response_md5_packet_shape() {
        let src_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let dest_mac = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let eap_id = 0x0a;
        let md5_value = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let username = "testuser";
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        let packet = EapolPacket::response_md5(&src_mac, &dest_mac, eap_id, &md5_value, username, &ip);

        // Check packet length
        assert_eq!(packet.len(), 96);

        // Check Ethernet header
        assert_eq!(&packet[0..6], dest_mac.as_slice());
        assert_eq!(&packet[6..12], src_mac.as_slice());
        assert_eq!(&packet[12..14], &[0x88, 0x8e]);

        // Check EAPOL header
        assert_eq!(packet[14], 0x01); // Version
        assert_eq!(packet[15], 0x00); // Type: EAP Packet

        // Check EAP header
        assert_eq!(packet[18], 0x02); // Code: Response
        assert_eq!(packet[19], eap_id); // ID
        assert_eq!(packet[22], 0x04); // Type: MD5-Challenge
        assert_eq!(packet[23], 0x10); // Value-Size: 16

        // Check MD5 value placement
        assert_eq!(&packet[24..40], &md5_value);

        // Check username placement
        let username_offset = 40;
        assert_eq!(&packet[username_offset..username_offset + username.len()], username.as_bytes());

        // Check marker after username
        let marker_offset = username_offset + username.len();
        assert_eq!(&packet[marker_offset..marker_offset + 5], &[0x00, 0x44, 0x61, 0x2a, 0x00]);

        // Check IP placement
        let ip_offset = marker_offset + 5;
        assert_eq!(&packet[ip_offset..ip_offset + 4], &[10, 0, 0, 1]);

        // Check length fields
        let expected_len = (username.len() + 31) as u16;
        assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), expected_len);
        assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), expected_len);
    }
}
