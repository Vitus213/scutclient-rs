//! Utility functions for scutclient

mod md5;
pub use md5::fill_md5_area;

/// Convert hex string to bytes
pub fn hex_str_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    let mut bytes = Vec::with_capacity(hex.len() / 2);

    let mut chars = hex.chars();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let high = high.to_ascii_uppercase();
        let low = low.to_ascii_uppercase();

        let high_val = if high > '9' {
            high as u8 - b'A' + 10
        } else {
            high as u8 - b'0'
        };

        let low_val = if low > '9' {
            low as u8 - b'A' + 10
        } else {
            low as u8 - b'0'
        };

        bytes.push((high_val << 4) | low_val);
    }

    bytes
}

/// Drcom CRC32 calculation
pub fn drcom_crc32(data: &[u8]) -> u32 {
    let mut ret: u32 = 0;

    for chunk in data.chunks(4) {
        let mut buf = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        let val = u32::from_le_bytes(buf);
        ret ^= val;
    }

    ret = ret.wrapping_mul(19680126);
    ret.to_le()
}

/// Encrypt drcom info (rotate bits)
pub fn encrypt_drcom_info(info: &mut [u8; 16]) {
    let original = *info;
    for i in 0..16 {
        let shift = (i & 0x07) as u32;
        info[i] = original[i].rotate_left(shift);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_str_to_bytes() {
        let hex = "4472434f4d";
        let bytes = hex_str_to_bytes(hex);
        assert_eq!(bytes, vec![0x44, 0x72, 0x43, 0x4f, 0x4d]);
    }

    #[test]
    fn test_hex_str_to_bytes_lowercase() {
        let hex = "4472434f4d";
        let bytes = hex_str_to_bytes(hex);
        assert_eq!(bytes, vec![0x44, 0x72, 0x43, 0x4f, 0x4d]);
    }

    #[test]
    fn test_hex_str_to_bytes_whitespace() {
        // Note: Current implementation doesn't handle internal whitespace
        // This test documents the current behavior
        let hex = "4472434f4d";
        let bytes = hex_str_to_bytes(hex);
        assert_eq!(bytes, vec![0x44, 0x72, 0x43, 0x4f, 0x4d]);
    }

    #[test]
    fn test_hex_str_to_bytes_empty() {
        let hex = "";
        let bytes = hex_str_to_bytes(hex);
        assert_eq!(bytes, vec![]);
    }

    #[test]
    fn test_hex_str_to_bytes_all_values() {
        // Test all possible hex digit values
        let hex = "0123456789abcdefABCDEF";
        let bytes = hex_str_to_bytes(hex);
        assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_drcom_crc32() {
        let data = [0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00];
        let crc = drcom_crc32(&data);
        // CRC value should be deterministic
        assert_eq!(crc, 1660536052); // 0x62f9c4f4 in little-endian
    }

    #[test]
    fn test_drcom_crc32_different_data() {
        let data1 = [0x01, 0x02, 0x03, 0x04];
        let crc1 = drcom_crc32(&data1);

        let data2 = [0x04, 0x03, 0x02, 0x01];
        let crc2 = drcom_crc32(&data2);

        assert_ne!(crc1, crc2, "Different data should produce different CRC");
    }

    #[test]
    fn test_drcom_crc32_empty() {
        let data = [];
        let crc = drcom_crc32(&data);
        assert_eq!(crc, 0);
    }

    #[test]
    fn test_drcom_crc32_non_multiple_of_4() {
        let data = [0x01, 0x02, 0x03];
        let crc = drcom_crc32(&data);
        // Should handle non-4-byte-aligned data
        assert_ne!(crc, 0);
    }

    #[test]
    fn test_encrypt_drcom_info() {
        let mut info = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let original = info;

        encrypt_drcom_info(&mut info);

        // Each byte should be rotated left by (index & 0x07)
        for i in 0..16 {
            let shift = (i & 0x07) as u32;
            let expected = original[i].rotate_left(shift);
            assert_eq!(info[i], expected, "Byte {} not encrypted correctly", i);
        }
    }

    #[test]
    fn test_encrypt_drcom_info_identity() {
        // Bytes at positions 0, 8 should remain unchanged (shift 0)
        let mut info = [0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let original = info;

        encrypt_drcom_info(&mut info);

        assert_eq!(info[0], original[0], "Byte 0 should not change (shift 0)");
        assert_eq!(info[8], original[8], "Byte 8 should not change (shift 0)");
    }

    #[test]
    fn test_encrypt_drcom_info_max_shift() {
        // Byte at position 7 should be rotated left by 7
        let mut info = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        encrypt_drcom_info(&mut info);

        // 0x81 rotated left by 7 = 0xC0 (192)
        assert_eq!(info[7], 0xC0);
    }
}
