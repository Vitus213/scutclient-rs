//! MD5 utility functions

/// Fill MD5 digest area for EAP MD5 challenge
/// digest = MD5(id + password + src_md5)
pub fn fill_md5_area(id: u8, password: &[u8], src_md5: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(1 + password.len() + src_md5.len());
    data.push(id);
    data.extend_from_slice(password);
    data.extend_from_slice(src_md5);

    md5::compute(data).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_md5_area() {
        // Test with known input and expected output
        let id = 0x01;
        let password = b"password";
        let src_md5 = [0u8; 16];

        let digest = fill_md5_area(id, password, &src_md5);
        assert_eq!(digest.len(), 16);

        // Assert exact digest for known inputs
        // MD5(0x01 + "password" + [0; 16]) should produce this specific digest
        let expected = [0xae, 0x88, 0xb6, 0xc2, 0xfe, 0x68, 0xbc, 0x92, 0x3a, 0xe9, 0x94, 0xf6, 0x52, 0x50, 0x8d, 0x12];
        assert_eq!(digest, expected, "MD5 digest mismatch");
    }

    #[test]
    fn test_fill_md5_area_different_inputs() {
        // Test with different inputs to ensure correctness
        let id = 0x02;
        let password = b"test123";
        let src_md5 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];

        let digest = fill_md5_area(id, password, &src_md5);
        assert_eq!(digest.len(), 16);

        // Verify it produces a different digest for different inputs
        let digest2 = fill_md5_area(0x03, b"different", &src_md5);
        assert_ne!(digest, digest2);
    }
}
