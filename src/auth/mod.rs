//! 802.1X EAPOL authentication module

mod eap;
mod eapol;
mod socket;

pub use eap::{EapCode, EapType};
pub use eapol::EapolPacket;
pub use socket::AuthSocket;

use std::io;
use std::net::Ipv4Addr;

use crate::config::{Config, IfaceInfo, AUTH_8021X_RECV_DELAY, AUTH_8021X_RECV_TIMES};
use crate::drcom::DrcomPacket;
use crate::utils::fill_md5_area;

/// Broadcast MAC address
pub const BROADCAST_ADDR: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
/// Multicast MAC address (standard 802.1X)
pub const MULTICAST_ADDR: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03];
/// Unicast MAC address (Ruijie switch)
pub const UNICAST_ADDR: [u8; 6] = [0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03];

/// EAPOL Ethernet type
pub const ETH_P_PAE: u16 = 0x888e;

/// Authentication state
pub struct AuthState {
    /// Socket for 802.1X communication
    socket: AuthSocket,
    /// Interface information
    iface_info: IfaceInfo,
    /// Server MAC address (learned from first packet)
    server_mac: [u8; 6],
    /// Current retry times
    retry_times: i32,
    /// 802.1X success flag
    success: bool,
}

impl AuthState {
    /// Create new authentication state
    pub fn new(config: &Config) -> io::Result<Self> {
        let socket = AuthSocket::new(&config.iface)?;
        let iface_info = socket.get_iface_info()?;

        Ok(Self {
            socket,
            iface_info,
            server_mac: [0u8; 6],
            retry_times: AUTH_8021X_RECV_TIMES,
            success: false,
        })
    }

    /// Get interface information
    pub fn iface_info(&self) -> &IfaceInfo {
        &self.iface_info
    }

    /// Send EAPOL Start packet
    pub fn send_start(&mut self, dest_mac: &[u8; 6]) -> io::Result<()> {
        let packet = EapolPacket::start(&self.iface_info.mac, dest_mac);
        self.socket.send(&packet)?;
        log::info!("Client: Send EAPOL Start to {:02x?}", dest_mac);
        Ok(())
    }

    /// Send EAPOL Logoff packet
    pub fn send_logoff(&mut self) -> io::Result<()> {
        let packet = EapolPacket::logoff(&self.iface_info.mac, &MULTICAST_ADDR);
        self.socket.send(&packet)?;
        log::info!("Client: Send Logoff.");
        Ok(())
    }

    /// Receive EAPOL packet
    pub fn recv(&mut self, timeout_ms: u64) -> io::Result<Option<Vec<u8>>> {
        self.socket.recv(timeout_ms)
    }

    /// Handle received EAP packet
    ///
    /// This is a pure state machine function that only updates internal state.
    /// Side effects like hooks and UDP communication should be handled by the caller
    /// based on the returned EapResult.
    pub fn handle_eap_packet(
        &mut self,
        data: &[u8],
        config: &Config,
    ) -> io::Result<EapResult> {
        if data.len() < 23 {
            return Ok(EapResult::Continue);
        }

        let eap_code = EapCode::from(data[18]);
        let eap_id = data[19];
        let eap_type = EapType::from(data[22]);

        match eap_code {
            EapCode::Request => {
                match eap_type {
                    EapType::Identity => {
                        log::info!("Server: Request Identity.");
                        // Learn server MAC
                        self.server_mac.copy_from_slice(&data[6..12]);

                        let response = EapolPacket::response_identity(
                            &self.iface_info.mac,
                            &self.server_mac,
                            eap_id,
                            &config.username,
                            &self.iface_info.ip,
                        );
                        self.socket.send(&response)?;
                        log::info!("Client: Response Identity.");
                    }
                    EapType::MD5 => {
                        log::info!("Server: Request MD5-Challenge.");
                        let challenge = &data[24..40];
                        let md5_digest = fill_md5_area(eap_id, config.password.as_bytes(), challenge);

                        let response = EapolPacket::response_md5(
                            &self.iface_info.mac,
                            &self.server_mac,
                            eap_id,
                            &md5_digest,
                            &config.username,
                            &self.iface_info.ip,
                        );
                        self.socket.send(&response)?;
                        log::info!("Client: Response MD5-Challenge.");
                    }
                    EapType::Notification => {
                        let msg_len = u16::from_be_bytes([data[20], data[21]]) as usize - 5;
                        if data.len() >= 23 + msg_len {
                            let msg = String::from_utf8_lossy(&data[23..23 + msg_len]);
                            if let Some(err) = parse_eap_error(&msg) {
                                log::error!("Server: Authentication failed: {}", err);
                                return Ok(EapResult::Failed(err.to_string()));
                            } else {
                                log::info!("Server: Notification: {}", msg);
                            }
                        }
                    }
                    _ => {
                        log::warn!("Server: Unknown EAP type: {:?}", eap_type);
                    }
                }
            }
            EapCode::Success => {
                log::info!("Server: Success.");
                self.success = true;
                self.retry_times = AUTH_8021X_RECV_TIMES;

                // Return Success result - caller will handle hooks and UDP
                return Ok(EapResult::Success);
            }
            EapCode::Failure => {
                log::error!("Server: Failure.");
                self.success = false;

                if self.retry_times > 0 {
                    self.retry_times -= 1;
                    return Ok(EapResult::Retry);
                } else {
                    return Ok(EapResult::Failed("Reconnection failed.".to_string()));
                }
            }
            _ => {
                log::warn!("Server: Unknown EAP code: {:?}", eap_code);
            }
        }

        Ok(EapResult::Continue)
    }

    /// Get server MAC
    pub fn server_mac(&self) -> &[u8; 6] {
        &self.server_mac
    }

    /// Check if authentication succeeded
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Set success flag
    pub fn set_success(&mut self, success: bool) {
        self.success = success;
    }

    /// Get socket file descriptor
    pub fn fd(&self) -> libc::c_int {
        self.socket.fd()
    }

    /// Non-blocking receive packet
    pub fn recv_ready(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.socket.recv_ready()
    }
}

/// Result of EAP handling
#[derive(Debug)]
pub enum EapResult {
    Continue,
    Success,
    Retry,
    Failed(String),
}

/// Parse EAP error message
pub fn parse_eap_error(msg: &str) -> Option<&str> {
    if msg.starts_with("userid error") {
        let errcode: i32 = msg.strip_prefix("userid error")?.parse().ok()?;
        match errcode {
            1 => Some("Account does not exist."),
            2 | 3 => Some("Username or password invalid."),
            4 => Some("This account might be expended."),
            _ => None,
        }
    } else if msg.starts_with("Authentication Fail") {
        let errcode: i32 = msg
            .strip_prefix("Authentication Fail ErrCode=")?
            .parse()
            .ok()?;
        match errcode {
            0 => Some("Username or password invalid."),
            5 => Some("This account is suspended."),
            9 => Some("This account might be expended."),
            11 => Some("You are not allowed to perform a radius authentication."),
            16 => Some("You are not allowed to access the internet now."),
            30 | 63 => Some("No more time available for this account."),
            _ => None,
        }
    } else if msg.contains("Mac, IP, NASip, PORT") {
        Some("You are not allowed to login using current IP/MAC address.")
    } else if msg.contains("flowover") {
        Some("Data usage has reached the limit.")
    } else if msg.contains("In use") {
        Some("This account is in use.")
    } else if msg.starts_with("AdminReset") {
        Some(msg)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eap_error_maps_known_messages() {
        assert_eq!(
            parse_eap_error("userid error2"),
            Some("Username or password invalid.")
        );
        assert_eq!(
            parse_eap_error("Authentication Fail ErrCode=16"),
            Some("You are not allowed to access the internet now.")
        );
        assert_eq!(
            parse_eap_error("userid error1"),
            Some("Account does not exist.")
        );
        assert_eq!(
            parse_eap_error("Authentication Fail ErrCode=5"),
            Some("This account is suspended.")
        );
    }

    #[test]
    fn auth_success_result_is_observable_by_main_loop() {
        let result = EapResult::Success;
        assert!(matches!(result, EapResult::Success));
    }

    #[test]
    fn auth_failed_result_contains_message() {
        let result = EapResult::Failed("test error".to_string());
        assert!(matches!(result, EapResult::Failed(_)));
        if let EapResult::Failed(msg) = result {
            assert_eq!(msg, "test error");
        }
    }
}
