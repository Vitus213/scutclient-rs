//! Dr.com UDP protocol implementation

mod packet;
mod udp;

pub use packet::DrcomPacket;
pub use udp::UdpClient;

use std::io;

use crate::config::{Config, DRCOM_UDP_HEARTBEAT_DELAY, DRCOM_UDP_HEARTBEAT_TIMEOUT};
use crate::utils::{drcom_crc32, encrypt_drcom_info};

/// Dr.com UDP state
pub struct DrcomState {
    /// UDP client
    client: UdpClient,
    /// Package ID (incremented each packet)
    package_id: u8,
    /// CRC/MD5 info from EAP authentication
    crc_md5_info: [u8; 16],
    /// Tail info from MISC_RESPONSE_INFO
    tail_info: [u8; 16],
    /// Flux info for heartbeat type 01
    misc1_flux: [u8; 4],
    /// Flux info for heartbeat type 03
    misc3_flux: [u8; 4],
    /// Need heartbeat flag
    need_heartbeat: bool,
    /// Last heartbeat done flag
    last_heartbeat_done: bool,
    /// Base heartbeat time
    base_heartbeat_time: std::time::Instant,
}

impl DrcomState {
    /// Create new Dr.com state
    pub fn new(config: &Config, local_ip: std::net::Ipv4Addr) -> io::Result<Self> {
        let client = UdpClient::new(
            config.iface.as_str(),
            config.udp_server,
            local_ip,
        )?;

        Ok(Self {
            client,
            package_id: 0,
            crc_md5_info: [0u8; 16],
            tail_info: [0u8; 16],
            misc1_flux: [0u8; 4],
            misc3_flux: [0u8; 4],
            need_heartbeat: false,
            last_heartbeat_done: true,
            base_heartbeat_time: std::time::Instant::now(),
        })
    }

    /// Send packet
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.client.send(data)
    }

    /// Receive packet with timeout
    pub fn recv(&self, timeout_ms: u64) -> io::Result<Option<Vec<u8>>> {
        self.client.recv(timeout_ms)
    }

    /// Handle received UDP packet
    pub fn handle_packet(
        &mut self,
        data: &[u8],
        config: &Config,
        mac: &[u8; 6],
        local_ip: std::net::Ipv4Addr,
    ) -> io::Result<Option<Vec<u8>>> {
        if data.is_empty() {
            return Ok(None);
        }

        // Server information message (0x4d38)
        if data.len() >= 2 && data[0] == 0x4d && data[1] == 0x38 {
            if data.len() > 4 {
                let msg = String::from_utf8_lossy(&data[4..]);
                log::info!("Server: Server Information: {}", msg);
            }
            return Ok(None);
        }

        // Dr.com protocol packet (0x07)
        if data[0] != 0x07 {
            return Ok(None);
        }

        let drcom_type = data[4];

        match drcom_type {
            // MISC_RESPONSE_FOR_ALIVE (0x02)
            0x02 => {
                log::info!("Server: MISC_RESPONSE_FOR_ALIVE. Send MISC_INFO.");
                std::thread::sleep(std::time::Duration::from_secs(1));
                self.need_heartbeat = false;
                self.base_heartbeat_time = std::time::Instant::now();
                self.last_heartbeat_done = true;

                let response = DrcomPacket::misc_info(config, mac, local_ip, data);
                return Ok(Some(response));
            }
            // MISC_RESPONSE_INFO (0x04)
            0x04 => {
                log::info!("Server: MISC_RESPONSE_INFO. Send MISC_HEART_BEAT_01.");
                // Store and encrypt tail info
                if data.len() >= 32 {
                    self.tail_info.copy_from_slice(&data[16..32]);
                    encrypt_drcom_info(&mut self.tail_info);
                }

                let response = DrcomPacket::misc_heartbeat_01(&self.misc1_flux);
                self.need_heartbeat = true;
                return Ok(Some(response));
            }
            // MISC_HEART_BEAT (0x0b)
            0x0b => {
                let heartbeat_type = data[5];
                match heartbeat_type {
                    // MISC_FILE_TYPE (0x06)
                    0x06 => {
                        log::info!("Server: MISC_FILE_TYPE. Send MISC_HEART_BEAT_01.");
                        let response = DrcomPacket::misc_heartbeat_01(&self.misc1_flux);
                        return Ok(Some(response));
                    }
                    // MISC_HEART_BEAT_02_TYPE (0x02)
                    0x02 => {
                        log::info!("Server: MISC_HEART_BEAT_02. Send MISC_HEART_BEAT_03.");
                        self.misc3_flux.copy_from_slice(&data[16..20]);
                        let response = DrcomPacket::misc_heartbeat_03(&self.misc3_flux, local_ip);
                        return Ok(Some(response));
                    }
                    // MISC_HEART_BEAT_04_TYPE (0x04)
                    0x04 => {
                        log::info!("Server: MISC_HEART_BEAT_04. Waiting next heart beat cycle.");
                        self.base_heartbeat_time = std::time::Instant::now();
                        self.last_heartbeat_done = true;
                    }
                    _ => {
                        log::warn!("Server: Unexpected heart beat request (type: 0x{:02x})", heartbeat_type);
                    }
                }
            }
            // MISC_RESPONSE_HEART_BEAT (0x06)
            0x06 => {
                log::info!("Server: MISC_RESPONSE_HEART_BEAT. Send MISC_HEART_BEAT_01.");
                let response = DrcomPacket::misc_heartbeat_01(&self.misc1_flux);
                return Ok(Some(response));
            }
            _ => {
                log::warn!("Server: Unexpected request (type: 0x{:02x})", drcom_type);
            }
        }

        Ok(None)
    }

    /// Check if heartbeat is needed
    pub fn check_heartbeat(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.need_heartbeat {
            return Ok(None);
        }

        let elapsed = self.base_heartbeat_time.elapsed().as_secs();

        // Check for timeout
        if !self.last_heartbeat_done && elapsed > DRCOM_UDP_HEARTBEAT_TIMEOUT {
            log::error!("Client: No response to last heartbeat.");
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Heartbeat timeout"));
        }

        // Send heartbeat
        if elapsed > DRCOM_UDP_HEARTBEAT_DELAY {
            log::info!("Client: Send alive heartbeat.");
            let packet = DrcomPacket::alive_heartbeat(&self.crc_md5_info, &self.tail_info);
            self.base_heartbeat_time = std::time::Instant::now();
            self.last_heartbeat_done = false;
            return Ok(Some(packet));
        }

        Ok(None)
    }

    /// Set CRC MD5 info
    pub fn set_crc_md5_info(&mut self, info: [u8; 16]) {
        self.crc_md5_info = info;
    }

    /// Get need heartbeat flag
    pub fn need_heartbeat(&self) -> bool {
        self.need_heartbeat
    }

    /// Set need heartbeat flag
    pub fn set_need_heartbeat(&mut self, need: bool) {
        self.need_heartbeat = need;
        if need {
            self.base_heartbeat_time = std::time::Instant::now();
            self.last_heartbeat_done = false;
        }
    }

    /// Get client fd for select
    pub fn fd(&self) -> libc::c_int {
        self.client.fd()
    }
}
