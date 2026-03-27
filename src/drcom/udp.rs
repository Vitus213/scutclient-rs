//! UDP client for Dr.com protocol

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use crate::config::SERVER_PORT;

/// UDP client for Dr.com communication
pub struct UdpClient {
    socket: UdpSocket,
    server_addr: SocketAddr,
}

impl UdpClient {
    /// Create new UDP client
    pub fn new(
        iface_name: &str,
        server_ip: Ipv4Addr,
        local_ip: Ipv4Addr,
    ) -> io::Result<Self> {
        let server_addr = SocketAddr::new(server_ip.into(), SERVER_PORT);
        let local_addr = SocketAddr::new(local_ip.into(), SERVER_PORT);

        let socket = UdpSocket::bind(local_addr)?;

        // Bind to device
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let c_iface = std::ffi::CString::new(iface_name).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "Invalid interface name")
            })?;
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    c_iface.as_ptr() as *const libc::c_void,
                    c_iface.as_bytes_with_nul().len() as u32,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        socket.set_broadcast(true)?;

        Ok(Self {
            socket,
            server_addr,
        })
    }

    /// Send data to server
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.socket.send_to(data, self.server_addr)?;
        Ok(())
    }

    /// Receive data with timeout
    pub fn recv(&self, timeout_ms: u64) -> io::Result<Option<Vec<u8>>> {
        self.socket.set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))?;

        let mut buffer = vec![0u8; 2048];
        match self.socket.recv_from(&mut buffer) {
            Ok((len, addr)) => {
                // Only accept packets from server
                if addr == self.server_addr {
                    buffer.truncate(len);
                    // Check if valid Dr.com packet
                    if len > 0 && (buffer[0] == 0x07 || (buffer[0] == 0x4d && buffer[1] == 0x38)) {
                        return Ok(Some(buffer));
                    }
                }
                Ok(None)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get file descriptor
    pub fn fd(&self) -> libc::c_int {
        use std::os::unix::io::AsRawFd;
        self.socket.as_raw_fd()
    }
}
