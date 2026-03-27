//! Raw socket for 802.1X authentication

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use nix::net::if_::if_nametoindex;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};

use crate::config::IfaceInfo;

/// Authentication socket for 802.1X
pub struct AuthSocket {
    fd: OwnedFd,
    iface_index: i32,
    mac: [u8; 6],
    ip: Ipv4Addr,
}

impl AuthSocket {
    /// Create new authentication socket
    pub fn new(iface_name: &str) -> io::Result<Self> {
        // Create raw socket for EAPOL packets
        let fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::empty(),
            Some(SockProtocol::EthAll),
        )
        .map_err(io::Error::other)?;

        // Get interface index
        let iface_index = if_nametoindex(iface_name)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))? as i32;

        // Get interface MAC and IP using ioctl
        let mac = get_interface_mac(fd.as_raw_fd(), iface_name)?;
        let ip = get_interface_ip(iface_name)?;

        log::info!("Interface {} is up.", iface_name);
        log::info!(
            "MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        log::info!("IP: {}", ip);

        Ok(Self {
            fd,
            iface_index,
            mac,
            ip,
        })
    }

    /// Get interface information
    pub fn get_iface_info(&self) -> io::Result<IfaceInfo> {
        Ok(IfaceInfo {
            mac: self.mac,
            ip: self.ip,
            index: self.iface_index,
        })
    }

    /// Send packet
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = self.iface_index;
        addr.sll_halen = 6;
        addr.sll_addr[0..6].copy_from_slice(&data[0..6]);

        let addr_len = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        let result = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                addr_len,
            )
        };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Receive packet with timeout
    pub fn recv(&self, timeout_ms: u64) -> io::Result<Option<Vec<u8>>> {
        let fd = self.fd.as_raw_fd();

        // Set up select
        let mut read_fds: libc::fd_set = unsafe { mem::zeroed() };

        unsafe {
            libc::FD_ZERO(&mut read_fds);
            libc::FD_SET(fd, &mut read_fds);
        }

        let mut timeout = libc::timeval {
            tv_sec: (timeout_ms / 1000) as libc::time_t,
            tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
        };

        let result = unsafe {
            libc::select(
                fd + 1,
                &mut read_fds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            )
        };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        if result == 0 {
            return Ok(None);
        }

        // Receive packet
        let mut buffer = vec![0u8; 2048];
        let result = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        let len = result as usize;
        buffer.truncate(len);

        // Filter: check if it's an EAPOL packet for us
        if len >= 14 {
            let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);
            if eth_type == 0x888e {
                // Check destination MAC matches our MAC
                if buffer[0..6] == self.mac {
                    return Ok(Some(buffer));
                }
            }
        }

        Ok(None)
    }

    /// Get file descriptor
    pub fn fd(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }

    /// Non-blocking receive packet
    pub fn recv_ready(&self) -> io::Result<Option<Vec<u8>>> {
        let fd = self.fd.as_raw_fd();
        let mut buffer = vec![0u8; 2048];

        let result = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err);
        }

        let len = result as usize;
        buffer.truncate(len);

        // Filter: check if it's an EAPOL packet for us
        if len >= 14 {
            let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);
            if eth_type == 0x888e {
                // Check destination MAC matches our MAC
                if buffer[0..6] == self.mac {
                    return Ok(Some(buffer));
                }
            }
        }

        Ok(None)
    }
}

/// Get interface MAC address using ioctl
fn get_interface_mac(fd: RawFd, iface_name: &str) -> io::Result<[u8; 6]> {
    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    set_ifreq_name(&mut ifreq, iface_name);

    let result = unsafe {
        libc::ioctl(
            fd,
            libc::SIOCGIFHWADDR,
            &mut ifreq as *mut libc::ifreq as *mut libc::c_void,
        )
    };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut mac = [0u8; 6];
    let hwaddr = unsafe { ifreq.ifr_ifru.ifru_hwaddr.sa_data };
    for (dst, src) in mac.iter_mut().zip(hwaddr.iter().take(6)) {
        *dst = *src as u8;
    }

    Ok(mac)
}

/// Get interface IP address using ioctl
fn get_interface_ip(iface_name: &str) -> io::Result<Ipv4Addr> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    set_ifreq_name(&mut ifreq, iface_name);

    // Set address family
    ifreq.ifr_ifru.ifru_addr.sa_family = libc::AF_INET as u16;

    let result = unsafe {
        libc::ioctl(
            fd,
            libc::SIOCGIFADDR,
            &mut ifreq as *mut libc::ifreq as *mut libc::c_void,
        )
    };

    unsafe { libc::close(fd) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Extract IP from sockaddr_in
    let addr = unsafe {
        &ifreq.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in
    };
    let ip_bytes = unsafe { (*addr).sin_addr.s_addr.to_ne_bytes() };

    Ok(Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
}

fn set_ifreq_name(ifreq: &mut libc::ifreq, iface_name: &str) {
    let name_bytes = iface_name.as_bytes();
    let copy_len = name_bytes.len().min(ifreq.ifr_name.len().saturating_sub(1));
    for (dst, src) in ifreq.ifr_name.iter_mut().zip(name_bytes.iter()).take(copy_len) {
        *dst = *src as libc::c_char;
    }
}
