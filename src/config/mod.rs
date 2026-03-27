//! Configuration and global state for scutclient

use std::net::Ipv4Addr;

use clap::{ArgAction, Parser};

/// Default server address
pub const SERVER_ADDR: &str = "202.38.210.131";
/// Default server port
pub const SERVER_PORT: u16 = 61440;
/// Default DNS address
pub const DNS_ADDR: &str = "222.201.130.30";

/// Drcom UDP heartbeat delay in seconds
pub const DRCOM_UDP_HEARTBEAT_DELAY: u64 = 12;
/// Drcom UDP heartbeat timeout in seconds
pub const DRCOM_UDP_HEARTBEAT_TIMEOUT: u64 = 2;
/// 802.1X receive delay in seconds
pub const AUTH_8021X_RECV_DELAY: u64 = 1;
/// 802.1X receive retry times
pub const AUTH_8021X_RECV_TIMES: i32 = 3;

/// Default Drcom version bytes
pub const DEFAULT_VERSION: &[u8] = &[0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a];
/// Default hash value
pub const DEFAULT_HASH: &str = "2ec15ad258aee9604b18f2f8114da38db16efd00";
/// Default client version hex string
pub const DEFAULT_VERSION_HEX: &str = "4472434f4d0096022a";

/// Client configuration
#[derive(Debug, Clone, Parser)]
#[command(name = "scutclient-rs", about = "SCUT Dr.com(X) client written in Rust", disable_help_flag = true)]
pub struct Config {
    /// Username for authentication
    #[arg(short = 'u', long = "username")]
    pub username: String,
    /// Password for authentication
    #[arg(short = 'p', long = "password")]
    pub password: String,
    /// Network interface name
    #[arg(short = 'i', long = "iface", default_value = "eth0")]
    pub iface: String,
    /// DNS server address
    #[arg(short = 'n', long = "dns", default_value = DNS_ADDR)]
    pub dns: Ipv4Addr,
    /// Hostname
    #[arg(short = 'H', long = "hostname", default_value_t = default_hostname())]
    pub hostname: String,
    /// UDP server address
    #[arg(short = 's', long = "udp-server", default_value = SERVER_ADDR)]
    pub udp_server: Ipv4Addr,
    /// Client version bytes
    #[arg(skip = DEFAULT_VERSION.to_vec())]
    pub version: Vec<u8>,
    #[arg(short = 'c', long = "cli-version", value_name = "HEX", default_value = DEFAULT_VERSION_HEX)]
    cli_version_raw: String,
    /// Hash value
    #[arg(short = 'h', long = "hash", default_value = DEFAULT_HASH)]
    pub hash: String,
    /// Network allowed time (hour, minute)
    #[arg(short = 'T', long = "net-time", value_parser = parse_net_time)]
    pub net_time: Option<(u8, u8)>,
    /// Command to execute after online
    #[arg(short = 'E', long = "online-hook")]
    pub online_hook: Option<String>,
    /// Command to execute when offline
    #[arg(short = 'Q', long = "offline-hook")]
    pub offline_hook: Option<String>,
    /// Debug level
    #[arg(short = 'D', long = "debug", default_value_t = 0)]
    pub debug_level: u8,
    /// Logoff mode
    #[arg(short = 'o', long = "logoff", action = ArgAction::SetTrue)]
    pub logoff: bool,
    /// Print help information
    #[arg(short = '?', long = "help", action = ArgAction::HelpLong, help = "Print help")]
    help: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            iface: "eth0".to_string(),
            dns: DNS_ADDR.parse().expect("default dns must be valid"),
            hostname: default_hostname(),
            udp_server: SERVER_ADDR.parse().expect("default server must be valid"),
            version: DEFAULT_VERSION.to_vec(),
            cli_version_raw: DEFAULT_VERSION_HEX.to_string(),
            hash: DEFAULT_HASH.to_string(),
            net_time: None,
            online_hook: None,
            offline_hook: None,
            debug_level: 0,
            logoff: false,
            help: None,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse() -> Self {
        let parsed = <Self as Parser>::parse();
        match Self::finalize(parsed) {
            Ok(config) => config,
            Err(message) => clap::Error::raw(clap::error::ErrorKind::ValueValidation, message).exit(),
        }
    }

    pub fn try_parse_from<I, T>(itr: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let parsed = <Self as Parser>::try_parse_from(itr)?;
        Self::finalize(parsed)
            .map_err(|message| clap::Error::raw(clap::error::ErrorKind::ValueValidation, message))
    }

    fn finalize(mut parsed: Self) -> Result<Self, String> {
        parsed.version = parse_hex_bytes(&parsed.cli_version_raw)?;
        Ok(parsed)
    }
}

fn default_hostname() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Ok(Vec::new());
    }

    if normalized.len() % 2 != 0 {
        return Err("hex string must contain an even number of digits".to_string());
    }

    let mut bytes = Vec::with_capacity(normalized.len() / 2);
    for pair in normalized.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| "hex string must be valid UTF-8".to_string())?;
        let value = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("invalid hex byte: {pair}"))?;
        bytes.push(value);
    }

    Ok(bytes)
}

fn parse_net_time(raw: &str) -> Result<(u8, u8), String> {
    if raw.len() != 5 || raw.as_bytes()[2] != b':' {
        return Err("net time must use HH:MM format".to_string());
    }

    let (hour, minute) = raw
        .split_once(':')
        .ok_or_else(|| "net time must use HH:MM format".to_string())?;

    if hour.len() != 2 || minute.len() != 2 {
        return Err("net time must use HH:MM format".to_string());
    }

    let hour: u8 = hour.parse().map_err(|_| "hour must be numeric".to_string())?;
    let minute: u8 = minute.parse().map_err(|_| "minute must be numeric".to_string())?;

    if hour > 23 {
        return Err("hour must be between 0 and 23".to_string());
    }

    if minute > 59 {
        return Err("minute must be between 0 and 59".to_string());
    }

    Ok((hour, minute))
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub index: i32,
}

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_HASH};

    #[test]
    fn parses_required_cli_flags() {
        let config = Config::try_parse_from([
            "scutclient-rs",
            "-u",
            "alice",
            "-p",
            "secret",
        ])
        .expect("config should parse required credentials");

        assert_eq!(config.username, "alice");
        assert_eq!(config.password, "secret");
        assert_eq!(config.iface, "eth0");
        assert_eq!(config.hash, DEFAULT_HASH);
        assert_eq!(config.net_time, None);
        assert!(!config.logoff);
    }

    #[test]
    fn rejects_missing_required_password() {
        let error = Config::try_parse_from(["scutclient-rs", "--username", "alice"])
            .expect_err("config should reject missing password");

        let rendered = error.to_string();
        assert!(rendered.contains("--password"));
    }

    #[test]
    fn parses_cli_version_hex_bytes() {
        let config = Config::try_parse_from([
            "scutclient-rs",
            "--username",
            "alice",
            "--password",
            "secret",
            "--cli-version",
            "4472434f4d0096022a",
        ])
        .expect("config should parse cli version bytes");

        assert_eq!(config.version, vec![0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a]);
    }

    #[test]
    fn rejects_invalid_cli_version_hex() {
        let error = Config::try_parse_from([
            "scutclient-rs",
            "--username",
            "alice",
            "--password",
            "secret",
            "--cli-version",
            "xyz",
        ])
        .expect_err("config should reject invalid cli version hex");

        let rendered = error.to_string();
        assert!(rendered.contains("invalid hex byte") || rendered.contains("even number of digits"));
    }

    #[test]
    fn rejects_non_padded_net_time() {
        let error = Config::try_parse_from([
            "scutclient-rs",
            "--username",
            "alice",
            "--password",
            "secret",
            "--net-time",
            "8:3",
        ])
        .expect_err("config should reject non-padded net time");

        assert!(error.to_string().contains("HH:MM"));
    }

    #[test]
    fn parses_net_time_hh_mm() {
        let config = Config::try_parse_from([
            "scutclient-rs",
            "--username",
            "alice",
            "--password",
            "secret",
            "--net-time",
            "08:30",
        ])
        .expect("config should parse net time");

        assert_eq!(config.net_time, Some((8, 30)));
    }
}
