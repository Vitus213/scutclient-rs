mod auth;
mod config;
mod drcom;
mod utils;

use std::error::Error;
use std::os::fd::BorrowedFd;
use std::process::Command;
use std::time::Duration;

use chrono::Timelike;
use clap::Parser;
use config::Config;
use nix::sys::signal::{self, SigSet};
use nix::sys::time::TimeValLike;

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();
    init_logger(config.debug_level);
    run(&config)
}

fn init_logger(debug_level: u8) {
    let default_filter = if debug_level > 0 { "debug" } else { "info" };

    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_filter),
    );
    builder.format_timestamp_secs();
    let _ = builder.try_init();
}

fn run(config: &Config) -> Result<(), Box<dyn Error>> {
    log::info!("bootstrap complete");

    // Setup signal handling
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    setup_signal_handlers(shutdown_tx)?;

    // Logoff mode: send logoff and exit
    if config.logoff {
        log::info!("Logoff mode: sending logoff request");
        let (mut auth, _) = authenticate(config)?;
        auth.send_logoff()?;
        log::info!("Logoff sent successfully");
        return Ok(());
    }

    // Main reconnection loop with exponential backoff
    let mut backoff_secs = 1u64;
    
    loop {
        match authenticate(config) {
            Ok((mut auth, mut drcom)) => {
                // Reset backoff on successful authentication
                backoff_secs = 1;
                
                // Run the session loop
                match run_session(&mut auth, &mut drcom, config, &shutdown_rx) {
                    SessionEnd::Signal => {
                        log::info!("Received shutdown signal, exiting cleanly");
                        // Send logoff before exit
                        let _ = auth.send_logoff();
                        return Ok(());
                    }
                    SessionEnd::NetTime => {
                        log::info!("Net time reached, disconnecting");
                        let _ = auth.send_logoff();
                        run_hook(config.offline_hook.as_deref());
                        return Ok(());
                    }
                    SessionEnd::Disconnected => {
                        log::warn!("Session disconnected, will retry with backoff");
                        run_hook(config.offline_hook.as_deref());
                    }
                    SessionEnd::Authenticated => {
                        // This should not happen in normal flow
                        log::warn!("Session ended with authenticated state");
                        run_hook(config.offline_hook.as_deref());
                    }
                }
            }
            Err(e) => {
                log::error!("Authentication failed: {}", e);
                run_hook(config.offline_hook.as_deref());
            }
        }

        // Check for shutdown signal during backoff
        let backoff = Duration::from_secs(backoff_secs);
        log::info!("Waiting {} seconds before reconnecting", backoff_secs);
        
        // Wait for either backoff or shutdown signal
        let shutdown = shutdown_rx.recv_timeout(backoff);
        if shutdown.is_ok() {
            log::info!("Received shutdown signal during backoff, exiting");
            return Ok(());
        }

        // Exponential backoff: double until 256 seconds
        backoff_secs = next_backoff_secs(backoff_secs);
    }
}

/// Authenticate using 802.1X and initialize Dr.com state
fn authenticate(config: &Config) -> Result<(auth::AuthState, drcom::DrcomState), Box<dyn Error>> {
    let mut auth = auth::AuthState::new(config)?;
    auth.send_start(&auth::MULTICAST_ADDR)?;

    loop {
        let data = match auth.recv(1000)? {
            Some(data) => data,
            None => {
                // Timeout, resend start
                auth.send_start(&auth::MULTICAST_ADDR)?;
                continue;
            }
        };

        match auth.handle_eap_packet(&data, config)? {
            auth::EapResult::Continue => {}
            auth::EapResult::Retry => {
                auth.send_start(&auth::MULTICAST_ADDR)?;
            }
            auth::EapResult::Success => {
                let mut drcom = drcom::DrcomState::new(config, auth.iface_info().ip)?;
                drcom.send(&drcom::DrcomPacket::misc_start_alive())?;
                
                // Execute online hook
                run_hook(config.online_hook.as_deref());
                
                return Ok((auth, drcom));
            }
            auth::EapResult::Failed(message) => {
                return Err(format!("Authentication failed: {}", message).into());
            }
        }
    }
}

/// Setup signal handlers for SIGINT and SIGTERM
fn setup_signal_handlers(
    shutdown_tx: std::sync::mpsc::Sender<()>,
) -> Result<(), Box<dyn Error>> {
    // Block SIGINT and SIGTERM in all threads
    let mut sigset = SigSet::empty();
    sigset.add(signal::Signal::SIGINT);
    sigset.add(signal::Signal::SIGTERM);
    signal::pthread_sigmask(signal::SigmaskHow::SIG_BLOCK, Some(&sigset), None)?;

    // Spawn a thread to handle signals
    std::thread::spawn(move || {
        // Wait for signals using libc::sigwait
        let mut sig: libc::c_int = 0;
        unsafe {
            let sigset_ptr = &sigset as *const SigSet as *const libc::sigset_t;
            if libc::sigwait(sigset_ptr, &mut sig) == 0 {
                log::info!("Received shutdown signal");
                let _ = shutdown_tx.send(());
            }
        }
    });

    Ok(())
}

/// Reason for session ending
#[derive(Debug, PartialEq)]
enum SessionEnd {
    Signal,
    NetTime,
    Disconnected,
    Authenticated,
}

/// Run the main session loop with 802.1X and Dr.com heartbeat
fn run_session(
    auth: &mut auth::AuthState,
    drcom: &mut drcom::DrcomState,
    config: &Config,
    shutdown_rx: &std::sync::mpsc::Receiver<()>,
) -> SessionEnd {
    loop {
        // Check for shutdown signal
        if shutdown_rx.try_recv().is_ok() {
            return SessionEnd::Signal;
        }

        // Check net_time
        let now = chrono::Local::now();
        if should_logoff_for_net_time(now, config.net_time) {
            return SessionEnd::NetTime;
        }

        // Use select to wait for data on either socket with timeout
        let auth_fd = auth.fd();
        let udp_fd = drcom.fd();

        // Set up file descriptors for select
        let mut read_fds = nix::sys::select::FdSet::new();
        unsafe {
            read_fds.insert(BorrowedFd::borrow_raw(auth_fd));
            read_fds.insert(BorrowedFd::borrow_raw(udp_fd));
        }

        // Calculate timeout for next heartbeat
        let heartbeat_timeout = if drcom.need_heartbeat() {
            // We need heartbeat soon, use short timeout
            nix::sys::time::TimeVal::seconds(1)
        } else {
            // No heartbeat needed, use longer timeout
            nix::sys::time::TimeVal::seconds(5)
        };

        // Wait for data or timeout
        let mut timeout = heartbeat_timeout;
        match nix::sys::select::select(None, Some(&mut read_fds), None, None, Some(&mut timeout)) {
            Ok(_) => {
                // Check 802.1X socket
                unsafe {
                    if read_fds.contains(BorrowedFd::borrow_raw(auth_fd)) {
                        match auth.recv_ready() {
                            Ok(Some(data)) => {
                                match auth.handle_eap_packet(&data, config) {
                                    Ok(auth::EapResult::Success) => {
                                        log::info!("Re-authentication successful");
                                    }
                                    Ok(auth::EapResult::Failed(msg)) => {
                                        log::error!("Authentication failed: {}", msg);
                                        return SessionEnd::Disconnected;
                                    }
                                    Ok(auth::EapResult::Retry) => {
                                        log::warn!("Authentication retry requested");
                                        if let Err(e) = auth.send_start(&auth::MULTICAST_ADDR) {
                                            log::error!("Failed to send restart: {}", e);
                                            return SessionEnd::Disconnected;
                                        }
                                    }
                                    Ok(auth::EapResult::Continue) => {}
                                    Err(e) => {
                                        log::error!("Error handling EAP packet: {}", e);
                                        return SessionEnd::Disconnected;
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                log::error!("Error receiving from auth socket: {}", e);
                                return SessionEnd::Disconnected;
                            }
                        }
                    }

                    // Check UDP socket
                    if read_fds.contains(BorrowedFd::borrow_raw(udp_fd)) {
                        match drcom.recv(100) {
                            Ok(Some(data)) => {
                                match drcom.handle_packet(
                                    &data,
                                    config,
                                    auth.server_mac(),
                                    auth.iface_info().ip,
                                ) {
                                    Ok(Some(response)) => {
                                        if let Err(e) = drcom.send(&response) {
                                            log::error!("Failed to send UDP response: {}", e);
                                            return SessionEnd::Disconnected;
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        log::error!("Error handling UDP packet: {}", e);
                                        return SessionEnd::Disconnected;
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                log::error!("Error receiving from UDP socket: {}", e);
                                // Don't return on UDP receive errors - might be transient
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("select error: {}", e);
                // Continue on select errors
            }
        }

        // Check and send heartbeat if needed
        match drcom.check_heartbeat() {
            Ok(Some(packet)) => {
                if let Err(e) = drcom.send(&packet) {
                    log::error!("Failed to send heartbeat: {}", e);
                    return SessionEnd::Disconnected;
                }
            }
            Ok(None) => {}
            Err(e) => {
                log::error!("Heartbeat check failed: {}", e);
                return SessionEnd::Disconnected;
            }
        }
    }
}

/// Calculate next backoff time (exponential backoff capped at 256 seconds)
fn next_backoff_secs(current: u64) -> u64 {
    let next = current.saturating_mul(2);
    if next > 256 {
        256
    } else {
        next
    }
}

/// Check if we should logoff based on net_time
fn should_logoff_for_net_time(
    now: chrono::DateTime<chrono::Local>,
    net_time: Option<(u8, u8)>,
) -> bool {
    match net_time {
        Some((hour, minute)) => {
            now.hour() >= hour as u32 && now.minute() >= minute as u32
        }
        None => false,
    }
}

/// Execute a hook command
fn run_hook(hook: Option<&str>) -> Result<(), Box<dyn Error>> {
    if let Some(cmd) = hook {
        log::debug!("Executing hook: {}", cmd);
        let status = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()?;
        
        if !status.success() {
            return Err(format!("Hook command failed with status: {}", status).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_backoff_secs_doubles_until_256() {
        // Test exponential backoff doubling
        assert_eq!(next_backoff_secs(1), 2);
        assert_eq!(next_backoff_secs(2), 4);
        assert_eq!(next_backoff_secs(4), 8);
        assert_eq!(next_backoff_secs(8), 16);
        assert_eq!(next_backoff_secs(16), 32);
        assert_eq!(next_backoff_secs(32), 64);
        assert_eq!(next_backoff_secs(64), 128);
        assert_eq!(next_backoff_secs(128), 256);
        
        // Cap at 256
        assert_eq!(next_backoff_secs(256), 256);
        assert_eq!(next_backoff_secs(512), 256);
    }

    #[test]
    fn test_should_logoff_for_net_time() {
        // Test at boundary - should logoff at exactly 08:30
        let time = chrono::Local::now()
            .with_hour(8).unwrap()
            .with_minute(30).unwrap()
            .with_second(0).unwrap();
        assert!(should_logoff_for_net_time(time, Some((8, 30))));
        
        // Test one minute before - should not logoff
        let time = chrono::Local::now()
            .with_hour(8).unwrap()
            .with_minute(29).unwrap()
            .with_second(0).unwrap();
        assert!(!should_logoff_for_net_time(time, Some((8, 30))));
        
        // Test one minute after - should logoff
        let time = chrono::Local::now()
            .with_hour(8).unwrap()
            .with_minute(31).unwrap()
            .with_second(0).unwrap();
        assert!(should_logoff_for_net_time(time, Some((8, 30))));
        
        // Test with no net_time - should never logoff
        let time = chrono::Local::now()
            .with_hour(23).unwrap()
            .with_minute(59).unwrap()
            .with_second(0).unwrap();
        assert!(!should_logoff_for_net_time(time, None));
    }

    #[test]
    fn test_run_hook_executes_command() {
        // Test that a hook command executes successfully
        // Using "true" command which always succeeds
        assert!(run_hook(Some("true")).is_ok());
        
        // Test with None - should return Ok
        assert!(run_hook(None).is_ok());
        
        // Test with failing command
        assert!(run_hook(Some("false")).is_err());
    }

    #[test]
    fn test_session_end_enum_exists() {
        // Verify SessionEnd enum has all required variants
        let _ = SessionEnd::Signal;
        let _ = SessionEnd::NetTime;
        let _ = SessionEnd::Disconnected;
        let _ = SessionEnd::Authenticated;
    }
}
