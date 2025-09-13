//! AWDL Daemon module
//!
//! This module contains the daemon implementation for the AWDL protocol.
//! It provides the main daemon functionality, I/O operations, event handling,
//! configuration management, and service discovery.

pub mod core;
pub mod io;
pub mod event;
pub mod config;
pub mod service;

// Re-export main types
pub use core::{AwdlDaemon, DaemonState, DaemonStats};
pub use io::*;
pub use event::*;
pub use config::DaemonConfig;
pub use service::*;

use crate::{AwdlError, Result};



/// Daemon builder for easy configuration
#[derive(Debug, Default)]
pub struct DaemonBuilder {
    config: Option<DaemonConfig>,
    io_config: Option<IoConfig>,
    service_config: Option<ServiceConfig>,
}

impl DaemonBuilder {
    /// Create new daemon builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set daemon configuration
    pub fn with_config(mut self, config: DaemonConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set I/O configuration
    pub fn with_io_config(mut self, io_config: IoConfig) -> Self {
        self.io_config = Some(io_config);
        self
    }

    /// Set service configuration
    pub fn with_service_config(mut self, service_config: ServiceConfig) -> Self {
        self.service_config = Some(service_config);
        self
    }

    /// Set network interface
    pub fn with_interface(mut self, interface: Option<String>) -> Self {
        if let Some(ref mut io_config) = self.io_config {
            if let Some(iface) = interface {
                io_config.interface = iface;
            }
        } else {
            let mut io_config = IoConfig::default();
            if let Some(iface) = interface {
                io_config.interface = iface;
            }
            self.io_config = Some(io_config);
        }
        self
    }

    /// Build the daemon
    pub async fn build(self) -> Result<AwdlDaemon> {
        let config = self.config.unwrap_or_default();
        let io_config = self.io_config.unwrap_or_default();
        let service_config = self.service_config.unwrap_or_default();

        AwdlDaemon::new(config, io_config, service_config).await
    }
}

/// Daemon utilities
pub struct DaemonUtils;

impl DaemonUtils {
    /// Check if daemon is running as root/administrator
    pub fn is_privileged() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        
        #[cfg(windows)]
        {
            // On Windows, check if running as administrator

            use winapi::um::processthreadsapi::GetCurrentProcess;
            use winapi::um::securitybaseapi::GetTokenInformation;
            use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
            
            unsafe {
                let mut token = std::ptr::null_mut();
                if winapi::um::processthreadsapi::OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY,
                    &mut token,
                ) == 0 {
                    return false;
                }
                
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut size = 0;
                
                let result = GetTokenInformation(
                    token,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut size,
                );
                
                winapi::um::handleapi::CloseHandle(token);
                
                result != 0 && elevation.TokenIsElevated != 0
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

    /// Get daemon process ID
    pub fn get_pid() -> u32 {
        std::process::id()
    }

    /// Create daemon lock file
    pub fn create_lock_file(path: &std::path::Path) -> Result<std::fs::File> {

        use std::io::Write;
        
        let mut file = std::fs::File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        
        writeln!(file, "{}", Self::get_pid())?;
        
        Ok(file)
    }

    /// Create PID file
    pub fn create_pid_file(path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        
        let mut file = std::fs::File::create(path)?;
        writeln!(file, "{}", Self::get_pid())?;
        Ok(())
    }

    /// Remove PID file
    pub fn remove_pid_file(path: &std::path::Path) -> Result<()> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Check if daemon is already running
    pub fn is_daemon_running(lock_path: &std::path::Path) -> Result<bool> {
        if !lock_path.exists() {
            return Ok(false);
        }
        
        let pid_str = std::fs::read_to_string(lock_path)?;
        let pid = pid_str.trim().parse::<u32>()
            .map_err(|_| AwdlError::Config("Invalid PID in lock file".to_string()))?;
        
        Ok(Self::is_process_running(pid))
    }

    /// Check if process is running
    pub fn is_process_running(pid: u32) -> bool {
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(pid as i32, 0) == 0
            }
        }
        
        #[cfg(windows)]
        {
            use winapi::um::processthreadsapi::OpenProcess;
            use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
            use winapi::um::handleapi::CloseHandle;
            
            unsafe {
                let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
                if handle.is_null() {
                    false
                } else {
                    CloseHandle(handle);
                    true
                }
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

    /// Daemonize process (Unix only)
    #[cfg(unix)]
    pub fn daemonize() -> Result<()> {
        use std::ffi::CString;
        
        unsafe {
            // First fork
            let pid = libc::fork();
            if pid < 0 {
                return Err(AwdlError::System("First fork failed".to_string()));
            } else if pid > 0 {
                // Parent process exits
                std::process::exit(0);
            }
            
            // Create new session
            if libc::setsid() < 0 {
                return Err(AwdlError::System("setsid failed".to_string()));
            }
            
            // Second fork
            let pid = libc::fork();
            if pid < 0 {
                return Err(AwdlError::System("Second fork failed".to_string()));
            } else if pid > 0 {
                // Parent process exits
                std::process::exit(0);
            }
            
            // Change working directory to root
            let root_path = CString::new("/").unwrap();
            if libc::chdir(root_path.as_ptr()) < 0 {
                return Err(AwdlError::System("chdir failed".to_string()));
            }
            
            // Set file permissions mask
            libc::umask(0);
            
            // Close standard file descriptors
            libc::close(libc::STDIN_FILENO);
            libc::close(libc::STDOUT_FILENO);
            libc::close(libc::STDERR_FILENO);
            
            // Redirect standard file descriptors to /dev/null
            let dev_null = CString::new("/dev/null").unwrap();
            let null_fd = libc::open(dev_null.as_ptr(), libc::O_RDWR);
            if null_fd >= 0 {
                libc::dup2(null_fd, libc::STDIN_FILENO);
                libc::dup2(null_fd, libc::STDOUT_FILENO);
                libc::dup2(null_fd, libc::STDERR_FILENO);
                if null_fd > 2 {
                    libc::close(null_fd);
                }
            }
        }
        
        Ok(())
    }

    /// Setup signal handlers
    pub fn setup_signal_handlers() -> Result<()> {
        #[cfg(unix)]
        {
            use signal_hook::{consts::SIGTERM, iterator::Signals};
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::Arc;
            
            let term = Arc::new(AtomicBool::new(false));
            let term_clone = Arc::clone(&term);
            
            let mut signals = Signals::new(&[SIGTERM])
                .map_err(|e| AwdlError::System(format!("Failed to setup signal handler: {}", e)))?;
            
            std::thread::spawn(move || {
                for sig in signals.forever() {
                    match sig {
                        SIGTERM => {
                            log::info!("Received SIGTERM, shutting down...");
                            term_clone.store(true, Ordering::Relaxed);
                            break;
                        }
                        _ => {}
                    }
                }
            });
        }
        
        Ok(())
    }

    /// Get system information
    pub fn get_system_info() -> SystemInfo {
        SystemInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            pid: Self::get_pid(),
            privileged: Self::is_privileged(),
        }
    }
}

/// System information
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub pid: u32,
    pub privileged: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_builder() {
        let builder = DaemonBuilder::new()
            .with_config(DaemonConfig::default())
            .with_io_config(IoConfig::default());
        
        // Builder should be configured
        assert!(builder.config.is_some());
        assert!(builder.io_config.is_some());
    }

    #[test]
    fn test_daemon_utils() {
        let pid = DaemonUtils::get_pid();
        assert!(pid > 0);
        
        let system_info = DaemonUtils::get_system_info();
        assert!(!system_info.os.is_empty());
        assert!(!system_info.arch.is_empty());
        assert_eq!(system_info.pid, pid);
    }
}