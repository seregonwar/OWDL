//! AWDL Daemon Core module
//!
//! This module contains the core daemon implementation for AWDL protocol.


use crate::Result;
use crate::state::{AwdlState, AwdlConfig};
use crate::peers::AwdlPeerManager;
use crate::sync::AwdlSyncManager;
use crate::election::AwdlElectionManager;
use crate::channel::AwdlChannelManager;
use super::io::{IoManager, IoConfig};
use super::event::{EventManager, EventConfig, AwdlEvent, EventPriority, EventHandler};
use super::io::IoEvent;
use super::io::IoEventHandler;
use super::service::{ServiceManager, ServiceConfig};
use super::config::DaemonConfig;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Mutex};


use serde::{Deserialize, Serialize};



/// Bridge to forward IoEvents into the EventManager as AwdlEvents
struct IoToEventBridge {
    event_manager: Arc<Mutex<EventManager>>,
}

#[async_trait::async_trait]
impl IoEventHandler for IoToEventBridge {
    async fn handle_event(&self, event: IoEvent) -> Result<()> {
        // Forward all Io events into the EventManager queue
        self.event_manager
            .lock()
            .await
            .emit(AwdlEvent::Io(event), EventPriority::Normal)
            .await
    }
}

/// Simple event logger to observe Io events in logs
struct EventLogger;

#[async_trait::async_trait]
impl EventHandler for EventLogger {
    async fn handle_event(&self, event: &AwdlEvent) -> Result<()> {
        match event {
            AwdlEvent::Io(ioe) => match ioe {
                super::io::IoEvent::RawPacket { data } => {
                    log::debug!("EventLogger: RawPacket len={} bytes", data.len());
                }
                super::io::IoEvent::PacketReceived { data, source } => {
                    log::debug!("EventLogger: UDP/TCP PacketReceived from {} len={}", source, data.len());
                }
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }

    fn name(&self) -> &str { "event_logger" }

    fn can_handle(&self, _event: &AwdlEvent) -> bool { true }
}

/// Daemon state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonState {
    /// Daemon is initializing
    Initializing,
    /// Daemon is starting up
    Starting,
    /// Daemon is running normally
    Running,
    /// Daemon is stopping
    Stopping,
    /// Daemon has stopped
    Stopped,
    /// Daemon encountered an error
    Error,
}

/// Daemon statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonStats {
    /// Uptime in seconds
    pub uptime: u64,
    /// Number of active peers
    pub active_peers: usize,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Number of errors
    pub error_count: u64,
    /// Last error message
    pub last_error: Option<String>,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// CPU usage percentage
    pub cpu_usage: f64,
}

/// Main AWDL Daemon structure
#[derive(Debug)]
pub struct AwdlDaemon {
    /// Daemon configuration
    config: DaemonConfig,
    /// Current daemon state
    state: Arc<RwLock<DaemonState>>,
    /// AWDL protocol state
    _awdl_state: Arc<RwLock<AwdlState>>,
    /// Peer manager
    peer_manager: Arc<Mutex<AwdlPeerManager>>,
    /// Synchronization manager
    sync_manager: Arc<Mutex<AwdlSyncManager>>,
    /// Election manager
    election_manager: Arc<Mutex<AwdlElectionManager>>,
    /// Channel manager
    channel_manager: Arc<Mutex<AwdlChannelManager>>,
    /// I/O manager
    io_manager: Arc<Mutex<IoManager>>,
    /// Event manager
    event_manager: Arc<Mutex<EventManager>>,
    /// Service manager
    service_manager: Arc<Mutex<ServiceManager>>,
    /// Daemon statistics
    stats: Arc<RwLock<DaemonStats>>,
    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Start time
    start_time: std::time::Instant,
}

impl AwdlDaemon {
    /// Create new AWDL daemon
    pub async fn new(
        config: DaemonConfig,
        io_config: IoConfig,
        service_config: ServiceConfig,
    ) -> Result<Self> {
        let awdl_config = AwdlConfig::default();
        let awdl_state = AwdlState::new(awdl_config.clone());
        
        let peer_manager = AwdlPeerManager::new(100, Duration::from_secs(30));
        let sync_manager = AwdlSyncManager::new();
        let election_manager = AwdlElectionManager::new(awdl_config.self_address);
        let channel_manager = AwdlChannelManager::new();
        
        let io_manager = IoManager::new(io_config).await?;
        let event_manager = EventManager::new(EventConfig::default());
        let service_manager = ServiceManager::new(service_config);
        
        Ok(Self {
            config,
            state: Arc::new(RwLock::new(DaemonState::Initializing)),
            _awdl_state: Arc::new(RwLock::new(awdl_state)),
            peer_manager: Arc::new(Mutex::new(peer_manager)),
            sync_manager: Arc::new(Mutex::new(sync_manager)),
            election_manager: Arc::new(Mutex::new(election_manager)),
            channel_manager: Arc::new(Mutex::new(channel_manager)),
            io_manager: Arc::new(Mutex::new(io_manager)),
            event_manager: Arc::new(Mutex::new(event_manager)),
            service_manager: Arc::new(Mutex::new(service_manager)),
            stats: Arc::new(RwLock::new(DaemonStats::default())),
            shutdown_tx: None,
            start_time: std::time::Instant::now(),
        })
    }


    /// Initialize the daemon
    pub async fn init(&mut self) -> Result<()> {
        log::info!("Initializing AWDL daemon...");
        
        // Set state to starting
        *self.state.write().await = DaemonState::Starting;
        
        // Initialize I/O manager
        self.io_manager.lock().await.init().await?;
        
        // Initialize event manager
        self.event_manager.lock().await.init().await?;
        
        // Initialize service manager
        self.service_manager.lock().await.init().await?;
        
        // Initialize AWDL components
        self.peer_manager.lock().await.init().await?;
        self.sync_manager.lock().await.init().await?;
        self.election_manager.lock().await.init().await?;
        self.channel_manager.lock().await.init().await?;
        
        log::info!("AWDL daemon initialized successfully");
        Ok(())
    }

    /// Start the daemon
    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting AWDL daemon...");
        
        // Initialize first
        self.init().await?;
        
        // Set state to running
        *self.state.write().await = DaemonState::Running;
        
        // Start Event Manager (handles its own event loop and timers)
        self.event_manager.lock().await.start().await?;

        // Register a basic event logger to observe Io events
        self.event_manager
            .lock()
            .await
            .add_handler(Arc::new(EventLogger))
            .await;

        // Wire Io -> Event bridge so IoEvent gets forwarded to EventManager
        let bridge = Arc::new(IoToEventBridge {
            event_manager: Arc::clone(&self.event_manager),
        });
        self.io_manager.lock().await.add_event_handler(bridge).await;

        // Start I/O manager
        self.io_manager.lock().await.start().await?;
        
        // Start heartbeat timer
        let stats = Arc::clone(&self.stats);
        let heartbeat_interval = self.config.general.heartbeat_interval;
        tokio::spawn(async move {
            Self::run_heartbeat(stats, heartbeat_interval).await;
        });
        
        // Start statistics collection
        if self.config.general.enable_metrics {
            let stats = Arc::clone(&self.stats);
            let stats_interval = self.config.general.stats_interval;
            let start_time = self.start_time;
            tokio::spawn(async move {
                Self::run_stats_collection(stats, stats_interval, start_time).await;
            });
        }
        
        log::info!("AWDL daemon started successfully");
        Ok(())
    }

    /// Stop the daemon
    pub async fn stop(&mut self) -> Result<()> {
        log::info!("Stopping AWDL daemon...");
        
        // Set state to stopping
        *self.state.write().await = DaemonState::Stopping;
        
        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        
        // Stop Event Manager before other components
        self.event_manager.lock().await.stop().await?;
        
        // Stop service manager
        self.service_manager.lock().await.stop().await?;
        
        // Stop I/O manager
        self.io_manager.lock().await.stop().await?;
        
        // Stop AWDL components
        self.channel_manager.lock().await.stop().await?;
        self.election_manager.lock().await.stop().await?;
        self.sync_manager.lock().await.stop().await?;
        self.peer_manager.lock().await.stop().await?;
        
        // Set state to stopped
        *self.state.write().await = DaemonState::Stopped;
        
        log::info!("AWDL daemon stopped successfully");
        Ok(())
    }

    /// Run the daemon (blocking)
    pub async fn run(&mut self) -> Result<()> {
        // Setup shutdown channel
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(tx);
        
        // Start the daemon
        self.start().await?;
        
        // Wait for shutdown signal
        let _ = rx.await;
        
        // Stop the daemon
        self.stop().await?;
        
        Ok(())
    }

    /// Get daemon state
    pub async fn get_state(&self) -> DaemonState {
        *self.state.read().await
    }

    /// Get daemon statistics
    pub async fn get_stats(&self) -> DaemonStats {
        self.stats.read().await.clone()
    }

    /// Get daemon configuration
    pub fn get_config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Update daemon configuration
    pub async fn update_config(&mut self, config: DaemonConfig) -> Result<()> {
        log::info!("Updating daemon configuration");
        self.config = config;
        
        // Restart components if necessary
        if self.get_state().await == DaemonState::Running {
            log::info!("Restarting daemon with new configuration");
            self.stop().await?;
            self.start().await?;
        }
        
        Ok(())
    }

    /// Handle daemon command
    pub async fn handle_command(&mut self, command: DaemonCommand) -> Result<DaemonResponse> {
        match command {
            DaemonCommand::GetState => {
                Ok(DaemonResponse::State(self.get_state().await))
            }
            DaemonCommand::GetStats => {
                Ok(DaemonResponse::Stats(self.get_stats().await))
            }
            DaemonCommand::GetConfig => {
                Ok(DaemonResponse::Config(self.config.clone()))
            }
            DaemonCommand::UpdateConfig(config) => {
                self.update_config(config).await?;
                Ok(DaemonResponse::Success)
            }
            DaemonCommand::Start => {
                if self.get_state().await != DaemonState::Running {
                    self.start().await?;
                }
                Ok(DaemonResponse::Success)
            }
            DaemonCommand::Stop => {
                if self.get_state().await == DaemonState::Running {
                    self.stop().await?;
                }
                Ok(DaemonResponse::Success)
            }
            DaemonCommand::Restart => {
                self.stop().await?;
                self.start().await?;
                Ok(DaemonResponse::Success)
            }
            DaemonCommand::GetPeers => {
                let peers = self.peer_manager.lock().await.get_peers().cloned().collect();
                Ok(DaemonResponse::Peers(peers))
            }
        }
    }

    // The EventManager now owns its internal event loop via start()/stop().

    /// Run heartbeat timer
    async fn run_heartbeat(stats: Arc<RwLock<DaemonStats>>, interval_secs: u64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        
        loop {
            interval.tick().await;
            
            // Update heartbeat statistics
            let stats_guard = stats.write().await;
            // Perform heartbeat operations here
            log::debug!("Heartbeat tick - active peers: {}", stats_guard.active_peers);
        }
    }

    /// Run statistics collection
    async fn run_stats_collection(
        stats: Arc<RwLock<DaemonStats>>,
        interval_secs: u64,
        start_time: std::time::Instant,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        
        loop {
            interval.tick().await;
            
            // Update statistics
            let mut stats_guard = stats.write().await;
            stats_guard.uptime = start_time.elapsed().as_secs();
            
            // Collect system metrics
            stats_guard.memory_usage = Self::get_memory_usage();
            stats_guard.cpu_usage = Self::get_cpu_usage();
            
            log::debug!("Statistics updated - uptime: {}s, memory: {} bytes", 
                       stats_guard.uptime, stats_guard.memory_usage);
        }
    }

    /// Get memory usage
    fn get_memory_usage() -> u64 {
        // Simple memory usage estimation
        // In a real implementation, you would use system APIs
        0
    }

    /// Get CPU usage
    fn get_cpu_usage() -> f64 {
        // Simple CPU usage estimation
        // In a real implementation, you would use system APIs
        0.0
    }
}

/// Daemon command enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonCommand {
    /// Get daemon state
    GetState,
    /// Get daemon statistics
    GetStats,
    /// Get daemon configuration
    GetConfig,
    /// Update daemon configuration
    UpdateConfig(DaemonConfig),
    /// Start daemon
    Start,
    /// Stop daemon
    Stop,
    /// Restart daemon
    Restart,
    /// Get peer list
    GetPeers,
}

/// Daemon response enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Success response
    Success,
    /// Error response
    Error(String),
    /// State response
    State(DaemonState),
    /// Statistics response
    Stats(DaemonStats),
    /// Configuration response
    Config(DaemonConfig),
    /// Peers response
    Peers(Vec<crate::peers::AwdlPeer>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::io::IoConfig;
    use crate::daemon::service::ServiceConfig;

    #[tokio::test]
    async fn test_daemon_creation() {
        let config = DaemonConfig::default();
        let io_config = IoConfig::default();
        let service_config = ServiceConfig::default();
        
        let daemon = AwdlDaemon::new(config, io_config, service_config).await;
        assert!(daemon.is_ok());
        
        let daemon = daemon.unwrap();
        assert_eq!(daemon.get_state().await, DaemonState::Initializing);
    }

    #[tokio::test]
    async fn test_daemon_state_transitions() {
        let config = DaemonConfig::default();
        let io_config = IoConfig::default();
        let service_config = ServiceConfig::default();
        
        let mut daemon = AwdlDaemon::new(config, io_config, service_config).await.unwrap();
        
        assert_eq!(daemon.get_state().await, DaemonState::Initializing);
        
        // Test initialization
        daemon.init().await.unwrap();
        assert_eq!(daemon.get_state().await, DaemonState::Starting);
    }

    #[test]
    fn test_daemon_config() {
        let config = DaemonConfig::default();
        assert_eq!(config.io.interface, "awdl0");
        assert_eq!(config.awdl.peers.max_peers, 100);
        assert_eq!(config.general.heartbeat_interval, 30000);
    }

    #[test]
    fn test_daemon_stats() {
        let stats = DaemonStats::default();
        assert_eq!(stats.uptime, 0);
        assert_eq!(stats.active_peers, 0);
        assert_eq!(stats.packets_sent, 0);
    }
}