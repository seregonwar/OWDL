//! AWDL Daemon I/O module
//!
//! This module handles I/O operations for the AWDL daemon.


use crate::{AwdlError, Result};
use crate::frame::AwdlFrame;

use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use serde::{Deserialize, Serialize};
use bytes::{Bytes, BytesMut};
#[cfg(windows)]
use pcap as winpcap;
#[cfg(windows)]
use tokio::sync::mpsc as tokio_mpsc;
#[cfg(windows)]
use nexus802::{
    phy::{PhyBackend as NexusPhyBackend, MonitorModeType as NexusMonitorMode, ChannelConfig as NexusChannelConfig},
};
#[cfg(windows)]
use nexus802::bridge::BridgeBackend as NexusBridgeBackend;
#[cfg(windows)]
use nexus802::config::BridgeConfig as NexusBridgeConfig;

/// I/O configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoConfig {
    /// Network interface name
    pub interface: String,
    /// UDP port for AWDL communication
    pub udp_port: u16,
    /// TCP port for management
    pub tcp_port: u16,
    /// Bind address
    pub bind_address: IpAddr,
    /// Maximum packet size
    pub max_packet_size: usize,
    /// Socket buffer size
    pub socket_buffer_size: usize,
    /// Enable raw socket mode
    pub raw_socket: bool,
    /// Socket timeout in milliseconds
    pub socket_timeout: u64,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            interface: "awdl0".to_string(),
            udp_port: 6363,
            tcp_port: 8080,
            bind_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            max_packet_size: 1500,
            socket_buffer_size: 65536,
            raw_socket: false,
            socket_timeout: 5000,
            max_connections: 100,
        }
    }
}

/// I/O statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Number of send errors
    pub send_errors: u64,
    /// Number of receive errors
    pub recv_errors: u64,
    /// Number of active connections
    pub active_connections: usize,
    /// Average packet size
    pub avg_packet_size: f64,
}

/// I/O event types
#[derive(Debug, Clone)]
pub enum IoEvent {
    /// Packet received
    PacketReceived {
        data: Bytes,
        source: SocketAddr,
    },
    /// Raw 802.11 packet (captured via Npcap/pcap) - no socket address
    RawPacket {
        data: Bytes,
    },
    /// Packet sent
    PacketSent {
        size: usize,
        destination: SocketAddr,
    },
    /// Connection established
    ConnectionEstablished {
        peer: SocketAddr,
    },
    /// Connection closed
    ConnectionClosed {
        peer: SocketAddr,
    },
    /// I/O error occurred
    IoError {
        error: String,
    },
}

/// I/O event handler trait
#[async_trait::async_trait]
pub trait IoEventHandler: Send + Sync {
    /// Handle I/O event
    async fn handle_event(&self, event: IoEvent) -> Result<()>;
}

/// Socket wrapper for different socket types
#[derive(Debug)]
pub enum SocketType {
    /// UDP socket
    Udp(Arc<UdpSocket>),
    /// TCP listener
    TcpListener(Arc<TcpListener>),
    /// TCP stream
    TcpStream(Arc<Mutex<TcpStream>>),
}

/// I/O connection information
#[derive(Debug, Clone)]
pub struct IoConnection {
    /// Connection ID
    pub id: u64,
    /// Peer address
    pub peer_addr: SocketAddr,
    /// Connection type
    pub conn_type: ConnectionType,
    /// Connection state
    pub state: ConnectionState,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Connection timestamp
    pub connected_at: std::time::Instant,
}

/// Connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// UDP connection
    Udp,
    /// TCP connection
    Tcp,
    /// Raw socket connection
    Raw,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Connection is connecting
    Connecting,
    /// Connection is established
    Connected,
    /// Connection is closing
    Closing,
    /// Connection is closed
    Closed,
    /// Connection has error
    Error,
}

/// I/O Manager
pub struct IoManager {
    /// I/O configuration
    config: IoConfig,
    /// UDP socket
    udp_socket: Option<Arc<UdpSocket>>,
    /// TCP listener
    tcp_listener: Option<Arc<TcpListener>>,
    /// Active connections
    connections: Arc<RwLock<HashMap<u64, IoConnection>>>,
    /// I/O statistics
    stats: Arc<RwLock<IoStats>>,
    /// Event handlers
    event_handlers: Arc<RwLock<Vec<Arc<dyn IoEventHandler>>>>,
    /// Next connection ID
    next_conn_id: Arc<Mutex<u64>>,
    /// Running state
    running: Arc<RwLock<bool>>,
    /// Windows: Active pcap capture handle when in raw mode
    #[cfg(windows)]
    pcap_handle: Option<Arc<Mutex<winpcap::Capture<winpcap::Active>>>>,
    /// Windows: Nexus802 bridge backend (WSL2) when used instead of Npcap
    #[cfg(windows)]
    nexus_backend: Option<Arc<Mutex<Box<dyn NexusPhyBackend>>>>,
}

impl std::fmt::Debug for IoManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoManager")
            .field("config", &self.config)
            .field("udp_socket", &self.udp_socket.is_some())
            .field("tcp_listener", &self.tcp_listener.is_some())
            .field("connections", &format!("[connections]"))
            .field("stats", &format!("[stats]"))
            .field("event_handlers", &format!("[event_handlers]"))
            .field("running", &self.running)
            .finish()
    }
}

impl IoManager {
    /// Create new I/O manager
    pub async fn new(config: IoConfig) -> Result<Self> {
        Ok(Self {
            config,
            udp_socket: None,
            tcp_listener: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(IoStats::default())),
            event_handlers: Arc::new(RwLock::new(Vec::new())),
            next_conn_id: Arc::new(Mutex::new(1)),
            running: Arc::new(RwLock::new(false)),
            #[cfg(windows)]
            pcap_handle: None,
            #[cfg(windows)]
            nexus_backend: None,
        })
    }

    /// Initialize I/O manager
    pub async fn init(&mut self) -> Result<()> {
        log::info!("Initializing I/O manager...");
        
        // Windows raw mode via Npcap/pcap
        #[cfg(windows)]
        if self.config.raw_socket {
            // Prefer Nexus802 WSL2 bridge if interface is explicitly "bridge"
            if self.config.interface.to_lowercase() == "bridge" {
                log::info!("Initializing Nexus802 WSL2 bridge backend (localhost:9000/9001)...");
                let bridge_cfg = NexusBridgeConfig {
                    wsl_distribution: "Ubuntu".to_string(),
                    bridge_executable: "/usr/local/bin/nexus802-bridge".to_string(),
                    shared_memory_size: 64 * 1024 * 1024,
                    control_pipe_name: "\\\\.\\pipe\\nexus802-control".to_string(),
                    rx_pipe_name: "\\\\.\\pipe\\nexus802-rx".to_string(),
                    tx_pipe_name: "\\\\.\\pipe\\nexus802-tx".to_string(),
                    timeout_seconds: 30,
                    use_shared_memory: true,
                };
                let mut backend_box: Box<dyn NexusPhyBackend> = Box::new(NexusBridgeBackend::new(bridge_cfg));
                backend_box.initialize().await.map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Nexus802 init failed: {}", e))))?;
                // Enable monitor mode and set default channel 6
                backend_box.enable_monitor_mode(NexusMonitorMode::Bridge).await.map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Nexus802 enable monitor failed: {}", e))))?;
                let ch = NexusChannelConfig { primary: 6, width: 20, center_freq: 2412 + (6 - 1) * 5, secondary_offset: None };
                let _ = backend_box.set_channel(ch).await;
                self.nexus_backend = Some(Arc::new(Mutex::new(backend_box)));
                log::info!("Nexus802 bridge backend initialized");
            } else {
                log::info!("Initializing raw 802.11 capture via Npcap on interface '{}'...", self.config.interface);
                // Try to open the device by name. On Windows this is typically \\Device\\NPF_{GUID}
                let mut cap = winpcap::Capture::from_device(self.config.interface.as_str())
                    .map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("pcap from_device failed: {}", e))))?;
                let mut cap = cap
                    .immediate_mode(true)
                    .timeout(1000)
                    .open()
                    .map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("pcap open failed: {}", e))))?;
                let datalink = cap.get_datalink();
                log::info!("pcap datalink: {:?}", datalink);
                self.pcap_handle = Some(Arc::new(Mutex::new(cap)));
            }
        }
        
        log::info!("I/O manager initialized - Raw (Npcap)");
        return Ok(());
    }

    /// Start I/O manager
    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting I/O manager...");
        
        *self.running.write().await = true;
        
        // Windows raw mode via Npcap
        #[cfg(windows)]
        if self.config.raw_socket {
            // If using Nexus802 backend, spawn its RX loop
            if let Some(backend) = &self.nexus_backend {
                let backend_arc = Arc::clone(backend);
                let handlers = Arc::clone(&self.event_handlers);
                let running = Arc::clone(&self.running);
                let stats = Arc::clone(&self.stats);
                tokio::spawn(async move {
                    while *running.read().await {
                        let mut guard = backend_arc.lock().await;
                        match guard.recv_frame_timeout(std::time::Duration::from_millis(200)).await {
                            Ok(Some((frame, _meta))) => {
                                {
                                    let mut s = stats.write().await;
                                    s.packets_received += 1;
                                    s.bytes_received += frame.len() as u64;
                                }
                                let event = IoEvent::RawPacket { data: Bytes::from(frame) };
                                let handlers_guard = handlers.read().await;
                                for h in handlers_guard.iter() {
                                    if let Err(e) = h.handle_event(event.clone()).await { log::error!("RawPacket handler error: {}", e); }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                log::warn!("Nexus802 RX error: {}", e);
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            }
                        }
                    }
                });
            } else if let Some(handle) = &self.pcap_handle {
                let cap = Arc::clone(handle);
                let stats = Arc::clone(&self.stats);
                let handlers = Arc::clone(&self.event_handlers);
                let running = Arc::clone(&self.running);

                // Channel from blocking reader to async forwarder
                let (tx, mut rx) = tokio_mpsc::unbounded_channel::<Bytes>();

                // Blocking reader
                tokio::task::spawn_blocking(move || {
                    loop {
                        // Read next packet under lock and copy data before releasing lock
                        let maybe_data: Option<Bytes> = {
                            let mut guard = cap.blocking_lock();
                            match guard.next_packet() {
                                Ok(packet) => Some(Bytes::copy_from_slice(packet.data)),
                                Err(_) => None,
                            }
                        };
                        if let Some(data) = maybe_data {
                            let _ = tx.send(data);
                        } else {
                            // No packet; continue looping (timeout(1) keeps it responsive)
                        }
                    }
                });

                // Async forwarder: update stats and notify handlers
                tokio::spawn(async move {
                    while *running.read().await {
                        if let Some(data) = rx.recv().await {
                            // Update statistics
                            {
                                let mut stats_guard = stats.write().await;
                                stats_guard.bytes_received += data.len() as u64;
                                stats_guard.packets_received += 1;
                                stats_guard.avg_packet_size = 
                                    stats_guard.bytes_received as f64 / stats_guard.packets_received as f64;
                            }

                            // Notify handlers
                            let event = IoEvent::RawPacket { data };
                            let handlers_guard = handlers.read().await;
                            for handler in handlers_guard.iter() {
                                if let Err(e) = handler.handle_event(event.clone()).await {
                                    log::error!("Raw event handler error: {}", e);
                                }
                            }
                        } else {
                            break;
                        }
                    }
                });
            }
        }

        // Start UDP receiver
        if let Some(udp_socket) = &self.udp_socket {
            let socket = Arc::clone(udp_socket);
            let stats = Arc::clone(&self.stats);
            let handlers = Arc::clone(&self.event_handlers);
            let running = Arc::clone(&self.running);
            
            tokio::spawn(async move {
                Self::run_udp_receiver(socket, stats, handlers, running).await;
            });
        }
        
        // Start TCP acceptor
        if let Some(tcp_listener) = &self.tcp_listener {
            let listener = Arc::clone(tcp_listener);
            let connections = Arc::clone(&self.connections);
            let next_conn_id = Arc::clone(&self.next_conn_id);
            let stats = Arc::clone(&self.stats);
            let handlers = Arc::clone(&self.event_handlers);
            let running = Arc::clone(&self.running);
            
            tokio::spawn(async move {
                Self::run_tcp_acceptor(listener, connections, next_conn_id, stats, handlers, running).await;
            });
        }
        
        log::info!("I/O manager started successfully");
        Ok(())
    }

    /// Stop I/O manager
    pub async fn stop(&mut self) -> Result<()> {
        log::info!("Stopping I/O manager...");
        
        *self.running.write().await = false;
        
        // Close all connections
        let mut connections = self.connections.write().await;
        for (_, mut conn) in connections.drain() {
            conn.state = ConnectionState::Closed;
        }
        
        // Windows: drop pcap handle
        #[cfg(windows)]
        {
            self.pcap_handle = None;
            if let Some(backend) = &self.nexus_backend {
                if let Ok(mut guard) = backend.try_lock() {
                    let _ = guard.disable_monitor_mode().await;
                    let _ = guard.shutdown().await;
                }
            }
            self.nexus_backend = None;
        }
        
        log::info!("I/O manager stopped successfully");
        Ok(())
    }

    /// Send packet via UDP
    pub async fn send_udp(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        if let Some(socket) = &self.udp_socket {
            let bytes_sent = socket.send_to(data, dest).await
                .map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("UDP send failed: {}", e))))?;
            
            // Update statistics
            let mut stats = self.stats.write().await;
            stats.bytes_sent += bytes_sent as u64;
            stats.packets_sent += 1;
            
            // Notify event handlers
            let event = IoEvent::PacketSent {
                size: bytes_sent,
                destination: dest,
            };
            self.notify_handlers(event).await;
            
            Ok(())
        } else {
            Err(AwdlError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "UDP socket not initialized")))
        }
    }

    /// Send AWDL frame
    pub async fn send_frame(&self, frame: &AwdlFrame, dest: SocketAddr) -> Result<()> {
        let mut buf = BytesMut::new();
        frame.serialize(&mut buf)?;
        self.send_udp(&buf, dest).await
    }

    /// Get I/O statistics
    pub async fn get_stats(&self) -> IoStats {
        self.stats.read().await.clone()
    }

    /// Get active connections
    pub async fn get_connections(&self) -> Vec<IoConnection> {
        self.connections.read().await.values().cloned().collect()
    }

    /// Add event handler
    pub async fn add_event_handler(&self, handler: Arc<dyn IoEventHandler>) {
        self.event_handlers.write().await.push(handler);
    }

    /// Remove event handler
    pub async fn remove_event_handler(&self, handler: Arc<dyn IoEventHandler>) {
        let mut handlers = self.event_handlers.write().await;
        handlers.retain(|h| !Arc::ptr_eq(h, &handler));
    }

    /// Notify event handlers
    async fn notify_handlers(&self, event: IoEvent) {
        let handlers = self.event_handlers.read().await;
        for handler in handlers.iter() {
            if let Err(e) = handler.handle_event(event.clone()).await {
                log::error!("Event handler error: {}", e);
            }
        }
    }

    /// Run UDP receiver loop
    async fn run_udp_receiver(
        socket: Arc<UdpSocket>,
        stats: Arc<RwLock<IoStats>>,
        handlers: Arc<RwLock<Vec<Arc<dyn IoEventHandler>>>>,
        running: Arc<RwLock<bool>>,
    ) {
        let mut buffer = vec![0u8; 65536];
        
        while *running.read().await {
            match socket.recv_from(&mut buffer).await {
                Ok((size, source)) => {
                    // Update statistics
                    {
                        let mut stats_guard = stats.write().await;
                        stats_guard.bytes_received += size as u64;
                        stats_guard.packets_received += 1;
                        stats_guard.avg_packet_size = 
                            stats_guard.bytes_received as f64 / stats_guard.packets_received as f64;
                    }
                    
                    // Create event
                    let event = IoEvent::PacketReceived {
                        data: Bytes::copy_from_slice(&buffer[..size]),
                        source,
                    };
                    
                    // Notify handlers
                    let handlers_guard = handlers.read().await;
                    for handler in handlers_guard.iter() {
                        if let Err(e) = handler.handle_event(event.clone()).await {
                            log::error!("UDP event handler error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("UDP receive error: {}", e);
                    
                    // Update error statistics
                    stats.write().await.recv_errors += 1;
                    
                    // Notify handlers about error
                    let event = IoEvent::IoError {
                        error: format!("UDP receive error: {}", e),
                    };
                    
                    let handlers_guard = handlers.read().await;
                    for handler in handlers_guard.iter() {
                        if let Err(e) = handler.handle_event(event.clone()).await {
                            log::error!("Error event handler error: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Run TCP acceptor loop
    async fn run_tcp_acceptor(
        listener: Arc<TcpListener>,
        connections: Arc<RwLock<HashMap<u64, IoConnection>>>,
        next_conn_id: Arc<Mutex<u64>>,
        stats: Arc<RwLock<IoStats>>,
        handlers: Arc<RwLock<Vec<Arc<dyn IoEventHandler>>>>,
        running: Arc<RwLock<bool>>,
    ) {
        while *running.read().await {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // Generate connection ID
                    let conn_id = {
                        let mut id = next_conn_id.lock().await;
                        let current_id = *id;
                        *id += 1;
                        current_id
                    };
                    
                    // Create connection info
                    let connection = IoConnection {
                        id: conn_id,
                        peer_addr,
                        conn_type: ConnectionType::Tcp,
                        state: ConnectionState::Connected,
                        bytes_sent: 0,
                        bytes_received: 0,
                        connected_at: std::time::Instant::now(),
                    };
                    
                    // Store connection
                    connections.write().await.insert(conn_id, connection);
                    
                    // Update statistics
                    stats.write().await.active_connections += 1;
                    
                    // Notify handlers
                    let event = IoEvent::ConnectionEstablished { peer: peer_addr };
                    let handlers_guard = handlers.read().await;
                    for handler in handlers_guard.iter() {
                        if let Err(e) = handler.handle_event(event.clone()).await {
                            log::error!("Connection event handler error: {}", e);
                        }
                    }
                    
                    // Handle TCP connection in separate task
                    let stream = Arc::new(Mutex::new(stream));
                    let connections_clone = Arc::clone(&connections);
                    let stats_clone = Arc::clone(&stats);
                    let handlers_clone = Arc::clone(&handlers);
                    let running_clone = Arc::clone(&running);
                    
                    tokio::spawn(async move {
                        Self::handle_tcp_connection(
                            conn_id,
                            stream,
                            peer_addr,
                            connections_clone,
                            stats_clone,
                            handlers_clone,
                            running_clone,
                        ).await;
                    });
                }
                Err(e) => {
                    log::error!("TCP accept error: {}", e);
                    
                    // Small delay to prevent busy loop on persistent errors
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Handle TCP connection
    async fn handle_tcp_connection(
        conn_id: u64,
        stream: Arc<Mutex<TcpStream>>,
        peer_addr: SocketAddr,
        connections: Arc<RwLock<HashMap<u64, IoConnection>>>,
        stats: Arc<RwLock<IoStats>>,
        handlers: Arc<RwLock<Vec<Arc<dyn IoEventHandler>>>>,
        running: Arc<RwLock<bool>>,
    ) {
        let mut buffer = vec![0u8; 4096];
        
        while *running.read().await {
            let mut stream_guard = stream.lock().await;
            
            match stream_guard.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed by peer
                    break;
                }
                Ok(size) => {
                    // Update connection statistics
                    if let Some(conn) = connections.write().await.get_mut(&conn_id) {
                        conn.bytes_received += size as u64;
                    }
                    
                    // Update global statistics
                    stats.write().await.bytes_received += size as u64;
                    
                    // Create event
                    let event = IoEvent::PacketReceived {
                        data: Bytes::copy_from_slice(&buffer[..size]),
                        source: peer_addr,
                    };
                    
                    // Notify handlers
                    let handlers_guard = handlers.read().await;
                    for handler in handlers_guard.iter() {
                        if let Err(e) = handler.handle_event(event.clone()).await {
                            log::error!("TCP event handler error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("TCP read error from {}: {}", peer_addr, e);
                    break;
                }
            }
        }
        
        // Clean up connection
        connections.write().await.remove(&conn_id);
        stats.write().await.active_connections = 
            stats.read().await.active_connections.saturating_sub(1);
        
        // Notify handlers about connection closure
        let event = IoEvent::ConnectionClosed { peer: peer_addr };
        let handlers_guard = handlers.read().await;
        for handler in handlers_guard.iter() {
            if let Err(e) = handler.handle_event(event.clone()).await {
                log::error!("Connection close event handler error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_io_config_default() {
        let config = IoConfig::default();
        assert_eq!(config.interface, "awdl0");
        assert_eq!(config.udp_port, 6363);
        assert_eq!(config.tcp_port, 8080);
        assert_eq!(config.max_packet_size, 1500);
    }

    #[tokio::test]
    async fn test_io_manager_creation() {
        let config = IoConfig::default();
        let manager = IoManager::new(config).await;
        assert!(manager.is_ok());
    }

    #[test]
    fn test_io_stats() {
        let stats = IoStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.active_connections, 0);
    }

    #[test]
    fn test_connection_info() {
        let conn = IoConnection {
            id: 1,
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            conn_type: ConnectionType::Tcp,
            state: ConnectionState::Connected,
            bytes_sent: 0,
            bytes_received: 0,
            connected_at: std::time::Instant::now(),
        };
        
        assert_eq!(conn.id, 1);
        assert_eq!(conn.conn_type, ConnectionType::Tcp);
        assert_eq!(conn.state, ConnectionState::Connected);
    }
}