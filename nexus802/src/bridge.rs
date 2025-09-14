//! WSL2 Bridge backend implementation (Tier 2)
//! 
//! This module implements communication with a Linux bridge running in WSL2
//! to access 802.11 monitor mode capabilities that may not be available
//! through Windows WDI/NDIS interfaces.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::timeout;

use crate::config::BridgeConfig;
use crate::phy::{
    ChannelConfig, FrameMetadata, FrameSourceType, MonitorModeType, PhyBackend, PhyCapabilities,
    PhyError, PhyStatistics, TxMetadata,
};
use crate::radiotap::EnhancedRadiotapHeader;

/// WSL2 Bridge backend
pub struct BridgeBackend {
    config: BridgeConfig,
    state: Arc<RwLock<BridgeState>>,
    control_channel: Option<mpsc::UnboundedSender<BridgeCommand>>,
    frame_receiver: Arc<Mutex<mpsc::UnboundedReceiver<(Bytes, FrameMetadata)>>>,
    statistics: Arc<RwLock<PhyStatistics>>,
}

/// Bridge connection state
#[derive(Debug, Clone)]
struct BridgeState {
    connected: bool,
    wsl_process_id: Option<u32>,
    bridge_version: Option<String>,
    capabilities: Option<PhyCapabilities>,
    current_channel: Option<ChannelConfig>,
    monitor_active: bool,
    last_frame_time: Option<Instant>,
    error_count: u32,
}

/// Commands sent to the bridge control channel
#[derive(Debug, Clone, Serialize, Deserialize)]
enum BridgeCommand {
    Initialize,
    GetCapabilities,
    EnableMonitor { mode: MonitorModeType },
    DisableMonitor,
    SetChannel { config: ChannelConfig },
    GetChannel,
    InjectFrame { data: Vec<u8>, metadata: TxMetadata },
    GetStatistics,
    Shutdown,
}

/// Responses from the bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
enum BridgeResponse {
    Success,
    Error { message: String },
    Capabilities { caps: PhyCapabilities },
    Channel { config: ChannelConfig },
    Statistics { stats: PhyStatistics },
    Frame { data: Vec<u8>, metadata: FrameMetadata },
}

/// Bridge protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BridgeMessage {
    id: u32,
    timestamp: u64,
    payload: BridgeMessagePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum BridgeMessagePayload {
    Command(BridgeCommand),
    Response(BridgeResponse),
    FrameData { data: Vec<u8>, metadata: FrameMetadata },
    Heartbeat,
}

impl BridgeBackend {
    /// Create a new bridge backend
    pub fn new(config: BridgeConfig) -> Self {
        let (frame_sender, frame_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            state: Arc::new(RwLock::new(BridgeState {
                connected: false,
                wsl_process_id: None,
                bridge_version: None,
                capabilities: None,
                current_channel: None,
                monitor_active: false,
                last_frame_time: None,
                error_count: 0,
            })),
            control_channel: None,
            frame_receiver: Arc::new(Mutex::new(frame_receiver)),
            statistics: Arc::new(RwLock::new(PhyStatistics::default())),
        }
    }
    
    /// Launch WSL2 bridge process
    async fn launch_bridge_process(&mut self) -> Result<tokio::process::Child, PhyError> {
        log::info!("Launching WSL2 bridge process...");
        
        let mut cmd = Command::new("wsl.exe");
        cmd.args(&[
            "-d", &self.config.wsl_distribution,
            "-e", &self.config.bridge_executable,
            "--control-pipe", &self.config.control_pipe_name,
            "--rx-pipe", &self.config.rx_pipe_name,
            "--tx-pipe", &self.config.tx_pipe_name,
        ]);
        
        if self.config.use_shared_memory {
            cmd.args(&[
                "--shared-memory-size", &self.config.shared_memory_size.to_string(),
            ]);
        }
        
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .stdin(Stdio::null());
        
        let child = cmd.spawn().map_err(|e| PhyError::Io(e))?;
        
        log::info!("WSL2 bridge process launched with PID: {:?}", child.id());
        
        Ok(child)
    }
    
    /// Establish connection to bridge
    async fn connect_to_bridge(&mut self) -> Result<(), PhyError> {
        log::info!("Connecting to WSL2 bridge...");
        
        // Launch bridge process
        let mut bridge_process = self.launch_bridge_process().await?;
        
        // Wait for bridge to start up
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Try to connect to named pipes
        let control_pipe = self.connect_control_pipe().await?;
        let rx_pipe = self.connect_rx_pipe().await?;
        
        // Start communication tasks
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        self.control_channel = Some(control_tx);
        
        // Start control channel handler
        let state_clone = Arc::clone(&self.state);
        let config_clone = self.config.clone();
        tokio::spawn(async move {
            Self::handle_control_channel(control_pipe, control_rx, state_clone, config_clone).await;
        });
        
        // Start frame receiver
        let frame_sender = {
            let receiver = Arc::clone(&self.frame_receiver);
            let mut receiver_guard = receiver.lock().await;
            let (sender, new_receiver) = mpsc::unbounded_channel();
            *receiver_guard = new_receiver;
            sender
        };
        
        let stats_clone = Arc::clone(&self.statistics);
        tokio::spawn(async move {
            Self::handle_frame_reception(rx_pipe, frame_sender, stats_clone).await;
        });
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.connected = true;
            state.wsl_process_id = bridge_process.id();
        }
        
        // Send initialization command
        self.send_command(BridgeCommand::Initialize).await?;
        
        log::info!("Successfully connected to WSL2 bridge");
        Ok(())
    }
    
    /// Connect to control pipe
    async fn connect_control_pipe(&self) -> Result<TcpStream, PhyError> {
        // MVP: connect to localhost control port (WSL2 bridge should listen here)
        TcpStream::connect(("127.0.0.1", 9000)).await.map_err(PhyError::Io)
    }
    
    /// Connect to RX data pipe
    async fn connect_rx_pipe(&self) -> Result<TcpStream, PhyError> {
        // MVP: connect to localhost data port (WSL2 bridge should send FrameData JSON lines)
        TcpStream::connect(("127.0.0.1", 9001)).await.map_err(PhyError::Io)
    }
    
    /// Handle control channel communication
    async fn handle_control_channel(
        mut stream: TcpStream,
        mut command_rx: mpsc::UnboundedReceiver<BridgeCommand>,
        state: Arc<RwLock<BridgeState>>,
        config: BridgeConfig,
    ) {
        let mut message_id = 0u32;
        let mut pending_responses: std::collections::HashMap<u32, tokio::sync::oneshot::Sender<BridgeResponse>> = 
            std::collections::HashMap::new();
        
        loop {
            tokio::select! {
                // Handle outgoing commands
                Some(command) = command_rx.recv() => {
                    message_id += 1;
                    let message = BridgeMessage {
                        id: message_id,
                        timestamp: chrono::Utc::now().timestamp_micros() as u64,
                        payload: BridgeMessagePayload::Command(command),
                    };
                    
                    if let Ok(mut serialized) = serde_json::to_vec(&message) {
                        // Send as line-delimited JSON
                        serialized.push(b'\n');
                        if let Err(e) = stream.write_all(&serialized).await {
                            log::error!("Control channel write failed: {}", e);
                            break;
                        }
                    }
                }
                
                // Simplified - skip message reading for compilation
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
        
        log::warn!("Control channel handler exiting");
    }
    
    /// Handle frame reception from RX pipe
    async fn handle_frame_reception(
        stream: TcpStream,
        frame_sender: mpsc::UnboundedSender<(Bytes, FrameMetadata)>,
        statistics: Arc<RwLock<PhyStatistics>>,
    ) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF
                    break;
                }
                Ok(_) => {
                    // Expect JSON BridgeMessage with FrameData
                    match serde_json::from_str::<BridgeMessage>(&line) {
                        Ok(msg) => {
                            match msg.payload {
                                BridgeMessagePayload::FrameData { data, metadata } => {
                                    let bytes = Bytes::from(data);
                                    {
                                        let mut stats = statistics.write().await;
                                        stats.frames_received += 1;
                                        stats.bytes_received += bytes.len() as u64;
                                    }
                                    if frame_sender.send((bytes, metadata)).is_err() {
                                        break;
                                    }
                                }
                                BridgeMessagePayload::Response(_r) => {
                                    // TODO: correlate with pending requests
                                }
                                BridgeMessagePayload::Heartbeat => {}
                                BridgeMessagePayload::Command(_) => {}
                            }
                        }
                        Err(e) => {
                            // Fallback: try parse as raw frame bytes (hex-encoded not supported here)
                            log::warn!("Failed to parse frame line as JSON: {}", e);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Frame reception read error: {}", e);
                    break;
                }
            }
        }
    }
    
    /// Read a bridge message from pipe (simplified)
    async fn read_bridge_message(
        _stream: &mut TcpStream
    ) -> Result<BridgeMessage, PhyError> {
        // Not used in MVP (handled by handle_frame_reception)
        Err(PhyError::Hardware { message: "Not implemented".to_string() })
    }
    
    /// Parse frame data from RX pipe
    fn parse_frame_data(data: &[u8]) -> Result<(Bytes, FrameMetadata), PhyError> {
        // Simplified frame parsing - in reality this would parse the bridge protocol
        if data.len() < 8 {
            return Err(PhyError::Hardware {
                message: "Frame data too short".to_string(),
            });
        }
        
        // For now, assume the data contains a radiotap header + 802.11 frame
        let frame_data = Bytes::copy_from_slice(data);
        
        // Parse radiotap header to extract metadata
        let metadata = match EnhancedRadiotapHeader::from_bytes(data) {
            Ok((header, _)) => FrameMetadata {
                timestamp: header.timestamp.unwrap_or(0),
                frequency: header.channel_frequency.unwrap_or(2437),
                channel_flags: header.channel_flags.unwrap_or(0),
                signal_dbm: header.antenna_signal,
                noise_dbm: header.antenna_noise,
                snr_db: header.quality_snr.map(|s| s as u8),
                fcs_present: true,
                source_type: FrameSourceType::Bridge,
                vendor_data: header.vendor_data,
            },
            Err(_) => {
                // Fallback metadata if radiotap parsing fails
                FrameMetadata {
                    timestamp: chrono::Utc::now().timestamp_micros() as u64,
                    frequency: 2437,
                    channel_flags: 0,
                    signal_dbm: None,
                    noise_dbm: None,
                    snr_db: None,
                    fcs_present: true,
                    source_type: FrameSourceType::Bridge,
                    vendor_data: None,
                }
            }
        };
        
        Ok((frame_data, metadata))
    }
    
    /// Send command to bridge
    async fn send_command(&self, command: BridgeCommand) -> Result<(), PhyError> {
        if let Some(ref control_tx) = self.control_channel {
            control_tx.send(command).map_err(|_| PhyError::Hardware {
                message: "Control channel closed".to_string(),
            })?;
            Ok(())
        } else {
            Err(PhyError::BackendUnavailable {
                backend: "WSL2 Bridge".to_string(),
            })
        }
    }
}

#[async_trait]
impl PhyBackend for BridgeBackend {
    async fn capabilities(&self) -> Result<PhyCapabilities, PhyError> {
        let state = self.state.read().await;
        if let Some(ref caps) = state.capabilities {
            Ok(caps.clone())
        } else {
            // Default capabilities for bridge backend
            Ok(PhyCapabilities {
                monitor_mode: true,
                raw_frame_indication: true,
                frame_injection: true,
                channel_switching: true,
                hardware_timestamps: true,
                signal_strength: true,
                fcs_present: true,
                supported_monitor_modes: vec![MonitorModeType::Bridge],
                supported_channels: (1..=14).map(|ch| 2412 + (ch - 1) * 5).collect(), // 2.4GHz channels
                max_frame_size: crate::MAX_FRAME_SIZE,
                version: "WSL2-Bridge-1.0".to_string(),
                extensions: std::collections::HashMap::new(),
            })
        }
    }
    
    async fn initialize(&mut self) -> Result<(), PhyError> {
        log::info!("Initializing WSL2 bridge backend");
        
        self.connect_to_bridge().await?;
        
        // Get capabilities from bridge
        self.send_command(BridgeCommand::GetCapabilities).await?;
        
        Ok(())
    }
    
    async fn enable_monitor_mode(&mut self, mode: MonitorModeType) -> Result<(), PhyError> {
        log::info!("Enabling monitor mode: {:?}", mode);
        
        self.send_command(BridgeCommand::EnableMonitor { mode }).await?;
        
        {
            let mut state = self.state.write().await;
            state.monitor_active = true;
        }
        
        Ok(())
    }
    
    async fn disable_monitor_mode(&mut self) -> Result<(), PhyError> {
        log::info!("Disabling monitor mode");
        
        self.send_command(BridgeCommand::DisableMonitor).await?;
        
        {
            let mut state = self.state.write().await;
            state.monitor_active = false;
        }
        
        Ok(())
    }
    
    async fn set_channel(&mut self, config: ChannelConfig) -> Result<(), PhyError> {
        log::info!("Setting channel: {:?}", config);
        
        self.send_command(BridgeCommand::SetChannel { config: config.clone() }).await?;
        
        {
            let mut state = self.state.write().await;
            state.current_channel = Some(config);
        }
        
        Ok(())
    }
    
    async fn get_channel(&self) -> Result<ChannelConfig, PhyError> {
        let state = self.state.read().await;
        state.current_channel.clone().ok_or(PhyError::Hardware {
            message: "No channel configured".to_string(),
        })
    }
    
    async fn recv_frame(&mut self) -> Result<Option<(Vec<u8>, FrameMetadata)>, PhyError> {
        let mut receiver = self.frame_receiver.lock().await;
        match receiver.try_recv() {
            Ok((data, metadata)) => {
                {
                    let mut state = self.state.write().await;
                    state.last_frame_time = Some(Instant::now());
                }
                Ok(Some((data.to_vec(), metadata)))
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(PhyError::Hardware {
                message: "Frame receiver disconnected".to_string(),
            }),
        }
    }
    
    async fn recv_frame_timeout(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<Option<(Vec<u8>, FrameMetadata)>, PhyError> {
        let mut receiver = self.frame_receiver.lock().await;
        match timeout(timeout_duration, receiver.recv()).await {
            Ok(Some((data, metadata))) => {
                {
                    let mut state = self.state.write().await;
                    state.last_frame_time = Some(Instant::now());
                }
                Ok(Some((data.to_vec(), metadata)))
            }
            Ok(None) => Err(PhyError::Hardware {
                message: "Frame receiver disconnected".to_string(),
            }),
            Err(_) => Err(PhyError::Timeout),
        }
    }
    
    async fn inject_frame(&mut self, frame: &[u8], metadata: TxMetadata) -> Result<(), PhyError> {
        log::debug!("Injecting frame: {} bytes", frame.len());
        
        self.send_command(BridgeCommand::InjectFrame {
            data: frame.to_vec(),
            metadata,
        }).await?;
        
        {
            let mut stats = self.statistics.write().await;
            stats.frames_transmitted += 1;
            stats.bytes_transmitted += frame.len() as u64;
        }
        
        Ok(())
    }
    
    async fn get_statistics(&self) -> Result<PhyStatistics, PhyError> {
        let stats = self.statistics.read().await;
        Ok(stats.clone())
    }
    
    async fn shutdown(&mut self) -> Result<(), PhyError> {
        log::info!("Shutting down WSL2 bridge backend");
        
        if let Some(ref control_tx) = self.control_channel {
            let _ = control_tx.send(BridgeCommand::Shutdown);
        }
        
        {
            let mut state = self.state.write().await;
            state.connected = false;
            state.monitor_active = false;
        }
        
        Ok(())
    }
}

impl Default for PhyStatistics {
    fn default() -> Self {
        Self {
            frames_received: 0,
            frames_transmitted: 0,
            bytes_received: 0,
            bytes_transmitted: 0,
            frames_dropped: 0,
            avg_fps: 0.0,
            cpu_usage: 0.0,
            memory_usage: 0,
            avg_latency_us: 0,
        }
    }
}
