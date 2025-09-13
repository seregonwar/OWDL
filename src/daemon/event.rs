//! AWDL Daemon Event module
//!
//! This module handles event management for the AWDL daemon.
//! It provides an event loop system for handling various AWDL events.

use crate::{AwdlError, Result};
use crate::daemon::io::IoEvent;

use std::sync::Arc;
use tokio::sync::{RwLock, Mutex, mpsc, oneshot};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;
use log::error;

/// Event types in the AWDL system
#[derive(Debug, Clone)]
pub enum AwdlEvent {
    /// I/O related events
    Io(IoEvent),
    /// Timer events
    Timer {
        id: Uuid,
        name: String,
    },
    /// State change events
    StateChange {
        old_state: String,
        new_state: String,
    },
    /// Peer events
    Peer {
        peer_id: String,
        event_type: PeerEventType,
    },
    /// Synchronization events
    Sync {
        sync_type: SyncEventType,
        data: Vec<u8>,
    },
    /// Election events
    Election {
        election_type: ElectionEventType,
    },
    /// Channel events
    Channel {
        channel_id: u8,
        event_type: ChannelEventType,
    },
    /// System events
    System {
        event_type: SystemEventType,
        message: String,
    },
    /// Service events
    Service(crate::daemon::service::ServiceEvent),
    /// Custom events
    Custom {
        name: String,
        data: Vec<u8>,
    },
}

/// Peer event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerEventType {
    /// Peer discovered
    Discovered,
    /// Peer connected
    Connected,
    /// Peer disconnected
    Disconnected,
    /// Peer updated
    Updated,
    /// Peer timeout
    Timeout,
}

/// Synchronization event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncEventType {
    /// Sync tree updated
    TreeUpdated,
    /// Sync parameters changed
    ParamsChanged,
    /// Sync state changed
    StateChanged,
    /// Sync timeout
    Timeout,
}

/// Election event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ElectionEventType {
    /// Election started
    Started,
    /// New master elected
    MasterElected,
    /// Election parameters changed
    ParamsChanged,
    /// Election timeout
    Timeout,
}

/// Channel event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelEventType {
    /// Channel switched
    Switched,
    /// Channel sequence updated
    SequenceUpdated,
    /// Channel encoding changed
    EncodingChanged,
}

/// System event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemEventType {
    /// System started
    Started,
    /// System stopped
    Stopped,
    /// System error
    Error,
    /// Configuration changed
    ConfigChanged,
    /// Statistics updated
    StatsUpdated,
}

/// Event priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventPriority {
    /// Low priority events
    Low = 0,
    /// Normal priority events
    Normal = 1,
    /// High priority events
    High = 2,
    /// Critical priority events
    Critical = 3,
}

/// Event handler trait
#[async_trait::async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle an event
    async fn handle_event(&self, event: &AwdlEvent) -> Result<()>;
    
    /// Get handler name
    fn name(&self) -> &str;
    
    /// Check if handler can handle this event type
    fn can_handle(&self, event: &AwdlEvent) -> bool;
}

/// Timer information
#[derive(Debug, Clone)]
pub struct TimerInfo {
    /// Timer ID
    pub id: Uuid,
    /// Timer name
    pub name: String,
    /// Timer interval
    pub interval: Duration,
    /// Whether timer repeats
    pub repeating: bool,
    /// Next fire time
    pub next_fire: Instant,
    /// Timer enabled state
    pub enabled: bool,
}

/// Event statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventStats {
    /// Total events processed
    pub events_processed: u64,
    /// Events by type
    pub events_by_type: HashMap<String, u64>,
    /// Events by priority
    pub events_by_priority: HashMap<String, u64>,
    /// Average processing time (microseconds)
    pub avg_processing_time: f64,
    /// Total processing time
    pub total_processing_time: u64,
    /// Number of handler errors
    pub handler_errors: u64,
    /// Queue size statistics
    pub max_queue_size: usize,
    pub current_queue_size: usize,
}

/// Event configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventConfig {
    /// Maximum event queue size
    pub max_queue_size: usize,
    /// Event processing timeout
    pub processing_timeout: Duration,
    /// Enable event statistics
    pub enable_stats: bool,
    /// Maximum number of handlers per event
    pub max_handlers_per_event: usize,
    /// Timer resolution
    pub timer_resolution: Duration,
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10000,
            processing_timeout: Duration::from_secs(30),
            enable_stats: true,
            max_handlers_per_event: 10,
            timer_resolution: Duration::from_millis(10),
        }
    }
}

/// Event with metadata
#[derive(Debug, Clone)]
struct EventWithMetadata {
    /// The event
    event: AwdlEvent,
    /// Event priority
    priority: EventPriority,
    /// Event timestamp
    _timestamp: Instant,
    /// Event ID
    _id: Uuid,
}

/// Event Manager
pub struct EventManager {
    /// Event configuration
    config: EventConfig,
    /// Event queue sender
    event_sender: mpsc::UnboundedSender<EventWithMetadata>,
    /// Event queue receiver
    event_receiver: Arc<Mutex<mpsc::UnboundedReceiver<EventWithMetadata>>>,
    /// Event handlers
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
    /// Active timers
    timers: Arc<RwLock<HashMap<Uuid, TimerInfo>>>,
    /// Event statistics
    stats: Arc<RwLock<EventStats>>,
    /// Running state
    running: Arc<RwLock<bool>>,
    /// Shutdown sender
    shutdown_sender: Option<oneshot::Sender<()>>,
}

impl std::fmt::Debug for EventManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventManager")
            .field("config", &self.config)
            .field("running", &self.running)
            .field("handlers", &format!("[handlers]"))
            .field("timers", &format!("[timers]"))
            .field("stats", &format!("[stats]"))
            .finish()
    }
}

impl EventManager {
    /// Create new event manager
    pub fn new(config: EventConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            event_sender,
            event_receiver: Arc::new(Mutex::new(event_receiver)),
            handlers: Arc::new(RwLock::new(Vec::new())),
            timers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EventStats::default())),
            running: Arc::new(RwLock::new(false)),
            shutdown_sender: None,
        }
    }

    /// Initialize event manager
    pub async fn init(&mut self) -> Result<()> {
        log::info!("Initializing event manager...");
        
        // Clear any existing handlers and timers
        self.handlers.write().await.clear();
        self.timers.write().await.clear();
        
        // Reset stats
        let mut stats = self.stats.write().await;
        *stats = EventStats::default();
        
        log::info!("Event manager initialized successfully");
        Ok(())
    }

    /// Start event manager
    pub async fn start(&mut self) -> Result<()> {
        log::info!("Starting event manager...");
        
        *self.running.write().await = true;
        
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        self.shutdown_sender = Some(shutdown_sender);
        
        // Start event processing loop
        let receiver = Arc::clone(&self.event_receiver);
        let handlers = Arc::clone(&self.handlers);
        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            Self::run_event_loop(receiver, handlers, stats, running, config, shutdown_receiver).await;
        });
        
        // Start timer loop
        let timers = Arc::clone(&self.timers);
        let event_sender = self.event_sender.clone();
        let running_clone = Arc::clone(&self.running);
        let timer_resolution = self.config.timer_resolution;
        
        tokio::spawn(async move {
            Self::run_timer_loop(timers, event_sender, running_clone, timer_resolution).await;
        });
        
        log::info!("Event manager started successfully");
        Ok(())
    }

    /// Stop event manager
    pub async fn stop(&mut self) -> Result<()> {
        log::info!("Stopping event manager...");
        
        *self.running.write().await = false;
        
        // Send shutdown signal
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        
        // Clear timers
        self.timers.write().await.clear();
        
        log::info!("Event manager stopped successfully");
        Ok(())
    }

    /// Emit an event
    pub async fn emit(&self, event: AwdlEvent, priority: EventPriority) -> Result<()> {
        let event_with_metadata = EventWithMetadata {
            event,
            priority,
            _timestamp: Instant::now(),
            _id: Uuid::new_v4(),
        };
        
        self.event_sender.send(event_with_metadata)
            .map_err(|e| AwdlError::Event(format!("Failed to emit event: {}", e)))?;
        
        Ok(())
    }

    /// Add event handler
    pub async fn add_handler(&self, handler: Arc<dyn EventHandler>) {
        self.handlers.write().await.push(handler);
    }

    /// Remove event handler
    pub async fn remove_handler(&self, handler: Arc<dyn EventHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.retain(|h| h.name() != handler.name());
    }

    /// Add timer
    pub async fn add_timer(
        &self,
        name: String,
        interval: Duration,
        repeating: bool,
    ) -> Uuid {
        let timer_id = Uuid::new_v4();
        let timer = TimerInfo {
            id: timer_id,
            name,
            interval,
            repeating,
            next_fire: Instant::now() + interval,
            enabled: true,
        };
        
        self.timers.write().await.insert(timer_id, timer);
        timer_id
    }

    /// Remove timer
    pub async fn remove_timer(&self, timer_id: Uuid) -> bool {
        self.timers.write().await.remove(&timer_id).is_some()
    }

    /// Enable/disable timer
    pub async fn set_timer_enabled(&self, timer_id: Uuid, enabled: bool) -> bool {
        if let Some(timer) = self.timers.write().await.get_mut(&timer_id) {
            timer.enabled = enabled;
            if enabled {
                timer.next_fire = Instant::now() + timer.interval;
            }
            true
        } else {
            false
        }
    }

    /// Get event statistics
    pub async fn get_stats(&self) -> EventStats {
        self.stats.read().await.clone()
    }

    /// Reset event statistics
    pub async fn reset_stats(&self) {
        *self.stats.write().await = EventStats::default();
    }

    /// Get active timers
    pub async fn get_timers(&self) -> Vec<TimerInfo> {
        self.timers.read().await.values().cloned().collect()
    }

    /// Process pending events in the queue
    pub async fn process_events(&self) -> Result<usize> {
        let mut processed_count = 0;
        let receiver = Arc::clone(&self.event_receiver);
        let handlers = Arc::clone(&self.handlers);
        let stats = Arc::clone(&self.stats);
        
        // Process events in a non-blocking manner
        let mut receiver_guard = receiver.lock().await;
        while let Ok(event_with_metadata) = receiver_guard.try_recv() {
            let start_time = Instant::now();
            let success = match Self::process_event(&event_with_metadata, &handlers).await {
                Ok(_) => true,
                Err(e) => {
                    error!("Failed to process event: {}", e);
                    false
                }
            };
            
            let processing_time = start_time.elapsed();
            Self::update_stats(&stats, &event_with_metadata, processing_time, success).await;
            processed_count += 1;
        }
        
        Ok(processed_count)
    }

    /// Event processing loop
    async fn run_event_loop(
        receiver: Arc<Mutex<mpsc::UnboundedReceiver<EventWithMetadata>>>,
        handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
        stats: Arc<RwLock<EventStats>>,
        running: Arc<RwLock<bool>>,
        config: EventConfig,
        mut shutdown_receiver: oneshot::Receiver<()>,
    ) {
        let mut receiver_guard = receiver.lock().await;
        
        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = &mut shutdown_receiver => {
                    log::info!("Event loop received shutdown signal");
                    break;
                }
                
                // Process events
                event_result = receiver_guard.recv() => {
                    if !*running.read().await {
                        break;
                    }
                    
                    match event_result {
                        Some(event_with_metadata) => {
                            let start_time = Instant::now();
                            
                            // Process event with timeout
                            let processing_result = tokio::time::timeout(
                                config.processing_timeout,
                                Self::process_event(&event_with_metadata, &handlers)
                            ).await;
                            
                            let processing_time = start_time.elapsed();
                            
                            // Update statistics
                            if config.enable_stats {
                                Self::update_stats(
                                    &stats,
                                    &event_with_metadata,
                                    processing_time,
                                    processing_result.is_ok()
                                ).await;
                            }
                            
                            match processing_result {
                                Ok(Ok(())) => {
                                    // Event processed successfully
                                }
                                Ok(Err(e)) => {
                                    log::error!("Event processing error: {}", e);
                                }
                                Err(_) => {
                                    log::error!("Event processing timeout");
                                }
                            }
                        }
                        None => {
                            // Channel closed
                            break;
                        }
                    }
                }
            }
        }
        
        log::info!("Event processing loop terminated");
    }

    /// Process a single event
    async fn process_event(
        event_with_metadata: &EventWithMetadata,
        handlers: &Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
    ) -> Result<()> {
        let handlers_guard = handlers.read().await;
        
        for handler in handlers_guard.iter() {
            if handler.can_handle(&event_with_metadata.event) {
                if let Err(e) = handler.handle_event(&event_with_metadata.event).await {
                    log::error!("Handler '{}' error: {}", handler.name(), e);
                }
            }
        }
        
        Ok(())
    }

    /// Update event statistics
    async fn update_stats(
        stats: &Arc<RwLock<EventStats>>,
        event_with_metadata: &EventWithMetadata,
        processing_time: Duration,
        success: bool,
    ) {
        let mut stats_guard = stats.write().await;
        
        stats_guard.events_processed += 1;
        
        // Update by type
        let event_type = Self::get_event_type_name(&event_with_metadata.event);
        *stats_guard.events_by_type.entry(event_type).or_insert(0) += 1;
        
        // Update by priority
        let priority_name = format!("{:?}", event_with_metadata.priority);
        *stats_guard.events_by_priority.entry(priority_name).or_insert(0) += 1;
        
        // Update processing time
        let processing_micros = processing_time.as_micros() as u64;
        stats_guard.total_processing_time += processing_micros;
        stats_guard.avg_processing_time = 
            stats_guard.total_processing_time as f64 / stats_guard.events_processed as f64;
        
        // Update error count
        if !success {
            stats_guard.handler_errors += 1;
        }
    }

    /// Get event type name for statistics
    fn get_event_type_name(event: &AwdlEvent) -> String {
        match event {
            AwdlEvent::Io(_) => "Io".to_string(),
            AwdlEvent::Timer { .. } => "Timer".to_string(),
            AwdlEvent::StateChange { .. } => "StateChange".to_string(),
            AwdlEvent::Peer { .. } => "Peer".to_string(),
            AwdlEvent::Sync { .. } => "Sync".to_string(),
            AwdlEvent::Election { .. } => "Election".to_string(),
            AwdlEvent::Channel { .. } => "Channel".to_string(),
            AwdlEvent::System { .. } => "System".to_string(),
            AwdlEvent::Service(_) => "Service".to_string(),
            AwdlEvent::Custom { .. } => "Custom".to_string(),
        }
    }

    /// Timer processing loop
    async fn run_timer_loop(
        timers: Arc<RwLock<HashMap<Uuid, TimerInfo>>>,
        event_sender: mpsc::UnboundedSender<EventWithMetadata>,
        running: Arc<RwLock<bool>>,
        resolution: Duration,
    ) {
        while *running.read().await {
            let now = Instant::now();
            let mut fired_timers = Vec::new();
            
            // Check for fired timers
            {
                let mut timers_guard = timers.write().await;
                for (timer_id, timer) in timers_guard.iter_mut() {
                    if timer.enabled && now >= timer.next_fire {
                        fired_timers.push((*timer_id, timer.name.clone()));
                        
                        if timer.repeating {
                            timer.next_fire = now + timer.interval;
                        } else {
                            timer.enabled = false;
                        }
                    }
                }
            }
            
            // Emit timer events
            for (timer_id, timer_name) in fired_timers {
                let timer_event = AwdlEvent::Timer {
                    id: timer_id,
                    name: timer_name,
                };
                
                let event_with_metadata = EventWithMetadata {
                    event: timer_event,
                    priority: EventPriority::Normal,
                    _timestamp: now,
                    _id: Uuid::new_v4(),
                };
                
                if let Err(e) = event_sender.send(event_with_metadata) {
                    log::error!("Failed to emit timer event: {}", e);
                }
            }
            
            // Sleep for timer resolution
            tokio::time::sleep(resolution).await;
        }
        
        log::info!("Timer loop terminated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestHandler {
        name: String,
        call_count: Arc<AtomicUsize>,
    }

    impl TestHandler {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }
        
        fn get_call_count(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl EventHandler for TestHandler {
        async fn handle_event(&self, _event: &AwdlEvent) -> Result<()> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        
        fn name(&self) -> &str {
            &self.name
        }
        
        fn can_handle(&self, _event: &AwdlEvent) -> bool {
            true
        }
    }

    #[test]
    fn test_event_config_default() {
        let config = EventConfig::default();
        assert_eq!(config.max_queue_size, 10000);
        assert_eq!(config.max_handlers_per_event, 10);
        assert!(config.enable_stats);
    }

    #[tokio::test]
    async fn test_event_manager_creation() {
        let config = EventConfig::default();
        let manager = EventManager::new(config);
        assert!(!*manager.running.read().await);
    }

    #[tokio::test]
    async fn test_timer_management() {
        let config = EventConfig::default();
        let manager = EventManager::new(config);
        
        let timer_id = manager.add_timer(
            "test_timer".to_string(),
            Duration::from_millis(100),
            false,
        ).await;
        
        let timers = manager.get_timers().await;
        assert_eq!(timers.len(), 1);
        assert_eq!(timers[0].name, "test_timer");
        
        let removed = manager.remove_timer(timer_id).await;
        assert!(removed);
        
        let timers = manager.get_timers().await;
        assert_eq!(timers.len(), 0);
    }

    #[tokio::test]
    async fn test_event_handler_management() {
        let config = EventConfig::default();
        let manager = EventManager::new(config);
        
        let handler: Arc<dyn EventHandler> = Arc::new(TestHandler::new("test_handler"));
        manager.add_handler(Arc::clone(&handler)).await;
        
        let handlers = manager.handlers.read().await;
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].name(), "test_handler");
    }

    #[test]
    fn test_event_priority_ordering() {
        assert!(EventPriority::Critical > EventPriority::High);
        assert!(EventPriority::High > EventPriority::Normal);
        assert!(EventPriority::Normal > EventPriority::Low);
    }
}