//! AWDL Daemon Service module
//!
//! This module provides service management functionality for the AWDL daemon.
//! It handles service registration, discovery, and lifecycle management.

use crate::{AwdlError, Result};

use crate::daemon::event::AwdlEvent;


use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Service types supported by AWDL
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceType {
    /// File sharing service
    FileSharing,
    /// Screen sharing service
    ScreenSharing,
    /// Audio streaming service
    AudioStreaming,
    /// Video streaming service
    VideoStreaming,
    /// Chat/messaging service
    Messaging,
    /// Custom service with name
    Custom(String),
}

/// Service state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceState {
    /// Service is inactive
    Inactive,
    /// Service is starting up
    Starting,
    /// Service is active and available
    Active,
    /// Service is stopping
    Stopping,
    /// Service has failed
    Failed(String),
}

/// Service priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ServicePriority {
    /// Low priority service
    Low = 1,
    /// Normal priority service
    Normal = 2,
    /// High priority service
    High = 3,
    /// Critical priority service
    Critical = 4,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Unique service identifier
    pub id: Uuid,
    /// Service type
    pub service_type: ServiceType,
    /// Service name
    pub name: String,
    /// Service description
    pub description: String,
    /// Service version
    pub version: String,
    /// Service state
    pub state: ServiceState,
    /// Service priority
    pub priority: ServicePriority,
    /// Service endpoint address
    pub endpoint: Option<SocketAddr>,
    /// Service metadata
    pub metadata: HashMap<String, String>,
    /// Service capabilities
    pub capabilities: Vec<String>,
    /// Service requirements
    pub requirements: Vec<String>,
    /// Service owner peer
    pub owner_peer: Option<String>,
    /// Service creation time
    pub created_at: DateTime<Utc>,
    /// Service last update time
    pub updated_at: DateTime<Utc>,
    /// Service TTL (time to live)
    pub ttl: Duration,
}

/// Service advertisement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAdvertisement {
    /// Service information
    pub service: ServiceInfo,
    /// Advertisement sequence number
    pub sequence: u32,
    /// Advertisement timestamp
    pub timestamp: u64,
    /// Advertisement signature (for security)
    pub signature: Option<Vec<u8>>,
}

/// Service discovery query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceQuery {
    /// Query ID
    pub id: Uuid,
    /// Service type filter
    pub service_type: Option<ServiceType>,
    /// Service name filter
    pub name_filter: Option<String>,
    /// Capability requirements
    pub required_capabilities: Vec<String>,
    /// Maximum results
    pub max_results: Option<usize>,
    /// Query timeout
    pub timeout: Duration,
}

/// Service discovery response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    /// Query ID this response is for
    pub query_id: Uuid,
    /// Found services
    pub services: Vec<ServiceInfo>,
    /// Response timestamp
    pub timestamp: u64,
    /// Responding peer
    pub responder: String,
}

/// Service statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceStats {
    /// Total services registered
    pub total_services: u64,
    /// Active services count
    pub active_services: u64,
    /// Failed services count
    pub failed_services: u64,
    /// Total advertisements sent
    pub advertisements_sent: u64,
    /// Total advertisements received
    pub advertisements_received: u64,
    /// Total queries sent
    pub queries_sent: u64,
    /// Total queries received
    pub queries_received: u64,
    /// Total responses sent
    pub responses_sent: u64,
    /// Total responses received
    pub responses_received: u64,
    /// Service discovery latency (ms)
    pub discovery_latency_ms: f64,
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Enable service discovery
    pub enable_discovery: bool,
    /// Service advertisement interval (ms)
    pub advertisement_interval: u64,
    /// Service query timeout (ms)
    pub query_timeout: u64,
    /// Maximum services per peer
    pub max_services_per_peer: usize,
    /// Service cache size
    pub service_cache_size: usize,
    /// Service TTL (seconds)
    pub default_service_ttl: u64,
    /// Enable service authentication
    pub enable_auth: bool,
    /// Enable service encryption
    pub enable_encryption: bool,
}

/// Service event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceEvent {
    /// Service registered
    ServiceRegistered {
        service_id: Uuid,
        service_type: ServiceType,
    },
    /// Service unregistered
    ServiceUnregistered {
        service_id: Uuid,
    },
    /// Service state changed
    ServiceStateChanged {
        service_id: Uuid,
        old_state: ServiceState,
        new_state: ServiceState,
    },
    /// Service discovered
    ServiceDiscovered {
        service: ServiceInfo,
        peer: String,
    },
    /// Service lost
    ServiceLost {
        service_id: Uuid,
        peer: String,
    },
    /// Query received
    QueryReceived {
        query: ServiceQuery,
        peer: String,
    },
    /// Response received
    ResponseReceived {
        response: ServiceResponse,
        peer: String,
    },
}

/// Service manager
#[derive(Debug)]
pub struct ServiceManager {
    /// Configuration
    config: ServiceConfig,
    /// Local services
    local_services: Arc<RwLock<HashMap<Uuid, ServiceInfo>>>,
    /// Remote services (peer -> services)
    remote_services: Arc<RwLock<HashMap<String, HashMap<Uuid, ServiceInfo>>>>,
    /// Pending queries
    pending_queries: Arc<RwLock<HashMap<Uuid, ServiceQuery>>>,
    /// Service statistics
    stats: Arc<RwLock<ServiceStats>>,
    /// Event sender
    event_sender: Option<mpsc::UnboundedSender<AwdlEvent>>,
    /// Service sequence counter
    sequence_counter: Arc<RwLock<u32>>,
}

/// Service registry trait
pub trait ServiceRegistry: Send + Sync {
    /// Register a service
    fn register_service(&self, service: ServiceInfo) -> Result<()>;
    
    /// Unregister a service
    fn unregister_service(&self, service_id: Uuid) -> Result<()>;
    
    /// Get service by ID
    fn get_service(&self, service_id: Uuid) -> Option<ServiceInfo>;
    
    /// List all services
    fn list_services(&self) -> Vec<ServiceInfo>;
    
    /// Find services by type
    fn find_services_by_type(&self, service_type: &ServiceType) -> Vec<ServiceInfo>;
}

/// Service discovery trait
pub trait ServiceDiscovery: Send + Sync {
    /// Start service discovery
    fn start_discovery(&self) -> Result<()>;
    
    /// Stop service discovery
    fn stop_discovery(&self) -> Result<()>;
    
    /// Query for services
    fn query_services(&self, query: ServiceQuery) -> Result<()>;
    
    /// Advertise services
    fn advertise_services(&self) -> Result<()>;
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            enable_discovery: true,
            advertisement_interval: 5000,
            query_timeout: 3000,
            max_services_per_peer: 50,
            service_cache_size: 1000,
            default_service_ttl: 300,
            enable_auth: false,
            enable_encryption: false,
        }
    }
}

impl ServiceInfo {
    /// Create new service info
    pub fn new(
        service_type: ServiceType,
        name: String,
        description: String,
        version: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            service_type,
            name,
            description,
            version,
            state: ServiceState::Inactive,
            priority: ServicePriority::Normal,
            endpoint: None,
            metadata: HashMap::new(),
            capabilities: Vec::new(),
            requirements: Vec::new(),
            owner_peer: None,
            created_at: now,
            updated_at: now,
            ttl: Duration::from_secs(300),
        }
    }

    /// Check if service is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, ServiceState::Active)
    }

    /// Check if service is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().signed_duration_since(self.updated_at).to_std().unwrap_or_default() > self.ttl
    }

    /// Update service timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Set service state
    pub fn set_state(&mut self, state: ServiceState) {
        self.state = state;
        self.touch();
    }

    /// Add capability
    pub fn add_capability(&mut self, capability: String) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
            self.touch();
        }
    }

    /// Remove capability
    pub fn remove_capability(&mut self, capability: &str) {
        self.capabilities.retain(|c| c != capability);
        self.touch();
    }

    /// Check if service has capability
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability.to_string())
    }

    /// Set metadata
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
        self.touch();
    }

    /// Get metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

impl ServiceManager {
    /// Create new service manager
    pub fn new(config: ServiceConfig) -> Self {
        Self {
            config,
            local_services: Arc::new(RwLock::new(HashMap::new())),
            remote_services: Arc::new(RwLock::new(HashMap::new())),
            pending_queries: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ServiceStats::default())),
            event_sender: None,
            sequence_counter: Arc::new(RwLock::new(0)),
        }
    }

    /// Initialize service manager
    pub async fn init(&mut self) -> Result<()> {
        // Clear all services and reset state
        self.local_services.write().unwrap().clear();
        self.remote_services.write().unwrap().clear();
        self.pending_queries.write().unwrap().clear();
        
        // Reset stats
        let mut stats = self.stats.write().unwrap();
        *stats = ServiceStats::default();
        
        // Reset sequence counter
        *self.sequence_counter.write().unwrap() = 0;
        
        Ok(())
    }

    /// Initialize service manager with event sender
    pub fn initialize(&mut self, event_sender: mpsc::UnboundedSender<AwdlEvent>) -> Result<()> {
        self.event_sender = Some(event_sender);
        Ok(())
    }

    /// Start service manager
    pub async fn start(&self) -> Result<()> {
        if self.config.enable_discovery {
            self.start_discovery().await?;
        }
        Ok(())
    }

    /// Stop service manager
    pub async fn stop(&self) -> Result<()> {
        self.stop_discovery().await?;
        Ok(())
    }

    /// Start service discovery
    async fn start_discovery(&self) -> Result<()> {
        // Start advertisement timer
        let services = self.local_services.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let sequence_counter = self.sequence_counter.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                Duration::from_millis(config.advertisement_interval)
            );
            
            loop {
                interval.tick().await;
                
                let services = services.read().unwrap();
                if !services.is_empty() {
                    // Send advertisements for all active services
                    for service in services.values() {
                        if service.is_active() {
                            let mut seq = sequence_counter.write().unwrap();
                            *seq += 1;
                            
                            let _advertisement = ServiceAdvertisement {
                                service: service.clone(),
                                sequence: *seq,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                signature: None,
                            };
                            
                            // TODO: Send advertisement to peers
                            
                            let mut stats = stats.write().unwrap();
                            stats.advertisements_sent += 1;
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    /// Stop service discovery
    async fn stop_discovery(&self) -> Result<()> {
        // TODO: Stop advertisement timer and cleanup
        Ok(())
    }

    /// Get service statistics
    pub fn get_stats(&self) -> ServiceStats {
        self.stats.read().unwrap().clone()
    }

    /// Reset service statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap();
        *stats = ServiceStats::default();
    }

    /// Handle service advertisement
    pub fn handle_advertisement(&self, advertisement: ServiceAdvertisement, peer: &str) -> Result<()> {
        let mut remote_services = self.remote_services.write().unwrap();
        let peer_services = remote_services.entry(peer.to_string()).or_insert_with(HashMap::new);
        
        let service_id = advertisement.service.id;
        let is_new = !peer_services.contains_key(&service_id);
        
        peer_services.insert(service_id, advertisement.service.clone());
        
        // Update statistics
        let mut stats = self.stats.write().unwrap();
        stats.advertisements_received += 1;
        
        // Send event
        if let Some(sender) = &self.event_sender {
            let event = if is_new {
                AwdlEvent::Service(ServiceEvent::ServiceDiscovered {
                    service: advertisement.service,
                    peer: peer.to_string(),
                })
            } else {
                AwdlEvent::Service(ServiceEvent::ServiceStateChanged {
                    service_id,
                    old_state: ServiceState::Active, // TODO: Track actual old state
                    new_state: advertisement.service.state,
                })
            };
            
            let _ = sender.send(event);
        }
        
        Ok(())
    }

    /// Handle service query
    pub fn handle_query(&self, query: ServiceQuery, peer: &str) -> Result<()> {
        let local_services = self.local_services.read().unwrap();
        let mut matching_services = Vec::new();
        
        for service in local_services.values() {
            if self.matches_query(service, &query) {
                matching_services.push(service.clone());
                
                if let Some(max) = query.max_results {
                    if matching_services.len() >= max {
                        break;
                    }
                }
            }
        }
        
        // Create response
        let _response = ServiceResponse {
            query_id: query.id,
            services: matching_services,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            responder: "local".to_string(), // TODO: Use actual node ID
        };
        
        // Update statistics
        let mut stats = self.stats.write().unwrap();
        stats.queries_received += 1;
        stats.responses_sent += 1;
        
        // Send event
        if let Some(sender) = &self.event_sender {
            let event = AwdlEvent::Service(ServiceEvent::QueryReceived {
                query,
                peer: peer.to_string(),
            });
            let _ = sender.send(event);
        }
        
        // TODO: Send response to peer
        
        Ok(())
    }

    /// Check if service matches query
    fn matches_query(&self, service: &ServiceInfo, query: &ServiceQuery) -> bool {
        // Check service type
        if let Some(ref query_type) = query.service_type {
            if &service.service_type != query_type {
                return false;
            }
        }
        
        // Check name filter
        if let Some(ref name_filter) = query.name_filter {
            if !service.name.contains(name_filter) {
                return false;
            }
        }
        
        // Check required capabilities
        for required_cap in &query.required_capabilities {
            if !service.has_capability(required_cap) {
                return false;
            }
        }
        
        // Check if service is active
        if !service.is_active() {
            return false;
        }
        
        true
    }

    /// Clean expired services
    pub fn cleanup_expired_services(&self) {
        let mut remote_services = self.remote_services.write().unwrap();
        
        for (peer, services) in remote_services.iter_mut() {
            let expired_services: Vec<Uuid> = services
                .iter()
                .filter(|(_, service)| service.is_expired())
                .map(|(id, _)| *id)
                .collect();
            
            for service_id in expired_services {
                services.remove(&service_id);
                
                // Send event
                if let Some(sender) = &self.event_sender {
                    let event = AwdlEvent::Service(ServiceEvent::ServiceLost {
                        service_id,
                        peer: peer.clone(),
                    });
                    let _ = sender.send(event);
                }
            }
        }
        
        // Remove peers with no services
        remote_services.retain(|_, services| !services.is_empty());
    }
}

impl ServiceRegistry for ServiceManager {
    fn register_service(&self, mut service: ServiceInfo) -> Result<()> {
        service.set_state(ServiceState::Active);
        
        let service_id = service.id;
        let service_type = service.service_type.clone();
        
        let mut local_services = self.local_services.write().unwrap();
        local_services.insert(service_id, service);
        
        // Update statistics
        let mut stats = self.stats.write().unwrap();
        stats.total_services += 1;
        stats.active_services += 1;
        
        // Send event
        if let Some(sender) = &self.event_sender {
            let event = AwdlEvent::Service(ServiceEvent::ServiceRegistered {
                service_id,
                service_type,
            });
            let _ = sender.send(event);
        }
        
        Ok(())
    }

    fn unregister_service(&self, service_id: Uuid) -> Result<()> {
        let mut local_services = self.local_services.write().unwrap();
        
        if local_services.remove(&service_id).is_some() {
            // Update statistics
            let mut stats = self.stats.write().unwrap();
            stats.active_services = stats.active_services.saturating_sub(1);
            
            // Send event
            if let Some(sender) = &self.event_sender {
                let event = AwdlEvent::Service(ServiceEvent::ServiceUnregistered {
                    service_id,
                });
                let _ = sender.send(event);
            }
            
            Ok(())
        } else {
            Err(AwdlError::Protocol(format!("Service {} not found", service_id)))
        }
    }

    fn get_service(&self, service_id: Uuid) -> Option<ServiceInfo> {
        let local_services = self.local_services.read().unwrap();
        local_services.get(&service_id).cloned()
    }

    fn list_services(&self) -> Vec<ServiceInfo> {
        let local_services = self.local_services.read().unwrap();
        local_services.values().cloned().collect()
    }

    fn find_services_by_type(&self, service_type: &ServiceType) -> Vec<ServiceInfo> {
        let local_services = self.local_services.read().unwrap();
        local_services
            .values()
            .filter(|service| &service.service_type == service_type)
            .cloned()
            .collect()
    }
}

impl ServiceDiscovery for ServiceManager {
    fn start_discovery(&self) -> Result<()> {
        // Discovery is started in the start() method
        Ok(())
    }

    fn stop_discovery(&self) -> Result<()> {
        // Discovery is stopped in the stop() method
        Ok(())
    }

    fn query_services(&self, query: ServiceQuery) -> Result<()> {
        let query_id = query.id;
        
        // Store pending query
        let mut pending_queries = self.pending_queries.write().unwrap();
        pending_queries.insert(query_id, query.clone());
        
        // Update statistics
        let mut stats = self.stats.write().unwrap();
        stats.queries_sent += 1;
        
        // TODO: Send query to peers
        
        Ok(())
    }

    fn advertise_services(&self) -> Result<()> {
        let local_services = self.local_services.read().unwrap();
        let mut stats = self.stats.write().unwrap();
        
        for service in local_services.values() {
            if service.is_active() {
                // TODO: Send advertisement
                stats.advertisements_sent += 1;
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_info_creation() {
        let service = ServiceInfo::new(
            ServiceType::FileSharing,
            "Test Service".to_string(),
            "A test service".to_string(),
            "1.0.0".to_string(),
        );
        
        assert_eq!(service.service_type, ServiceType::FileSharing);
        assert_eq!(service.name, "Test Service");
        assert_eq!(service.state, ServiceState::Inactive);
        assert!(!service.is_active());
    }

    #[test]
    fn test_service_capabilities() {
        let mut service = ServiceInfo::new(
            ServiceType::FileSharing,
            "Test Service".to_string(),
            "A test service".to_string(),
            "1.0.0".to_string(),
        );
        
        service.add_capability("read".to_string());
        service.add_capability("write".to_string());
        
        assert!(service.has_capability("read"));
        assert!(service.has_capability("write"));
        assert!(!service.has_capability("execute"));
        
        service.remove_capability("write");
        assert!(!service.has_capability("write"));
    }

    #[test]
    fn test_service_manager_creation() {
        let config = ServiceConfig::default();
        let manager = ServiceManager::new(config);
        
        let stats = manager.get_stats();
        assert_eq!(stats.total_services, 0);
        assert_eq!(stats.active_services, 0);
    }

    #[test]
    fn test_service_registration() {
        let config = ServiceConfig::default();
        let manager = ServiceManager::new(config);
        
        let service = ServiceInfo::new(
            ServiceType::FileSharing,
            "Test Service".to_string(),
            "A test service".to_string(),
            "1.0.0".to_string(),
        );
        
        let service_id = service.id;
        manager.register_service(service).unwrap();
        
        let retrieved = manager.get_service(service_id).unwrap();
        assert!(retrieved.is_active());
        
        let stats = manager.get_stats();
        assert_eq!(stats.total_services, 1);
        assert_eq!(stats.active_services, 1);
    }

    #[test]
    fn test_service_query_matching() {
        let config = ServiceConfig::default();
        let manager = ServiceManager::new(config);
        
        let mut service = ServiceInfo::new(
            ServiceType::FileSharing,
            "File Service".to_string(),
            "A file sharing service".to_string(),
            "1.0.0".to_string(),
        );
        service.set_state(ServiceState::Active);
        service.add_capability("read".to_string());
        service.add_capability("write".to_string());
        
        let query = ServiceQuery {
            id: Uuid::new_v4(),
            service_type: Some(ServiceType::FileSharing),
            name_filter: Some("File".to_string()),
            required_capabilities: vec!["read".to_string()],
            max_results: None,
            timeout: Duration::from_secs(5),
        };
        
        assert!(manager.matches_query(&service, &query));
        
        let query_no_match = ServiceQuery {
            id: Uuid::new_v4(),
            service_type: Some(ServiceType::AudioStreaming),
            name_filter: None,
            required_capabilities: Vec::new(),
            max_results: None,
            timeout: Duration::from_secs(5),
        };
        
        assert!(!manager.matches_query(&service, &query_no_match));
    }
}