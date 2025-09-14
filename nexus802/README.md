# Nexus802 - Multi-Tier IEEE 802.11 Protocol Implementation

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Nexus802 è un'implementazione Rust di un protocollo multi-tier per l'accesso ai frame IEEE 802.11 su sistemi Windows, fornendo meccanismi di fallback attraverso diversi metodi di accesso.

## Architettura

Il protocollo Nexus802 implementa un approccio stratificato per superare le limitazioni dell'accesso monitor mode su Windows moderni:

- **Tier 1**: NDIS WDI-Aware Filter Driver (kernel-mode)
- **Tier 2**: Hybrid Bridge Architecture (WSL2/Linux + Vendor Drivers)
- **Tier 3**: Advanced Frame Processing Pipeline
- **Tier 4**: Intelligent Fallback & Auto-Configuration
- **Tier 5**: Security & Compliance Framework
- **Tier 6**: Performance Optimization & Monitoring

## Caratteristiche

### Backend Supportati

- **WSL2 Bridge** (Raccomandato): Utilizza un bridge Linux in WSL2 per accesso monitor mode
- **Vendor Drivers**: Integrazione con CommView, Acrylic WiFi, OmniPeek
- **NDIS Filter**: Driver kernel-mode per accesso diretto (avanzato)
- **Mock Backend**: Per testing e sviluppo

### Funzionalità

- ✅ Monitor mode unificato attraverso multiple sorgenti
- ✅ Frame injection IEEE 802.11
- ✅ Channel switching dinamico
- ✅ Radiotap header avanzato con estensioni custom
- ✅ Aggregazione frame da sorgenti multiple
- ✅ Fallback automatico intelligente
- ✅ Performance monitoring e statistiche
- ✅ Configurazione TOML flessibile

## Installazione

### Prerequisiti

- Rust 1.70 o superiore
- Windows 10/11
- WSL2 con distribuzione Ubuntu (per backend bridge)

### Compilazione

```bash
git clone <repository>
cd nexus802

# Compilazione con backend WSL2 (default)
cargo build --release

# Compilazione con tutti i backend
cargo build --release --all-features

# Solo backend specifici
cargo build --release --features "bridge-wsl2,vendor-commview"
```

### Installazione Binari

```bash
# Installa daemon e CLI
cargo install --path . --bins

# O copia manualmente
cp target/release/nexus802-daemon.exe /usr/local/bin/
cp target/release/nexus802-cli.exe /usr/local/bin/
```

## Configurazione

### Generazione Configurazione Default

```bash
nexus802-cli config generate -o nexus802.toml
```

### Configurazione WSL2 Bridge

1. Installa una distribuzione WSL2:
```bash
wsl --install Ubuntu
```

2. Configura il bridge Linux (esempio per Ubuntu):
```bash
# In WSL2
sudo apt update
sudo apt install iw wireless-tools
# Installa il bridge executable (da implementare)
```

3. Modifica `nexus802.toml`:
```toml
[bridge]
wsl_distribution = "Ubuntu"
bridge_executable = "/usr/local/bin/nexus802-bridge"
shared_memory_size = 67108864  # 64MB
use_shared_memory = true
```

## Utilizzo

### Avvio Daemon

```bash
# Avvio con configurazione default
nexus802-daemon

# Con configurazione custom
nexus802-daemon -c /path/to/config.toml

# Con backend specifico
nexus802-daemon --backend bridge-wsl2 --channel 6
```

### Test Backend

```bash
# Test backend WSL2 per 30 secondi su canale 11
nexus802-cli test -b bridge-wsl2 -c 11 -d 30

# Scan reti su canali multipli
nexus802-cli scan -c "1,6,11"
```

### Esempio Programmazione

```rust
use nexus802::{
    config::Nexus802Config,
    phy::{PhyBackend, MonitorModeType, ChannelConfig},
    bridge::BridgeBackend,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Carica configurazione
    let config = Nexus802Config::from_file("nexus802.toml")?;
    
    // Crea backend WSL2
    let mut backend = BridgeBackend::new(config.bridge.unwrap());
    
    // Inizializza
    backend.initialize().await?;
    
    // Abilita monitor mode
    backend.enable_monitor_mode(MonitorModeType::Bridge).await?;
    
    // Imposta canale
    let channel = ChannelConfig {
        primary: 6,
        width: 20,
        center_freq: 2437,
        secondary_offset: None,
    };
    backend.set_channel(channel).await?;
    
    // Ricevi frame
    while let Ok(Some((frame_data, metadata))) = backend.recv_frame().await {
        println!("Frame ricevuto: {} bytes da {:?} su {}MHz", 
                 frame_data.len(), metadata.source_type, metadata.frequency);
        
        // Processa frame...
    }
    
    Ok(())
}
```

## Struttura Progetto

```
nexus802/
├── src/
│   ├── lib.rs              # Libreria principale
│   ├── error.rs            # Gestione errori
│   ├── config.rs           # Configurazione
│   ├── frame.rs            # Processing frame 802.11
│   ├── radiotap.rs         # Generazione/parsing radiotap
│   ├── bridge.rs           # Backend WSL2 bridge
│   ├── phy/                # Astrazione PHY layer
│   │   ├── mod.rs
│   │   ├── capabilities.rs
│   │   └── monitor_mode.rs
│   └── bin/
│       ├── daemon.rs       # Daemon principale
│       └── cli.rs          # Tool CLI
├── Cargo.toml
└── README.md
```

## Backend WSL2 Bridge

Il backend WSL2 Bridge è la soluzione raccomandata per Windows 10/11 moderni dove WDI limita l'accesso monitor mode.

### Architettura Bridge

```
Windows Host                    WSL2 Linux
┌─────────────────┐            ┌──────────────────┐
│ Nexus802 Daemon │◄──────────►│ Bridge Process   │
│                 │ Named Pipes│                  │
│ - Control       │            │ - Monitor Mode   │
│ - Frame RX/TX   │            │ - Frame Capture  │
│ - Statistics    │            │ - Channel Switch │
└─────────────────┘            └──────────────────┘
         ▲                              ▲
         │                              │
         ▼                              ▼
┌─────────────────┐            ┌──────────────────┐
│ Shared Memory   │◄──────────►│ WiFi Hardware    │
│ Ring Buffers    │            │ (Monitor Mode)   │
└─────────────────┘            └──────────────────┘
```

### Vantaggi

- ✅ Bypassa limitazioni WDI Windows
- ✅ Accesso completo monitor mode Linux
- ✅ Performance elevate via shared memory
- ✅ Compatibilità hardware estesa
- ✅ Nessun driver kernel richiesto

## Troubleshooting

### Backend WSL2 Non Disponibile

```bash
# Verifica WSL2
wsl --list --verbose

# Verifica distribuzione
wsl -d Ubuntu echo "WSL2 OK"

# Verifica bridge executable
wsl -d Ubuntu ls -la /usr/local/bin/nexus802-bridge
```

### Problemi Permission

```bash
# Esegui come Administrator per accesso hardware
# O configura WSL2 con privilegi appropriati
```

### Debug Logging

```bash
# Abilita debug logging
RUST_LOG=debug nexus802-daemon

# O nel config
[general]
log_level = "debug"
```

## Roadmap

- [ ] **Tier 1**: Implementazione NDIS Filter Driver
- [ ] **Tier 2**: Backend vendor driver (CommView, Acrylic)
- [ ] **Tier 3**: Frame aggregation pipeline avanzato
- [ ] **Tier 4**: Auto-configuration intelligente
- [ ] **Tier 5**: Security framework completo
- [ ] **Tier 6**: Ottimizzazioni performance NUMA
- [ ] Bridge Linux completo per WSL2
- [ ] Supporto USB WiFi adapter
- [ ] GUI management interface
- [ ] Plugin system per estensioni

## Contributi

Contributi benvenuti! Vedi [CONTRIBUTING.md](CONTRIBUTING.md) per linee guida.

## Licenza

MIT License - vedi [LICENSE](LICENSE) per dettagli.

## Crediti

Basato sui concetti del protocollo multi-tier documentato in `docs/Multi-Tier-Protocol.md`.
Sviluppato per supportare OWDL (Open Wireless Direct Link) su piattaforme Windows.
