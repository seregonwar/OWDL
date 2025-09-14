# Architettura Tecnica Driver NDIS IEEE 802.11 Monitor Mode

## Architettura del Sistema

### Stack NDIS e Posizionamento Driver

```
Application Layer (AWDL Daemon)
         ↓ DeviceIoControl()
    [User-Mode Service]
         ↓ IOCTL Interface
═══════════════════════════════ Kernel Boundary
    [Monitor Filter Driver] ← Target Implementation
         ↓ NDIS 6.x Interface
    [Intel AX200 Miniport]
         ↓ Bus Interface
    [PCIe Hardware Layer]
```

### Componenti Architetturali

#### 1. NDIS Lightweight Filter (LWF)
- **Tipo**: `NdisFilterDriver` con `NDIS_FILTER_PARTIAL_CHARACTERISTICS`
- **Binding**: Selective binding solo su adapter 802.11 compatibili
- **Position**: `FilterModulePosition = NdisFilterModulePositionMonitoring`

#### 2. Virtual Miniport Interface
- **Scopo**: Espone interfaccia separata con datalink `DLT_IEEE802_11_RADIOTAP`
- **Implementazione**: NDIS Virtual Miniport Driver associato al filter
- **Name**: `\\Device\\NPF_{GUID}_Monitor`

## Implementazioni Tecniche Dettagliate

### 1. Monitor Mode Forcing Strategies

#### A. OID Interception e Override
```c
// Intercetta e modifica OID requests per forzare monitor mode
NDIS_STATUS FilterOidRequest(
    NDIS_HANDLE FilterModuleContext,
    PNDIS_OID_REQUEST OidRequest
) {
    if (OidRequest->RequestType == NdisRequestSetInformation) {
        switch (OidRequest->DATA.SET_INFORMATION.Oid) {
            
        case OID_DOT11_CURRENT_OPERATION_MODE:
            // Forza monitor mode
            PDOT11_CURRENT_OPERATION_MODE opMode = 
                (PDOT11_CURRENT_OPERATION_MODE)OidRequest->DATA.SET_INFORMATION.InformationBuffer;
            opMode->uCurrentOpMode = DOT11_OPERATION_MODE_NETWORK_MONITOR;
            break;
            
        case OID_DOT11_SCAN_REQUEST:
            // Intercetta scan requests per channel control
            return HandleScanRequest(FilterModuleContext, OidRequest);
            
        case OID_DOT11_RESET_REQUEST:
            // Mantiene monitor mode dopo reset
            return HandleResetRequest(FilterModuleContext, OidRequest);
        }
    }
    
    return NdisFOidRequest(FilterModuleContext, OidRequest);
}
```

#### B. Hardware Register Manipulation
```c
// Accesso diretto ai registri Intel AX200 via memory-mapped I/O
typedef struct _AX200_REGISTERS {
    ULONG CSR_BASE;           // 0x00000000 - Control Status Registers
    ULONG FW_BASE;            // 0x00400000 - Firmware interface
    ULONG MAC_BASE;           // 0x00A00000 - MAC layer registers
} AX200_REGISTERS, *PAX200_REGISTERS;

NTSTATUS ForceMonitorModeHardware(PFILTER_CONTEXT Context) {
    // 1. Map PCI BAR0 per accesso registri
    PHYSICAL_ADDRESS PhysAddr = {0};
    PhysAddr.LowPart = Context->PCIBaseAddress;
    
    PVOID MappedRegs = MmMapIoSpace(PhysAddr, 0x1000, MmNonCached);
    if (!MappedRegs) return STATUS_INSUFFICIENT_RESOURCES;
    
    // 2. Configura MAC per promiscuous mode
    ULONG MacConfig = READ_REGISTER_ULONG((PULONG)((PUCHAR)MappedRegs + MAC_CONFIG_OFFSET));
    MacConfig |= MAC_PROMISCUOUS_MODE | MAC_MONITOR_MODE;
    WRITE_REGISTER_ULONG((PULONG)((PUCHAR)MappedRegs + MAC_CONFIG_OFFSET), MacConfig);
    
    // 3. Disabilita frame filtering hardware
    WRITE_REGISTER_ULONG((PUCHAR)MappedRegs + FRAME_FILTER_OFFSET, 0x00000000);
    
    // 4. Configura DMA per raw frame delivery
    ULONG DmaConfig = READ_REGISTER_ULONG((PULONG)((PUCHAR)MappedRegs + DMA_CONFIG_OFFSET));
    DmaConfig |= DMA_RAW_FRAME_MODE;
    WRITE_REGISTER_ULONG((PULONG)((PUCHAR)MappedRegs + DMA_CONFIG_OFFSET), DmaConfig);
    
    MmUnmapIoSpace(MappedRegs, 0x1000);
    return STATUS_SUCCESS;
}
```

### 2. Frame Interception e Processing

#### A. NBL (Net Buffer List) Manipulation
```c
VOID FilterReceiveNetBufferLists(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags
) {
    PFILTER_CONTEXT Context = (PFILTER_CONTEXT)FilterModuleContext;
    PNET_BUFFER_LIST CurrentNBL = NetBufferLists;
    
    while (CurrentNBL) {
        PNET_BUFFER CurrentNB = NET_BUFFER_LIST_FIRST_NB(CurrentNBL);
        
        while (CurrentNB) {
            // Estrai raw data prima del processing
            PVOID DataBuffer = NdisGetDataBuffer(CurrentNB, 
                                               NET_BUFFER_DATA_LENGTH(CurrentNB),
                                               NULL, 1, 0);
            
            if (DataBuffer) {
                // Verifica se è frame 802.11 vs Ethernet
                if (IsRaw80211Frame(DataBuffer, NET_BUFFER_DATA_LENGTH(CurrentNB))) {
                    // Processa frame 802.11 raw
                    Process80211Frame(Context, DataBuffer, NET_BUFFER_DATA_LENGTH(CurrentNB));
                } else {
                    // Ricostruisci 802.11 da Ethernet (se possibile)
                    Reconstruct80211FromEthernet(Context, DataBuffer, NET_BUFFER_DATA_LENGTH(CurrentNB));
                }
            }
            
            CurrentNB = NET_BUFFER_NEXT_NB(CurrentNB);
        }
        
        CurrentNBL = NET_BUFFER_LIST_NEXT_NBL(CurrentNBL);
    }
    
    // Passa al layer superiore
    NdisFIndicateReceiveNetBufferLists(Context->FilterHandle,
                                       NetBufferLists,
                                       PortNumber,
                                       NumberOfNetBufferLists,
                                       ReceiveFlags);
}
```

#### B. Radiotap Header Generation
```c
typedef struct _RADIOTAP_HEADER_EXTENDED {
    // Standard radiotap header
    UCHAR it_version;        // 0
    UCHAR it_pad;           // 0
    USHORT it_len;          // Lunghezza header completo
    ULONG it_present;       // Campi presenti
    
    // Extended fields per AWDL compatibility
    ULONGLONG timestamp;     // 64-bit timestamp
    UCHAR flags;            // Frame flags
    UCHAR rate;             // Data rate
    USHORT channel_freq;    // Channel frequency
    USHORT channel_flags;   // Channel flags
    CHAR signal_dbm;        // Signal strength
    CHAR noise_dbm;         // Noise level
    UCHAR antenna;          // Antenna index
    
} RADIOTAP_HEADER_EXTENDED, *PRADIOTAP_HEADER_EXTENDED;

VOID EncapsulateWithRadiotap(
    PFILTER_CONTEXT Context,
    PVOID Frame80211,
    ULONG FrameLength,
    PCAPTURED_FRAME* OutputFrame
) {
    // Alloca buffer per frame + radiotap header
    ULONG TotalLength = sizeof(RADIOTAP_HEADER_EXTENDED) + FrameLength;
    PCAPTURED_FRAME CapturedFrame = ExAllocatePoolWithTag(NonPagedPool, 
                                                          sizeof(CAPTURED_FRAME) + TotalLength,
                                                          DRIVER_TAG);
    
    // Costruisci radiotap header
    PRADIOTAP_HEADER_EXTENDED RadiotapHdr = (PRADIOTAP_HEADER_EXTENDED)CapturedFrame->FrameData;
    RtlZeroMemory(RadiotapHdr, sizeof(RADIOTAP_HEADER_EXTENDED));
    
    RadiotapHdr->it_version = 0;
    RadiotapHdr->it_len = sizeof(RADIOTAP_HEADER_EXTENDED);
    RadiotapHdr->it_present = RADIOTAP_PRESENT_TIMESTAMP | 
                              RADIOTAP_PRESENT_FLAGS |
                              RADIOTAP_PRESENT_RATE |
                              RADIOTAP_PRESENT_CHANNEL |
                              RADIOTAP_PRESENT_SIGNAL |
                              RADIOTAP_PRESENT_ANTENNA;
    
    // Popolazione campi con dati hardware
    KeQuerySystemTime((PLARGE_INTEGER)&RadiotapHdr->timestamp);
    RadiotapHdr->rate = GetCurrentDataRate(Context);
    RadiotapHdr->channel_freq = GetCurrentChannelFreq(Context);
    RadiotapHdr->signal_dbm = GetSignalStrength(Context);
    
    // Copia frame 802.11 dopo header
    RtlCopyMemory((PUCHAR)RadiotapHdr + sizeof(RADIOTAP_HEADER_EXTENDED),
                  Frame80211,
                  FrameLength);
    
    CapturedFrame->FrameLength = TotalLength;
    *OutputFrame = CapturedFrame;
}
```

### 3. Virtual Interface Implementation

#### A. NDIS Virtual Miniport
```c
// Caratteristiche del virtual miniport per Npcap integration
NDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportCharacteristics = {
    .Header = {
        .Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS,
        .Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3,
        .Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3
    },
    
    .MajorNdisVersion = 6,
    .MinorNdisVersion = 80,
    
    // Handler functions
    .InitializeHandlerEx = VirtualMiniportInitialize,
    .HaltHandlerEx = VirtualMiniportHalt,
    .ShutdownHandlerEx = VirtualMiniportShutdown,
    .ResetHandlerEx = VirtualMiniportReset,
    .SendNetBufferListsHandler = VirtualMiniportSendNBLs,
    .CancelSendHandler = VirtualMiniportCancelSend,
    .OidRequestHandler = VirtualMiniportOidRequest,
    .CancelOidRequestHandler = VirtualMiniportCancelOidRequest,
    .ReturnNetBufferListsHandler = VirtualMiniportReturnNBLs,
};

NDIS_STATUS VirtualMiniportInitialize(
    NDIS_HANDLE MiniportAdapterHandle,
    NDIS_HANDLE MiniportDriverContext,
    PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters
) {
    // Configura caratteristiche per interface IEEE 802.11
    NDIS_MINIPORT_ADAPTER_ATTRIBUTES AdapterAttributes;
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES GeneralAttributes;
    
    RtlZeroMemory(&GeneralAttributes, sizeof(GeneralAttributes));
    GeneralAttributes.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
    GeneralAttributes.Header.Size = NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
    
    // Configura per wireless adapter
    GeneralAttributes.MediaType = NdisMediumNative802_11;
    GeneralAttributes.PhysicalMediumType = NdisPhysicalMediumNative802_11;
    GeneralAttributes.MaxXmitLinkSpeed = 1200000000;  // 1.2 Gbps (AX200 max)
    GeneralAttributes.MaxRcvLinkSpeed = 1200000000;
    GeneralAttributes.XmitLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
    GeneralAttributes.RcvLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
    
    // Importante: Configura datalink per raw 802.11
    GeneralAttributes.MediaConnectState = MediaConnectStateConnected;
    GeneralAttributes.MediaDuplexState = MediaDuplexStateFull;
    
    return NdisMSetMiniportAttributes(MiniportAdapterHandle,
                                      (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&GeneralAttributes);
}
```

#### B. Frame Queue Management
```c
// Lock-free circular buffer per high-performance frame delivery
typedef struct _FRAME_RING_BUFFER {
    volatile LONG WriteIndex;
    volatile LONG ReadIndex;
    ULONG BufferSize;
    ULONG FrameSlots;
    PCAPTURED_FRAME Frames[MAX_FRAME_SLOTS];
} FRAME_RING_BUFFER, *PFRAME_RING_BUFFER;

BOOLEAN EnqueueFrame(PFRAME_RING_BUFFER RingBuffer, PCAPTURED_FRAME Frame) {
    LONG CurrentWrite = RingBuffer->WriteIndex;
    LONG NextWrite = (CurrentWrite + 1) % RingBuffer->FrameSlots;
    
    // Check if buffer is full
    if (NextWrite == RingBuffer->ReadIndex) {
        return FALSE;  // Buffer full, drop frame
    }
    
    // Store frame
    RingBuffer->Frames[CurrentWrite] = Frame;
    
    // Atomic update write index
    InterlockedExchange(&RingBuffer->WriteIndex, NextWrite);
    
    // Signal waiting readers
    KeSetEvent(&RingBuffer->FrameAvailableEvent, 0, FALSE);
    
    return TRUE;
}

PCAPTURED_FRAME DequeueFrame(PFRAME_RING_BUFFER RingBuffer) {
    LONG CurrentRead = RingBuffer->ReadIndex;
    
    // Check if buffer is empty
    if (CurrentRead == RingBuffer->WriteIndex) {
        return NULL;
    }
    
    // Get frame
    PCAPTURED_FRAME Frame = RingBuffer->Frames[CurrentRead];
    
    // Atomic update read index
    LONG NextRead = (CurrentRead + 1) % RingBuffer->FrameSlots;
    InterlockedExchange(&RingBuffer->ReadIndex, NextRead);
    
    return Frame;
}
```

### 4. Channel Control e Management

#### A. Multi-Channel Support
```c
typedef struct _CHANNEL_CONFIG {
    ULONG ChannelNumber;      // 1-14 (2.4GHz), 36-165 (5GHz)
    ULONG CenterFrequency;    // MHz
    ULONG ChannelWidth;       // 20, 40, 80, 160 MHz
    BOOLEAN Active;           // Currently monitoring
    ULONGLONG DwellTime;      // Tempo permanenza (us)
} CHANNEL_CONFIG, *PCHANNEL_CONFIG;

NTSTATUS SetMonitorChannel(PFILTER_CONTEXT Context, PCHANNEL_CONFIG ChannelConfig) {
    // 1. Costruisci DOT11_SCAN_REQUEST per channel switch
    DOT11_SCAN_REQUEST_V2 ScanRequest = {0};
    ScanRequest.dot11BSSType = dot11_BSS_type_any;
    ScanRequest.dot11ScanType = dot11_scan_type_passive;  // Passive per monitor mode
    
    // 2. Configura channel list
    DOT11_PHY_ID_LIST PhyIdList = {0};
    PhyIdList.uNumOfEntries = 1;
    PhyIdList.dot11PhyId[0] = 0;  // Primary PHY
    
    DOT11_SCAN_REQUEST_V2_ELEMENT ScanElement = {0};
    ScanElement.dot11SSID.uSSIDLength = 0;  // Wildcard
    ScanElement.uNumOfProbeRequests = 0;    // No active probing
    ScanElement.uProbeDelay = 0;
    ScanElement.uMinChannelTime = ChannelConfig->DwellTime / 1000;  // Convert to ms
    ScanElement.uMaxChannelTime = ChannelConfig->DwellTime / 1000;
    
    // 3. Channel specification
    DOT11_CHANNEL_HINT ChannelHint = {0};
    ChannelHint.dot11PhyId = 0;
    ChannelHint.uChannelNumber = ChannelConfig->ChannelNumber;
    
    // 4. Invia OID request al miniport
    NDIS_OID_REQUEST OidRequest = {0};
    OidRequest.RequestType = NdisRequestSetInformation;
    OidRequest.DATA.SET_INFORMATION.Oid = OID_DOT11_SCAN_REQUEST;
    OidRequest.DATA.SET_INFORMATION.InformationBuffer = &ScanRequest;
    OidRequest.DATA.SET_INFORMATION.InformationBufferLength = sizeof(ScanRequest);
    
    return NdisFOidRequest(Context->FilterHandle, &OidRequest);
}
```

### 5. Performance Optimizations

#### A. CPU Affinity e Thread Prioritization
```c
// Dedica CPU core specifici per packet processing
NTSTATUS OptimizeProcessingAffinity(PFILTER_CONTEXT Context) {
    // 1. Query system topology
    ULONG ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    
    // 2. Reserve last CPU core per packet processing
    KAFFINITY PacketProcessorAffinity = (KAFFINITY)(1ULL << (ProcessorCount - 1));
    
    // 3. Set DPC affinity per interrupt handling
    KeSetTargetProcessorDpcEx(&Context->PacketProcessingDpc, &PacketProcessorAffinity);
    
    // 4. Boost thread priority per time-critical operations
    KeSetPriorityThread(KeGetCurrentThread(), HIGH_PRIORITY);
    
    return STATUS_SUCCESS;
}
```

#### B. Memory Pool Optimization
```c
// Pre-allocated frame buffer pool
typedef struct _FRAME_POOL {
    LOOKASIDE_LIST_EX FrameLookaside;
    NPAGED_LOOKASIDE_LIST BufferLookaside;
    ULONG PreAllocatedFrames;
    ULONG MaxFrameSize;
} FRAME_POOL, *PFRAME_POOL;

NTSTATUS InitializeFramePool(PFRAME_POOL Pool, ULONG MaxFrames, ULONG MaxFrameSize) {
    // Initialize lookaside lists for high-performance allocation
    NTSTATUS Status = ExInitializeLookasideListEx(
        &Pool->FrameLookaside,
        NULL, NULL,
        NonPagedPool,
        0,
        sizeof(CAPTURED_FRAME) + MaxFrameSize,
        DRIVER_TAG,
        0);
        
    if (!NT_SUCCESS(Status)) return Status;
    
    Pool->MaxFrameSize = MaxFrameSize;
    Pool->PreAllocatedFrames = MaxFrames;
    
    return STATUS_SUCCESS;
}
```

## Integration Points

### 1. Npcap/WinPcap Compatibility
- **NDIS Interface**: Standard NDIS miniport interface
- **Device Naming**: Segue convenzioni NPF (Netgroup Packet Filter)
- **Datalink Type**: Espone `DLT_IEEE802_11_RADIOTAP` (127)
- **Buffer Management**: Compatible con pcap buffer format

### 2. User-Mode Control Interface
```c
// IOCTL definitions per user-mode control
#define IOCTL_MONITOR_START     CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_STOP      CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_CHANNEL       CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATISTICS    CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
```

Questa architettura fornisce una base tecnica solida per implementare monitor mode su hardware Intel che normalmente non lo supporta, attraverso intercettazione a livello NDIS e manipolazione hardware diretta..

---

# Addendum: Vincoli Realistici su Windows e Roadmap Attuabile

## Vincoli di Piattaforma (Windows 10/11)

- Native 802.11 vs WDI:
  - I driver Wi‑Fi moderni adottano WDI (Windows Driver Interface). Molti OID `DOT11_*` sono deprecati o non operativi sui miniport WDI.
  - Non è garantito poter forzare `DOT11_OPERATION_MODE_NETWORK_MONITOR` da un LWF (Lightweight Filter).

- Limiti LWF:
  - Un NDIS LWF non ha privilegi per abilitare monitor/injection se il miniport non li espone.
  - Un LWF non può accedere direttamente a registri hardware/PCI (BAR mapping, DMA setup). Queste operazioni competono a miniport/driver IHV con supporto del vendor.

- Ricostruzione 802.11 da Ethernet:
  - Se il miniport consegna solo Ethernet (EN10MB), non è possibile ricostruire header 802.11 o Radiotap mancanti in modo fedele.

## Correzioni al Design Originario

- Rimuovere/annotare la sezione "Hardware Register Manipulation":
  - L'accesso a registri MAC/PHY non è realistico in un LWF e richiede supporto vendor/miniport proprietario. Mantenerla solo come sezione esplorativa, marcata come "Non attuabile senza collaborazione vendor".

- OID Interception/Override:
  - Classificare come "best effort": su miniport WDI potrebbe non avere effetto. Documentare fallback.

- Radiotap:
  - Generare l'header Radiotap in user‑mode. Il driver fornisce raw 802.11 + metadati (RSSI, canale, rate) via IOCTL o shared buffer; l'header viene costruito nello user‑mode.

- Virtual Miniport 802.11:
  - Esporre un miniport 802.11 virtuale è sensato solo se esiste un backend reale che fornisca 802.11 grezzo (es. bridge esterno o driver IHV). In assenza, evitare collisioni con WLAN AutoConfig.

## Architettura Rivista (Fasi)

1. Fase 1 — LWF Passivo + Capability Detection
   - Implementare un LWF che si lega selettivamente a interfacce candidabili.
   - Se il miniport espone 802.11 grezzo (caso raro) o se è presente un driver IHV (es. CommView) compatibile, inoltrare raw frames + metadati a user‑mode.
   - Costruire Radiotap e fare parsing AWDL in user‑mode.

2. Fase 2 — Radio Bridge Esterno (Consigliato per Sblocco Rapido)
   - Usare un appliance Linux/USB dongle con monitor/injection reale che cattura/inietta 802.11 e inoltra i frame a Windows via TCP/gRPC.
   - Il driver/servizio Windows funge da endpoint locale, presentando i frame all'applicazione.

3. Fase 3 — Driver IHV/Miniport Personalizzato (Solo con Vendor)
   - Con documentazione NDA o hardware che espone API MAC/PHY, implementare un miniport che abiliti monitor/injection e controllo canale.
   - Prevedere tempi lunghi, firma EV e attestazione/WHQL.

## PnP/Power/Binding/Distribuzione

- PnP/Power:
  - Implementare correttamente `FilterAttach/Detach`, `Pause/Restart`, stati di alimentazione D0/Dx.

- Binding Selettivo:
  - INF con include/exclude su adapter target; evitare interferenze con WLAN AutoConfig.

- Firma e Sicurezza:
  - EV Code Signing, attestation signing per compatibilità con Secure Boot/HVCI. Documentare flusso di build/sign.

## Interfaccia User‑Mode

- IOCTL:
  - Definire IOCTL per start/stop, get stats, passaggio frame e metadati.
  - Buffer circolari lock‑free o shared memory per alta performance.

- Radiotap in UM:
  - Comporre Radiotap con metadati forniti dal kernel; serializzare per strumenti compatibili (pcap/wireshark).

## Roadmap e Deliverable

- M0 — Documento Rivisto (questa sezione):
  - Aggiornamento design con vincoli WDI/NDIS, rimozione accesso registri, Radiotap in UM.

- M1 — Scheletro LWF (Pass‑through):
  - Binding, PnP/Power, logging; IOCTL base; test signing.

- M2 — UM Library + Radiotap Builder:
  - Ricezione frame/metadati, composizione Radiotap, parsing AWDL.

- M3 — Radio Bridge (Opzionale ma Consigliato):
  - gRPC/TCP endpoint; integrazione con daemon esistente; test end‑to‑end AWDL.

- M4 — Valutazione Miniport/IVH (Se Disponibile):
  - Studio fattibilità con vendor; pianificazione attestation/WHQL.

## Prossimi Passi Concreti

- Implementare M0→M1: preparare scheletro LWF con selective binding e IOCTL base.
- Integrare lato applicativo la composizione Radiotap in user‑mode e il parser AWDL esistente.
- In parallelo, predisporre un “Radio Bridge” Linux per sbloccare lo sviluppo AWDL reale subito.