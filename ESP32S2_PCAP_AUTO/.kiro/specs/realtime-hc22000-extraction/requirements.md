# Requirements Document: Real-time HC22000 Extraction on ESP32

## Introduction

This feature transforms the ESP32 PCAP capture system from a "dump everything" approach to a "filter essentials" approach by implementing real-time HC22000 extraction. Instead of storing complete 802.11 frames in PCAP format, the system will extract only the essential cryptographic material needed for WiFi password cracking with Hashcat mode 22000.

The HC22000 format is a text-based format that stores PMKID data and EAPOL handshake key material in hex-encoded strings, significantly reducing storage requirements while maintaining all necessary data for password recovery.

## Glossary

- **HC22000_Extractor**: The component that parses 802.11 frames and extracts HC22000 data
- **PCAP_Manager**: The existing packet capture management component
- **File_Writer**: The component that writes HC22000 formatted data to SPIFFS
- **Frame_Parser**: The component that parses 802.11 management and data frames
- **EAPOL_Parser**: The component that parses EAPOL-Key frames
- **RSN_Parser**: The component that parses RSN Information Elements
- **Config_Manager**: The component that manages system configuration
- **PMKID**: Pairwise Master Key Identifier - 16 bytes extracted from RSN IE
- **ANonce**: Authenticator Nonce - 32 bytes from Message 1 or 3
- **SNonce**: Supplicant Nonce - 32 bytes from Message 2
- **MIC**: Message Integrity Code - 16 bytes from Message 2
- **EAPOL**: Extensible Authentication Protocol over LAN
- **RSN_IE**: Robust Security Network Information Element (Tag ID 48)
- **Message_1**: First message of 4-way handshake (AP to Client, contains ANonce)
- **Message_2**: Second message of 4-way handshake (Client to AP, contains SNonce and MIC)
- **Message_3**: Third message of 4-way handshake (AP to Client, contains ANonce)
- **Message_4**: Fourth message of 4-way handshake (Client to AP, contains MIC)
- **BSSID**: Basic Service Set Identifier - MAC address of the Access Point
- **ESSID**: Extended Service Set Identifier - Network name (SSID)

## Requirements

### Requirement 1: Output Format Configuration

**User Story:** As a user, I want to choose between PCAP and HC22000 output formats, so that I can use the format appropriate for my needs

#### Acceptance Criteria

1. THE Config_Manager SHALL provide a configuration option to select output format (PCAP or HC22000)
2. WHEN the system starts, THE Config_Manager SHALL load the configured output format
3. THE Config_Manager SHALL default to PCAP format for backward compatibility
4. THE PCAP_Manager SHALL use the configured format when creating output files

### Requirement 2: PMKID Extraction from Beacon Frames

**User Story:** As a user, I want to extract PMKID from Beacon frames, so that I can attempt password recovery using PMKID attacks

#### Acceptance Criteria

1. WHEN a Beacon frame is received, THE Frame_Parser SHALL locate the RSN Information Element (Tag ID 48)
2. IF the RSN IE contains a PMKID (16 bytes at the end), THEN THE RSN_Parser SHALL extract the PMKID
3. THE RSN_Parser SHALL extract the BSSID from the Beacon frame (bytes 16-21)
4. THE RSN_Parser SHALL extract the ESSID from the Beacon frame SSID element
5. WHEN PMKID extraction is complete, THE HC22000_Extractor SHALL format the data according to HC22000 specification
6. THE File_Writer SHALL append the PMKID data as a new line to the session HC22000 file

### Requirement 3: PMKID Extraction from Association Frames

**User Story:** As a user, I want to extract PMKID from Association Response frames, so that I can capture PMKID from multiple frame types

#### Acceptance Criteria

1. WHEN an Association Response frame (subtype 0x1) is received, THE Frame_Parser SHALL locate the RSN Information Element
2. WHEN a Reassociation Response frame (subtype 0x3) is received, THE Frame_Parser SHALL locate the RSN Information Element
3. IF the RSN IE contains a PMKID, THEN THE RSN_Parser SHALL extract the PMKID
4. THE RSN_Parser SHALL extract BSSID and ESSID from the Association Response frame
5. THE HC22000_Extractor SHALL format the PMKID data according to HC22000 specification

### Requirement 4: Message Type Detection

**User Story:** As a user, I want the system to correctly identify EAPOL message types, so that handshake pairs can be matched accurately

#### Acceptance Criteria

1. WHEN an EAPOL-Key frame is received, THE EAPOL_Parser SHALL extract the Key Information field (2 bytes at offset 5-6)
2. IF Key Ack=1 AND MIC=0 AND Install=0, THEN THE EAPOL_Parser SHALL classify the message as Message_1
3. IF Key Ack=0 AND MIC=1 AND Install=0 AND the message follows Message_1, THEN THE EAPOL_Parser SHALL classify the message as Message_2
4. IF Key Ack=1 AND MIC=1 AND Install=1, THEN THE EAPOL_Parser SHALL classify the message as Message_3
5. IF Key Ack=0 AND MIC=1 AND Install=0 AND the message follows Message_3, THEN THE EAPOL_Parser SHALL classify the message as Message_4
6. THE EAPOL_Parser SHALL verify the Pairwise bit is set (bit 3 of Key Information) for all messages

### Requirement 5: M12 Handshake Extraction

**User Story:** As a user, I want to extract Message 1 + Message 2 pairs, so that I can perform password recovery using M12 handshakes

#### Acceptance Criteria

1. WHEN Message_1 is detected, THE HC22000_Extractor SHALL extract ANonce (32 bytes at EAPOL offset 13)
2. WHEN Message_1 is detected, THE HC22000_Extractor SHALL extract the AP BSSID
3. WHEN Message_2 is detected for the same BSSID, THE HC22000_Extractor SHALL extract SNonce (32 bytes at EAPOL offset 13)
4. WHEN Message_2 is detected, THE HC22000_Extractor SHALL extract MIC (16 bytes at EAPOL offset 77)
5. WHEN Message_2 is detected, THE HC22000_Extractor SHALL extract the full EAPOL payload
6. WHEN Message_2 is detected, THE HC22000_Extractor SHALL extract the Client MAC address
7. WHEN both Message_1 and Message_2 are captured for the same BSSID, THE HC22000_Extractor SHALL combine them into an M12 pair
8. THE File_Writer SHALL append the M12 data as a new line to the session HC22000 file

### Requirement 6: M32 Handshake Extraction

**User Story:** As a user, I want to extract Message 3 + Message 2 pairs, so that I can perform password recovery using alternative handshake captures

#### Acceptance Criteria

1. WHEN Message_3 is detected, THE HC22000_Extractor SHALL extract ANonce (32 bytes at EAPOL offset 13)
2. WHEN Message_3 is detected, THE HC22000_Extractor SHALL extract the AP BSSID
3. WHEN Message_2 is detected for the same BSSID, THE HC22000_Extractor SHALL extract SNonce, MIC, EAPOL payload, and Client MAC
4. WHEN both Message_3 and Message_2 are captured for the same BSSID, THE HC22000_Extractor SHALL combine them into an M32 pair
5. THE File_Writer SHALL append the M32 data as a new line to the session HC22000 file

### Requirement 7: HC22000 Format Compliance

**User Story:** As a user, I want HC22000 files to be correctly formatted, so that Hashcat can parse them without errors

#### Acceptance Criteria

1. THE HC22000_Extractor SHALL format output as: `WPA*02*PMKID/MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL*MESSAGEPAIR`
2. THE HC22000_Extractor SHALL hex-encode all binary data fields (MAC addresses, nonces, MIC, EAPOL)
3. THE HC22000_Extractor SHALL use asterisk (*) as field separator
4. THE HC22000_Extractor SHALL encode ESSID as hex string
5. THE HC22000_Extractor SHALL set MESSAGEPAIR field to appropriate value (0 for PMKID, 2 for M12, 3 for M32)
6. THE HC22000_Extractor SHALL append newline character after each record
7. THE HC22000_Extractor SHALL handle endianness correctly (network byte order is big endian)

### Requirement 8: Data Validation

**User Story:** As a user, I want the system to validate extracted data, so that only complete and valid HC22000 records are written

#### Acceptance Criteria

1. WHEN extracting PMKID, THE RSN_Parser SHALL verify PMKID length is exactly 16 bytes
2. WHEN extracting ANonce, THE EAPOL_Parser SHALL verify ANonce length is exactly 32 bytes
3. WHEN extracting SNonce, THE EAPOL_Parser SHALL verify SNonce length is exactly 32 bytes
4. WHEN extracting MIC, THE EAPOL_Parser SHALL verify MIC length is exactly 16 bytes
5. WHEN extracting ESSID, THE Frame_Parser SHALL verify ESSID length is between 0 and 32 bytes
6. IF any validation fails, THEN THE HC22000_Extractor SHALL discard the incomplete data and log an error
7. THE HC22000_Extractor SHALL verify all required fields are present before writing to file

### Requirement 9: File Naming and Management

**User Story:** As a user, I want a single HC22000 file per capture session, so that all extracted hashes are consolidated in one place

#### Acceptance Criteria

1. WHEN capture starts in HC22000 mode, THE File_Writer SHALL create a file named `/.auto_{timestamp}.hc22000`
2. THE File_Writer SHALL use the same timestamp format as PCAP files for consistency
3. THE File_Writer SHALL keep the file open throughout the capture session
4. WHEN a PMKID is extracted, THE File_Writer SHALL append one line to the session file
5. WHEN an M12 pair is complete, THE File_Writer SHALL append one line to the session file
6. WHEN an M32 pair is complete, THE File_Writer SHALL append one line to the session file
7. WHEN capture stops, THE File_Writer SHALL close the session file
8. THE File_Writer SHALL support multiple networks and multiple hash types in the same file

### Requirement 10: Memory Optimization

**User Story:** As a user, I want the system to operate within ESP32 memory constraints, so that captures remain stable during long sessions

#### Acceptance Criteria

1. THE HC22000_Extractor SHALL process packets without buffering complete frames
2. THE HC22000_Extractor SHALL extract data using direct offset calculations
3. THE HC22000_Extractor SHALL reuse existing packet filtering infrastructure
4. THE HC22000_Extractor SHALL limit the number of tracked handshake pairs to MAX_HANDSHAKES
5. WHEN memory is low (free heap < 8000 bytes), THE HC22000_Extractor SHALL skip packet processing
6. THE HC22000_Extractor SHALL use stack allocation for temporary buffers where possible

### Requirement 11: Backward Compatibility

**User Story:** As a user, I want to retain PCAP capture functionality, so that I can choose the appropriate format for my workflow

#### Acceptance Criteria

1. THE Config_Manager SHALL maintain existing PCAP capture functionality
2. WHEN PCAP mode is selected, THE PCAP_Manager SHALL operate exactly as before
3. WHEN HC22000 mode is selected, THE PCAP_Manager SHALL use HC22000_Extractor instead of PCAP writer
4. THE Config_Manager SHALL allow runtime switching between modes via configuration
5. THE system SHALL preserve all existing PCAP-related functions and structures

### Requirement 12: Real-time Processing

**User Story:** As a user, I want HC22000 extraction to happen in real-time, so that I can see results immediately without post-processing

#### Acceptance Criteria

1. WHEN a relevant frame is captured, THE HC22000_Extractor SHALL process it immediately in the packet handler
2. WHEN extraction is complete, THE File_Writer SHALL append the HC22000 record to the session file immediately
3. THE File_Writer SHALL flush data to storage within 1 second of extraction
4. THE system SHALL log successful extractions to Serial output in real-time
5. THE system SHALL display extraction statistics (PMKID count, M12 count, M32 count) during capture

### Requirement 13: Error Handling

**User Story:** As a user, I want the system to handle errors gracefully, so that capture continues even when individual frames fail to parse

#### Acceptance Criteria

1. IF frame parsing fails, THEN THE Frame_Parser SHALL log the error and continue processing
2. IF EAPOL parsing fails, THEN THE EAPOL_Parser SHALL log the error and continue processing
3. IF file write fails, THEN THE File_Writer SHALL log the error and retry once
4. IF SPIFFS is full, THEN THE File_Writer SHALL log an error and close the session file
5. THE system SHALL continue capturing and processing packets even when individual extractions fail
6. THE system SHALL display error counts in capture statistics

### Requirement 14: Hex Encoding

**User Story:** As a user, I want all binary data to be correctly hex-encoded, so that Hashcat can parse the HC22000 files

#### Acceptance Criteria

1. THE HC22000_Extractor SHALL provide a hex encoding function that converts binary data to hex strings
2. THE hex encoding function SHALL use lowercase hexadecimal characters (0-9, a-f)
3. THE hex encoding function SHALL produce exactly 2 characters per input byte
4. THE HC22000_Extractor SHALL apply hex encoding to: MAC addresses, PMKID, ANonce, SNonce, MIC, EAPOL payload, and ESSID
5. THE hex encoding function SHALL handle zero-length inputs by producing empty strings

### Requirement 15: ESSID Extraction and Encoding

**User Story:** As a user, I want ESSID to be correctly extracted and encoded, so that Hashcat can identify the target network

#### Acceptance Criteria

1. WHEN processing a Beacon frame, THE Frame_Parser SHALL locate the SSID element (Tag ID 0)
2. THE Frame_Parser SHALL extract the SSID string from the element
3. THE Frame_Parser SHALL handle hidden SSIDs (zero-length SSID) by using an empty string
4. THE HC22000_Extractor SHALL hex-encode the ESSID for inclusion in HC22000 format
5. THE HC22000_Extractor SHALL maintain an ESSID lookup table mapping BSSID to ESSID
6. WHEN processing EAPOL frames, THE HC22000_Extractor SHALL retrieve ESSID from the lookup table using BSSID

### Requirement 16: Handshake Pair Tracking

**User Story:** As a user, I want the system to track handshake pairs correctly, so that M12 and M32 pairs are matched accurately

#### Acceptance Criteria

1. THE HC22000_Extractor SHALL maintain a handshake state table indexed by BSSID
2. WHEN Message_1 is captured, THE HC22000_Extractor SHALL store ANonce and timestamp in the state table
3. WHEN Message_2 is captured, THE HC22000_Extractor SHALL check if Message_1 exists for the same BSSID
4. WHEN Message_3 is captured, THE HC22000_Extractor SHALL store ANonce and timestamp in the state table
5. WHEN Message_2 is captured, THE HC22000_Extractor SHALL check if Message_3 exists for the same BSSID
6. THE HC22000_Extractor SHALL create M12 pair when Message_1 and Message_2 are both present
7. THE HC22000_Extractor SHALL create M32 pair when Message_3 and Message_2 are both present
8. THE HC22000_Extractor SHALL expire handshake state entries after 30 seconds

### Requirement 17: Statistics and Logging

**User Story:** As a user, I want to see extraction statistics, so that I can monitor capture progress and success rate

#### Acceptance Criteria

1. THE HC22000_Extractor SHALL maintain counters for: PMKID extractions, M12 pairs, M32 pairs, and extraction errors
2. WHEN a PMKID is extracted, THE HC22000_Extractor SHALL log the BSSID and ESSID to Serial
3. WHEN an M12 pair is complete, THE HC22000_Extractor SHALL log the BSSID and ESSID to Serial
4. WHEN an M32 pair is complete, THE HC22000_Extractor SHALL log the BSSID and ESSID to Serial
5. WHEN capture stops, THE system SHALL display final statistics including all extraction counts
6. THE system SHALL display extraction success rate (successful extractions / total relevant frames)

### Requirement 18: EAPOL Payload Extraction

**User Story:** As a user, I want the complete EAPOL payload to be extracted, so that Hashcat has all necessary data for password recovery

#### Acceptance Criteria

1. WHEN Message_2 is detected, THE EAPOL_Parser SHALL extract the complete EAPOL frame starting from the EAPOL header
2. THE EAPOL_Parser SHALL determine EAPOL frame length from the Length field (bytes 2-3 of EAPOL header)
3. THE EAPOL_Parser SHALL extract EAPOL payload up to the determined length
4. THE EAPOL_Parser SHALL verify EAPOL payload length is at least 121 bytes (minimum for WPA2)
5. THE HC22000_Extractor SHALL hex-encode the complete EAPOL payload for HC22000 format

### Requirement 19: RSN Information Element Parsing

**User Story:** As a user, I want RSN IE to be correctly parsed, so that PMKID can be reliably extracted

#### Acceptance Criteria

1. WHEN parsing management frames, THE RSN_Parser SHALL scan for Tag ID 48 (RSN Information Element)
2. THE RSN_Parser SHALL extract the element length from the byte following Tag ID
3. THE RSN_Parser SHALL verify the element length is at least 20 bytes (minimum RSN IE size)
4. IF the element length is at least 36 bytes, THEN THE RSN_Parser SHALL check for PMKID at the end
5. THE RSN_Parser SHALL extract PMKID as the last 16 bytes of the RSN IE
6. THE RSN_Parser SHALL verify PMKID is non-zero before accepting it

### Requirement 20: Configuration Options

**User Story:** As a user, I want to configure HC22000 extraction behavior, so that I can customize the system for my needs

#### Acceptance Criteria

1. THE Config_Manager SHALL provide a configuration option to enable/disable PMKID extraction
2. THE Config_Manager SHALL provide a configuration option to enable/disable M12 extraction
3. THE Config_Manager SHALL provide a configuration option to enable/disable M32 extraction
4. THE Config_Manager SHALL provide a configuration option to set maximum handshake pairs to track
5. THE Config_Manager SHALL provide a configuration option to set handshake state timeout (default 30 seconds)
6. THE Config_Manager SHALL load configuration from config.h at compile time
