package inspect

type TLSInspector struct{}

// InspectClientHello parses a TLS Client Hello packet to extract the Server Name Indication (SNI).
// Returns the hostname and a boolean indicating if it was found.
func (t *TLSInspector) InspectClientHello(payload []byte) (string, bool) {
	if len(payload) < 43 {
		return "", false
	}
	// Content Type: Handshake (22)
	if payload[0] != 0x16 {
		return "", false
	}
	// Handshake Type: Client Hello (1)
	if payload[5] != 0x01 {
		return "", false
	}

	// Record Header: 5 bytes
	// Handshake Header: 4 bytes
	// Client Version: 2 bytes
	// Random: 32 bytes
	offset := 5 + 4 + 2 + 32
	if offset >= len(payload) {
		return "", false
	}
	
	// Session ID
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset >= len(payload) {
		return "", false
	}
	
	// Cipher Suites
	if offset+2 > len(payload) {
		return "", false
	}
	cipherSuitesLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + cipherSuitesLen
	if offset >= len(payload) {
		return "", false
	}
	
	// Compression Methods
	compMethodsLen := int(payload[offset])
	offset += 1 + compMethodsLen
	if offset >= len(payload) {
		return "", false
	}
	
	// Extensions Length
	if offset+2 > len(payload) {
		return "", false
	}
	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2

	end := offset + extensionsLen
	if end > len(payload) {
		end = len(payload)
	}

	for offset+4 <= end {
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		offset += 4
		if offset+extLen > end {
			break
		}
		
		if extType == 0x0000 { // Server Name Indication
			if extLen < 2 {
				break
			}
			sniListLen := int(payload[offset])<<8 | int(payload[offset+1])
			sniOffset := offset + 2
			for sniOffset+3 <= offset+extLen && (sniOffset-offset-2) < sniListLen {
				nameType := payload[sniOffset]
				nameLen := int(payload[sniOffset+1])<<8 | int(payload[sniOffset+2])
				sniOffset += 3
				if nameType == 0x00 && sniOffset+nameLen <= offset+extLen {
					serverName := string(payload[sniOffset : sniOffset+nameLen])
					return serverName, true
				}
				sniOffset += nameLen
			}
		}
		offset += extLen
	}
	return "", false
}
