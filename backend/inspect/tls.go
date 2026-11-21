package inspect

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// TLSFingerprint encapsulates the complete Encrypted Traffic Analytics (ETA) profile.
type TLSFingerprint struct {
	SNI             string   `json:"sni"`
	Version         uint16   `json:"version"`
	VersionStr      string   `json:"version_str"`
	CipherSuites    []uint16 `json:"cipher_suites"`
	Extensions      []uint16 `json:"extensions"`
	Curves          []uint16 `json:"curves"`
	PointFormats    []uint8  `json:"point_formats"`
	ALPN            []string `json:"alpn,omitempty"`
	JA3Raw          string   `json:"ja3_raw"`
	JA3Hash         string   `json:"ja3_hash"`
	IsMaliciousJA3  bool     `json:"is_malicious_ja3"`
	MalwareFamily   string   `json:"malware_family,omitempty"`
	ThreatSeverity  string   `json:"threat_severity,omitempty"`
	IsWeakCipher    bool     `json:"is_weak_cipher"`
	WeakCipherDesc  string   `json:"weak_cipher_desc,omitempty"`
	IsDeprecatedVer bool     `json:"is_deprecated_ver"`
}

// Known malicious JA3 database (Cobalt Strike, Emotet, TrickBot, Metasploit, AsyncRAT, etc.)
var knownMaliciousJA3 = map[string]struct {
	Name     string
	Severity string
}{
	"a0e9f5d64349fb13191bc781f81f42e1": {Name: "Cobalt Strike HTTPS Beacon", Severity: "Critical"},
	"72a589da586844d7f0818ce684948eea": {Name: "Cobalt Strike Malleable C2", Severity: "Critical"},
	"b32309a26951912be7dba376398abc3b": {Name: "Metasploit Meterpreter Reverse HTTPS", Severity: "Critical"},
	"4d7a28d6f22da2e8ee309e8699c70376": {Name: "Emotet Banking Trojan C2", Severity: "Critical"},
	"6734f3743167022587532acab30bf442": {Name: "TrickBot Anchor C2", Severity: "Critical"},
	"fd37536d5012e75e11f7c132c32cf988": {Name: "AsyncRAT / Quasar Remote Access Trojan", Severity: "High"},
	"51c64c77e60f3980eea90869b68c58a8": {Name: "Dridex / Bugat Malware C2", Severity: "Critical"},
	"bb861217eef9f27042a5c48b26e0b4f8": {Name: "QakBot (QBot) Loader", Severity: "Critical"},
	"3b5074b1b95c324c4c442950f8004927": {Name: "Go-Exploit Automated Scanning Framework", Severity: "High"},
	"59392e27606cb74fc894f7945d8b2d18": {Name: "Empire PowerShell Post-Exploitation Agent", Severity: "Critical"},
}

// Insecure/weak cipher suites (RC4, DES, 3DES, EXPORT, NULL)
var weakCiphers = map[uint16]string{
	0x0001: "TLS_RSA_WITH_NULL_MD5 (No Encryption)",
	0x0002: "TLS_RSA_WITH_NULL_SHA (No Encryption)",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5 (Insecure RC4)",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA (Insecure RC4)",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA (Insecure 56-bit DES)",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA (Sweet32 Vulnerable 3DES)",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (Deprecated 3DES)",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (Deprecated 3DES)",
	0xc002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA (Insecure RC4)",
	0xc003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (Deprecated 3DES)",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (Insecure RC4)",
	0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (Deprecated 3DES)",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA (Insecure RC4)",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (Deprecated 3DES)",
}

// GREASE values as defined in RFC 8701 (must be filtered out for standard JA3 calculation)
func isGREASE(val uint16) bool {
	switch val {
	case 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa:
		return true
	}
	return false
}

// TLSInspector analyzes TLS traffic and computes JA3/JA3S fingerprints.
type TLSInspector struct {
	mu          sync.RWMutex
	customRules map[string]string // custom JA3 hash -> description
}

// NewTLSInspector creates an enterprise TLS Inspector.
func NewTLSInspector() *TLSInspector {
	return &TLSInspector{
		customRules: make(map[string]string),
	}
}

// AddCustomJA3Rule allows operators to register custom threat fingerprints at runtime.
func (t *TLSInspector) AddCustomJA3Rule(ja3Hash, description string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.customRules[strings.ToLower(strings.TrimSpace(ja3Hash))] = description
}

// InspectClientHello preserves backwards compatibility.
func (t *TLSInspector) InspectClientHello(payload []byte) (string, bool) {
	fp := t.InspectDetailed(payload)
	if fp == nil || fp.SNI == "" {
		return "", false
	}
	return fp.SNI, true
}

// InspectDetailed produces a comprehensive Encrypted Traffic Analytics (ETA) evaluation.
func (t *TLSInspector) InspectDetailed(payload []byte) *TLSFingerprint {
	if len(payload) < 43 {
		return nil
	}
	// Record Content Type: Handshake (0x16)
	if payload[0] != 0x16 {
		return nil
	}
	// Handshake Message Type: Client Hello (0x01)
	if payload[5] != 0x01 {
		return nil
	}

	fp := &TLSFingerprint{
		CipherSuites: make([]uint16, 0),
		Extensions:   make([]uint16, 0),
		Curves:       make([]uint16, 0),
		PointFormats: make([]uint8, 0),
		ALPN:         make([]string, 0),
	}

	// Handshake Client Version (bytes 9-10)
	clientVersion := uint16(payload[9])<<8 | uint16(payload[10])
	fp.Version = clientVersion
	switch clientVersion {
	case 0x0300:
		fp.VersionStr = "SSL 3.0"
		fp.IsDeprecatedVer = true
	case 0x0301:
		fp.VersionStr = "TLS 1.0"
		fp.IsDeprecatedVer = true
	case 0x0302:
		fp.VersionStr = "TLS 1.1"
		fp.IsDeprecatedVer = true
	case 0x0303:
		fp.VersionStr = "TLS 1.2"
	case 0x0304:
		fp.VersionStr = "TLS 1.3"
	default:
		fp.VersionStr = fmt.Sprintf("Unknown (0x%04x)", clientVersion)
	}

	// Offset past: Record Header (5) + Handshake Header (4) + Version (2) + Random (32) = 43
	offset := 43
	if offset >= len(payload) {
		return nil
	}

	// Session ID
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(payload) {
		return nil
	}

	// Cipher Suites Length
	cipherSuitesLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2
	if offset+cipherSuitesLen > len(payload) {
		return nil
	}

	var ja3Ciphers []string
	for i := 0; i < cipherSuitesLen; i += 2 {
		c := uint16(payload[offset+i])<<8 | uint16(payload[offset+i+1])
		if !isGREASE(c) {
			fp.CipherSuites = append(fp.CipherSuites, c)
			ja3Ciphers = append(ja3Ciphers, strconv.Itoa(int(c)))
			if desc, isWeak := weakCiphers[c]; isWeak && !fp.IsWeakCipher {
				fp.IsWeakCipher = true
				fp.WeakCipherDesc = desc
			}
		}
	}
	offset += cipherSuitesLen
	if offset >= len(payload) {
		return fp
	}

	// Compression Methods Length
	compMethodsLen := int(payload[offset])
	offset += 1 + compMethodsLen
	if offset+2 > len(payload) {
		return fp
	}

	// Extensions Length
	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2
	end := offset + extensionsLen
	if end > len(payload) {
		end = len(payload)
	}

	var ja3Extensions []string
	var ja3Curves []string
	var ja3Points []string

	for offset+4 <= end {
		extType := uint16(payload[offset])<<8 | uint16(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		extDataStart := offset + 4
		offset += 4 + extLen
		if extDataStart+extLen > end {
			break
		}

		if !isGREASE(extType) {
			fp.Extensions = append(fp.Extensions, extType)
			ja3Extensions = append(ja3Extensions, strconv.Itoa(int(extType)))
		}

		// Parse Specific Extensions
		switch extType {
		case 0x0000: // Server Name Indication (SNI)
			if extLen >= 2 {
				sniListLen := int(payload[extDataStart])<<8 | int(payload[extDataStart+1])
				sniOffset := extDataStart + 2
				for sniOffset+3 <= extDataStart+extLen && (sniOffset-extDataStart-2) < sniListLen {
					nameType := payload[sniOffset]
					nameLen := int(payload[sniOffset+1])<<8 | int(payload[sniOffset+2])
					sniOffset += 3
					if nameType == 0x00 && sniOffset+nameLen <= extDataStart+extLen {
						fp.SNI = string(payload[sniOffset : sniOffset+nameLen])
						break
					}
					sniOffset += nameLen
				}
			}

		case 0x000a: // Supported Elliptic Curves / Groups (Extension 10)
			if extLen >= 2 {
				curvesListLen := int(payload[extDataStart])<<8 | int(payload[extDataStart+1])
				curvesOffset := extDataStart + 2
				for i := 0; i < curvesListLen && curvesOffset+i+2 <= extDataStart+extLen; i += 2 {
					curve := uint16(payload[curvesOffset+i])<<8 | uint16(payload[curvesOffset+i+1])
					if !isGREASE(curve) {
						fp.Curves = append(fp.Curves, curve)
						ja3Curves = append(ja3Curves, strconv.Itoa(int(curve)))
					}
				}
			}

		case 0x000b: // EC Point Formats (Extension 11)
			if extLen >= 1 {
				pointsListLen := int(payload[extDataStart])
				pointsOffset := extDataStart + 1
				for i := 0; i < pointsListLen && pointsOffset+i < extDataStart+extLen; i++ {
					point := payload[pointsOffset+i]
					fp.PointFormats = append(fp.PointFormats, point)
					ja3Points = append(ja3Points, strconv.Itoa(int(point)))
				}
			}

		case 0x0010: // Application-Layer Protocol Negotiation (ALPN)
			if extLen >= 2 {
				alpnListLen := int(payload[extDataStart])<<8 | int(payload[extDataStart+1])
				alpnOffset := extDataStart + 2
				for alpnOffset < extDataStart+2+alpnListLen && alpnOffset < extDataStart+extLen {
					protoLen := int(payload[alpnOffset])
					alpnOffset++
					if alpnOffset+protoLen <= extDataStart+extLen {
						fp.ALPN = append(fp.ALPN, string(payload[alpnOffset:alpnOffset+protoLen]))
						alpnOffset += protoLen
					} else {
						break
					}
				}
			}
		}
	}

	// Compute Standard JA3 Raw String:
	// Format: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
	ja3Raw := fmt.Sprintf("%d,%s,%s,%s,%s",
		fp.Version,
		strings.Join(ja3Ciphers, "-"),
		strings.Join(ja3Extensions, "-"),
		strings.Join(ja3Curves, "-"),
		strings.Join(ja3Points, "-"),
	)
	fp.JA3Raw = ja3Raw

	// Compute MD5
	h := md5.Sum([]byte(ja3Raw))
	fp.JA3Hash = hex.EncodeToString(h[:])

	// Evaluate Threat Intelligence on JA3 Fingerprint
	if malInfo, exists := knownMaliciousJA3[fp.JA3Hash]; exists {
		fp.IsMaliciousJA3 = true
		fp.MalwareFamily = malInfo.Name
		fp.ThreatSeverity = malInfo.Severity
	} else {
		t.mu.RLock()
		if desc, customExists := t.customRules[fp.JA3Hash]; customExists {
			fp.IsMaliciousJA3 = true
			fp.MalwareFamily = desc
			fp.ThreatSeverity = "High"
		}
		t.mu.RUnlock()
	}

	return fp
}
