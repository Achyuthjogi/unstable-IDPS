package inspect

import (
	"bytes"
)

// SSHInspector analyzes SSH traffic.
type SSHInspector struct{}

// Inspect checks for SSH anomalies in the protocol handshake.
func (s *SSHInspector) Inspect(payload []byte) bool {
	// Check for deprecated SSH versions
	if bytes.HasPrefix(payload, []byte("SSH-1.")) {
		return true // Anomaly: SSHv1 is deprecated and insecure
	}
	return false
}
