package inspect

import (
	"bytes"
	"strings"
)

// HTTPInspector analyzes HTTP traffic.
type HTTPInspector struct{}

// InspectRequest extracts basic HTTP request info and checks for anomalies.
// Returns (method, uri, isAnomaly)
func (h *HTTPInspector) InspectRequest(payload []byte) (string, string, bool) {
	if len(payload) < 10 {
		return "", "", false
	}

	// Fast check for HTTP methods
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "),
		[]byte("PATCH "),
	}

	var method string
	var match []byte
	for _, m := range methods {
		if bytes.HasPrefix(payload, m) {
			method = string(bytes.TrimSpace(m))
			match = m
			break
		}
	}

	if method == "" {
		// Not HTTP or invalid method
		// If it looks like text but not a valid method, check if it's an HTTP response from a server
		if bytes.HasPrefix(payload, []byte("HTTP/1.")) || bytes.HasPrefix(payload, []byte("HTTP/2.")) {
			return "RESPONSE", "", false // Benign HTTP response
		}

		// If it still contains HTTP/ but doesn't match standard methods or response formats, it's an anomaly
		if bytes.Contains(payload, []byte("HTTP/")) {
			return "", "", true // Anomaly: Invalid method
		}
		return "", "", false
	}

	// Extract URI
	start := len(match)
	end := bytes.Index(payload[start:], []byte(" HTTP/"))
	if end == -1 {
		return method, "", true // Anomaly: Malformed request line
	}

	uri := string(payload[start : start+end])

	// Alert only when traversal escapes the URI root. Relative paths such as
	// /static/css/../images/logo.png are normal browser requests.
	if escapesURIRoot(uri) {
		return method, uri, true
	}

	return method, uri, false
}

func escapesURIRoot(uri string) bool {
	uri = strings.ReplaceAll(uri, `\`, "/")
	depth := 0
	for _, segment := range strings.Split(uri, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			if depth == 0 {
				return true
			}
			depth--
		default:
			depth++
		}
	}
	return false
}
