package rules

import (
	"bytes"
)

// Match evaluates the rule's content and PCRE options against a payload.
// It follows Snort's sticky cursor evaluation model.
func (r *Rule) Match(payload []byte) bool {
	cursor := 0

	for _, content := range r.Contents {
		start := 0
		if content.Modifier.Offset >= 0 {
			start = content.Modifier.Offset
		} else if content.Modifier.Distance >= 0 {
			start = cursor + content.Modifier.Distance
		} else if content.Modifier.Within >= 0 {
			start = cursor
		}

		if start > len(payload) {
			return false
		}
		
		end := len(payload)
		if content.Modifier.Depth >= 0 {
			if start + content.Modifier.Depth <= end {
				end = start + content.Modifier.Depth
			}
		} else if content.Modifier.Within >= 0 {
			if start + content.Modifier.Within <= end {
				end = start + content.Modifier.Within
			}
		}

		if start > end {
			return false
		}
		
		searchBuf := payload[start:end]
		
		var matchIdx int
		if content.Modifier.Nocase {
			lowerBuf := bytes.ToLower(searchBuf)
			matchIdx = bytes.Index(lowerBuf, content.Pattern)
		} else {
			matchIdx = bytes.Index(searchBuf, content.Pattern)
		}

		if matchIdx == -1 {
			return false
		}

		// Update cursor for the next sticky content match
		cursor = start + matchIdx + len(content.Pattern)
	}

	if r.PCRE != nil {
		if !r.PCRE.Match(payload) {
			return false
		}
	}

	return true
}
