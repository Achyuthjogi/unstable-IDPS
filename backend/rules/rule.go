package rules

import (
	"regexp"
)

// Action defines what to do when a rule matches.
type Action string

const (
	ActionAlert Action = "alert"
	ActionDrop  Action = "drop"
	ActionPass  Action = "pass"
	ActionLog   Action = "log"
)

// ContentModifier defines how a content match should be evaluated.
type ContentModifier struct {
	Nocase   bool
	Offset   int // Absolute offset from start of payload
	Depth    int // Search depth from offset
	Distance int // Relative offset from end of previous match
	Within   int // Search depth from end of previous match + distance
}

// ContentMatch represents a byte pattern match option in a rule.
type ContentMatch struct {
	Pattern  []byte
	Modifier ContentModifier
}

// Rule represents a Snort-inspired detection rule.
type Rule struct {
	// Rule Header
	Action    Action
	Protocol  string // "tcp", "udp", "icmp", "ip"
	SrcNet    string // CIDR, IP, or "any"
	SrcPort   string // Port, port range, or "any"
	Direction string // "->" or "<>"
	DstNet    string
	DstPort   string

	// Metadata Options
	SID       int
	Rev       int
	Msg       string
	Classtype string
	Reference []string
	Priority  int

	// Detection Options
	Contents  []ContentMatch
	PCRE      *regexp.Regexp
	FlowOpts  map[string]bool // e.g. "established", "to_server", "to_client"
}
