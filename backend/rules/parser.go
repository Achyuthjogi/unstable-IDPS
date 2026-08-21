package rules

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParseRule parses a Snort-like rule string into a Rule struct.
func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil // skip empty or comment lines
	}

	parts := strings.SplitN(line, "(", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid rule format: missing '('")
	}

	header := strings.Fields(strings.TrimSpace(parts[0]))
	if len(header) != 7 {
		return nil, fmt.Errorf("invalid rule header: expected 7 fields, got %d", len(header))
	}

	rule := &Rule{
		Action:    Action(header[0]),
		Protocol:  header[1],
		SrcNet:    header[2],
		SrcPort:   header[3],
		Direction: header[4],
		DstNet:    header[5],
		DstPort:   header[6],
		FlowOpts:  make(map[string]bool),
	}

	bodyStr := strings.TrimSpace(parts[1])
	if !strings.HasSuffix(bodyStr, ")") {
		return nil, fmt.Errorf("invalid rule body: missing closing ')'")
	}
	bodyStr = bodyStr[:len(bodyStr)-1]

	opts := parseOptions(bodyStr)
	
	var lastContent *ContentMatch

	for _, opt := range opts {
		if opt.Key == "msg" {
			rule.Msg = strings.Trim(opt.Value, `"`)
		} else if opt.Key == "sid" {
			rule.SID, _ = strconv.Atoi(opt.Value)
		} else if opt.Key == "rev" {
			rule.Rev, _ = strconv.Atoi(opt.Value)
		} else if opt.Key == "classtype" {
			rule.Classtype = opt.Value
		} else if opt.Key == "priority" {
			rule.Priority, _ = strconv.Atoi(opt.Value)
		} else if opt.Key == "reference" {
			rule.Reference = append(rule.Reference, opt.Value)
		} else if opt.Key == "flow" {
			for _, fopt := range strings.Split(opt.Value, ",") {
				rule.FlowOpts[strings.TrimSpace(fopt)] = true
			}
		} else if opt.Key == "content" {
			contentVal := strings.Trim(opt.Value, `"`)
			parsedContent, err := ParseHexContent(contentVal)
			if err == nil {
				c := ContentMatch{
					Pattern: parsedContent,
					Modifier: ContentModifier{
						Offset: -1, Depth: -1, Distance: -1, Within: -1,
					},
				}
				rule.Contents = append(rule.Contents, c)
				lastContent = &rule.Contents[len(rule.Contents)-1]
			}
		} else if opt.Key == "nocase" {
			if lastContent != nil {
				lastContent.Modifier.Nocase = true
				for i, b := range lastContent.Pattern {
					if b >= 'A' && b <= 'Z' {
						lastContent.Pattern[i] = b + 32
					}
				}
			}
		} else if opt.Key == "offset" {
			if lastContent != nil {
				lastContent.Modifier.Offset, _ = strconv.Atoi(opt.Value)
			}
		} else if opt.Key == "depth" {
			if lastContent != nil {
				lastContent.Modifier.Depth, _ = strconv.Atoi(opt.Value)
			}
		} else if opt.Key == "distance" {
			if lastContent != nil {
				lastContent.Modifier.Distance, _ = strconv.Atoi(opt.Value)
			}
		} else if opt.Key == "within" {
			if lastContent != nil {
				lastContent.Modifier.Within, _ = strconv.Atoi(opt.Value)
			}
		} else if opt.Key == "pcre" {
			pcreVal := strings.Trim(opt.Value, `"`)
			if len(pcreVal) > 2 && pcreVal[0] == '/' {
				lastSlash := strings.LastIndex(pcreVal, "/")
				if lastSlash > 0 {
					pattern := pcreVal[1:lastSlash]
					flags := pcreVal[lastSlash+1:]
					if strings.Contains(flags, "i") {
						pattern = "(?i)" + pattern
					}
					re, err := regexp.Compile(pattern)
					if err == nil {
						rule.PCRE = re
					}
				}
			}
		}
	}

	return rule, nil
}

type option struct {
	Key   string
	Value string
}

// parseOptions naively splits the rule body options.
// A real parser would handle escaped semicolons and quotes properly.
func parseOptions(bodyStr string) []option {
	var opts []option
	
	// Custom split to handle escaped semicolons (\;)
	var parts []string
	var current strings.Builder
	for i := 0; i < len(bodyStr); i++ {
		if bodyStr[i] == '\\' && i+1 < len(bodyStr) && bodyStr[i+1] == ';' {
			current.WriteByte(';')
			i++ // skip the escaped semicolon
		} else if bodyStr[i] == ';' {
			parts = append(parts, current.String())
			current.Reset()
		} else {
			current.WriteByte(bodyStr[i])
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := ""
		if len(kv) > 1 {
			val = strings.TrimSpace(kv[1])
		}
		opts = append(opts, option{Key: key, Value: val})
	}
	return opts
}

// ParseHexContent handles Snort's mixed string and hex content (e.g. "HTTP/1.1|0D 0A|")
func ParseHexContent(content string) ([]byte, error) {
	var result []byte
	inHex := false
	var currentHex strings.Builder

	for i := 0; i < len(content); i++ {
		if content[i] == '|' {
			if inHex {
				hexStr := strings.ReplaceAll(currentHex.String(), " ", "")
				bytes, err := hex.DecodeString(hexStr)
				if err != nil {
					return nil, err
				}
				result = append(result, bytes...)
				currentHex.Reset()
			}
			inHex = !inHex
		} else {
			if inHex {
				currentHex.WriteByte(content[i])
			} else {
				result = append(result, content[i])
			}
		}
	}
	return result, nil
}
