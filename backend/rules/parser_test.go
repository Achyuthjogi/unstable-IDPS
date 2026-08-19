package rules

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseRule(t *testing.T) {
	ruleStr := `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQL Injection"; flow:established,to_server; content:"SELECT"; nocase; content:"FROM"; distance:0; pcre:"/UNION/i"; classtype:web-application-attack; sid:1001; rev:1;)`

	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}
	if rule == nil {
		t.Fatalf("Rule is nil")
	}

	if rule.Action != ActionAlert {
		t.Errorf("Expected ActionAlert, got %v", rule.Action)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("Expected protocol tcp, got %v", rule.Protocol)
	}
	if rule.DstPort != "80" {
		t.Errorf("Expected dst port 80, got %v", rule.DstPort)
	}

	if rule.Msg != "SQL Injection" {
		t.Errorf("Expected msg 'SQL Injection', got '%v'", rule.Msg)
	}

	if rule.SID != 1001 {
		t.Errorf("Expected SID 1001, got %v", rule.SID)
	}

	if rule.FlowOpts["established"] != true || rule.FlowOpts["to_server"] != true {
		t.Errorf("Expected flow options established, to_server, got %v", rule.FlowOpts)
	}

	if len(rule.Contents) != 2 {
		t.Fatalf("Expected 2 contents, got %v", len(rule.Contents))
	}

	if !bytes.Equal(rule.Contents[0].Pattern, []byte("select")) {
		t.Errorf("Expected pattern 'select' (nocase), got '%s'", string(rule.Contents[0].Pattern))
	}
	if !rule.Contents[0].Modifier.Nocase {
		t.Error("Expected first content to be nocase")
	}

	if rule.Contents[1].Modifier.Distance != 0 {
		t.Errorf("Expected distance 0 for second content, got %v", rule.Contents[1].Modifier.Distance)
	}

	if rule.PCRE == nil {
		t.Fatal("Expected PCRE to be parsed")
	}
	if !rule.PCRE.MatchString("UnIoN") {
		t.Errorf("Expected PCRE to match 'UnIoN' (case insensitive)")
	}
}

func TestParseHexContent(t *testing.T) {
	str := "foo|41 42|bar|00|"
	res, err := ParseHexContent(str)
	if err != nil {
		t.Fatalf("Failed to parse hex content: %v", err)
	}
	expected := []byte{'f', 'o', 'o', 0x41, 0x42, 'b', 'a', 'r', 0x00}
	if !reflect.DeepEqual(res, expected) {
		t.Errorf("Expected %v, got %v", expected, res)
	}
}
