package rules

import (
	"testing"
)

func TestMatcher(t *testing.T) {
	ruleStr := `alert tcp any any -> any any (msg:"Test Sticky"; content:"GET"; content:"/admin"; distance:0; within:10; pcre:"/admin[A-Z]/";)`
	rule, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	payload1 := []byte("GET /adminX HTTP/1.1")
	if !rule.Match(payload1) {
		t.Errorf("Expected Match for payload1")
	}

	payload2 := []byte("GET /user HTTP/1.1")
	if rule.Match(payload2) {
		t.Errorf("Expected NO Match for payload2")
	}
	
	// Fails within
	payload3 := []byte("GET                                     /adminX HTTP/1.1")
	if rule.Match(payload3) {
		t.Errorf("Expected NO Match for payload3 due to within")
	}
}
