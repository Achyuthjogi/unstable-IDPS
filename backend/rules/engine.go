package rules

import (
	"idps-backend/match"
)

// Engine holds loaded rules and pattern matchers.
type Engine struct {
	Rules          []*Rule
	MPSE           *match.AhoCorasick
	NocaseMPSE     *match.AhoCorasick
	
	patternToRules map[int][]int // patternID -> rule indices
	nocaseToRules  map[int][]int // patternID -> rule indices
	NoContentRules []int         // rule indices without content
}

// NewEngine creates a new rule engine.
func NewEngine() *Engine {
	return &Engine{
		MPSE:           match.NewAhoCorasick(),
		NocaseMPSE:     match.NewAhoCorasick(),
		patternToRules: make(map[int][]int),
		nocaseToRules:  make(map[int][]int),
	}
}

// AddRule adds a parsed rule to the engine.
func (e *Engine) AddRule(r *Rule) {
	ruleIdx := len(e.Rules)
	e.Rules = append(e.Rules, r)

	// Select the "fast pattern" (we just use the first content for simplicity)
	if len(r.Contents) > 0 {
		firstContent := r.Contents[0]
		if firstContent.Modifier.Nocase {
			pid := e.NocaseMPSE.AddPattern(firstContent.Pattern)
			e.nocaseToRules[pid] = append(e.nocaseToRules[pid], ruleIdx)
		} else {
			pid := e.MPSE.AddPattern(firstContent.Pattern)
			e.patternToRules[pid] = append(e.patternToRules[pid], ruleIdx)
		}
	} else {
		e.NoContentRules = append(e.NoContentRules, ruleIdx)
	}
}

// Build compiles the MPSEs. Must be called before matching.
func (e *Engine) Build() {
	e.MPSE.Build()
	e.NocaseMPSE.Build()
}

// Match evaluates all rules against a payload and returns the matched rules.
func (e *Engine) Match(payload []byte) []*Rule {
	var matchedRules []*Rule
	evaluated := make(map[int]bool)

	// Fast pattern match - Case sensitive
	results := e.MPSE.Search(payload)
	for _, res := range results {
		for _, ruleIdx := range e.patternToRules[res.PatternID] {
			if !evaluated[ruleIdx] {
				evaluated[ruleIdx] = true
				if e.Rules[ruleIdx].Match(payload) {
					matchedRules = append(matchedRules, e.Rules[ruleIdx])
				}
			}
		}
	}

	// Fast pattern match - Case insensitive
	if len(payload) > 0 {
		lowerPayload := make([]byte, len(payload))
		for i, b := range payload {
			if b >= 'A' && b <= 'Z' {
				lowerPayload[i] = b + 32
			} else {
				lowerPayload[i] = b
			}
		}
		
		resultsNocase := e.NocaseMPSE.Search(lowerPayload)
		for _, res := range resultsNocase {
			for _, ruleIdx := range e.nocaseToRules[res.PatternID] {
				if !evaluated[ruleIdx] {
					evaluated[ruleIdx] = true
					if e.Rules[ruleIdx].Match(payload) {
						matchedRules = append(matchedRules, e.Rules[ruleIdx])
					}
				}
			}
		}
	}

	// Evaluate rules without content
	for _, ruleIdx := range e.NoContentRules {
		if !evaluated[ruleIdx] {
			evaluated[ruleIdx] = true
			if e.Rules[ruleIdx].Match(payload) {
				matchedRules = append(matchedRules, e.Rules[ruleIdx])
			}
		}
	}

	return matchedRules
}
