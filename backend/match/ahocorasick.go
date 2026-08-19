package match

// MatchResult represents a single pattern match in the payload.
type MatchResult struct {
	PatternID int
	Index     int // Start index of the match in the payload
}

type node struct {
	children [256]*node
	fail     *node
	outputs  []int
}

// AhoCorasick implements a multi-pattern search engine.
type AhoCorasick struct {
	root     *node
	patterns [][]byte
	built    bool
}

// NewAhoCorasick creates a new multi-pattern search engine.
func NewAhoCorasick() *AhoCorasick {
	return &AhoCorasick{
		root: &node{},
	}
}

// AddPattern adds a byte pattern to the search engine.
// Returns an ID that can be used to identify the pattern in MatchResult.
func (ac *AhoCorasick) AddPattern(pattern []byte) int {
	if ac.built {
		panic("Cannot add pattern to built AhoCorasick")
	}
	id := len(ac.patterns)
	ac.patterns = append(ac.patterns, append([]byte(nil), pattern...)) // copy to prevent mutation

	curr := ac.root
	for _, b := range pattern {
		if curr.children[b] == nil {
			curr.children[b] = &node{}
		}
		curr = curr.children[b]
	}
	curr.outputs = append(curr.outputs, id)
	return id
}

// Build computes the failure transitions. Must be called before Search.
func (ac *AhoCorasick) Build() {
	if ac.built {
		return
	}
	queue := make([]*node, 0)

	// Initialize root's children
	for i := 0; i < 256; i++ {
		if ac.root.children[i] != nil {
			ac.root.children[i].fail = ac.root
			queue = append(queue, ac.root.children[i])
		}
	}

	// BFS to compute failure links
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for i := 0; i < 256; i++ {
			child := curr.children[i]
			if child != nil {
				failNode := curr.fail
				for failNode != nil && failNode.children[i] == nil {
					failNode = failNode.fail
				}
				if failNode == nil {
					child.fail = ac.root
				} else {
					child.fail = failNode.children[i]
				}

				// Merge output lists for dictionary matching
				if len(child.fail.outputs) > 0 {
					child.outputs = append(child.outputs, child.fail.outputs...)
				}
				queue = append(queue, child)
			}
		}
	}
	ac.built = true
}

// Search finds all occurrences of the added patterns in the payload.
// Returns a list of MatchResult, which includes the PatternID and start Index.
func (ac *AhoCorasick) Search(payload []byte) []MatchResult {
	if !ac.built {
		panic("AhoCorasick: Search called before Build")
	}

	var results []MatchResult
	curr := ac.root

	for i, b := range payload {
		for curr != nil && curr.children[b] == nil {
			curr = curr.fail
		}
		if curr == nil {
			curr = ac.root
		} else {
			curr = curr.children[b]
		}

		if len(curr.outputs) > 0 {
			for _, id := range curr.outputs {
				pattern := ac.patterns[id]
				startIndex := i - len(pattern) + 1
				results = append(results, MatchResult{
					PatternID: id,
					Index:     startIndex,
				})
			}
		}
	}
	return results
}
