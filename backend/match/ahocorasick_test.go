package match

import (
	"reflect"
	"sort"
	"testing"
)

func TestAhoCorasickSearch(t *testing.T) {
	ac := NewAhoCorasick()
	
	idHe := ac.AddPattern([]byte("he"))
	idShe := ac.AddPattern([]byte("she"))
	ac.AddPattern([]byte("his"))
	idHers := ac.AddPattern([]byte("hers"))

	ac.Build()

	payload := []byte("ushers")
	results := ac.Search(payload)

	// Expected matches in "ushers":
	// "she" at index 1
	// "he" at index 2
	// "hers" at index 2
	expected := []MatchResult{
		{PatternID: idShe, Index: 1},
		{PatternID: idHe, Index: 2},
		{PatternID: idHers, Index: 2},
	}

	// Sort results by Index then PatternID to ensure stable comparison
	sort.Slice(results, func(i, j int) bool {
		if results[i].Index == results[j].Index {
			return results[i].PatternID < results[j].PatternID
		}
		return results[i].Index < results[j].Index
	})
	
	sort.Slice(expected, func(i, j int) bool {
		if expected[i].Index == expected[j].Index {
			return expected[i].PatternID < expected[j].PatternID
		}
		return expected[i].Index < expected[j].Index
	})

	if !reflect.DeepEqual(results, expected) {
		t.Errorf("Expected %v, got %v", expected, results)
	}
}

func BenchmarkAhoCorasick(b *testing.B) {
	ac := NewAhoCorasick()
	ac.AddPattern([]byte("SELECT"))
	ac.AddPattern([]byte("DROP TABLE"))
	ac.AddPattern([]byte("UNION ALL"))
	ac.AddPattern([]byte("AND 1=1"))
	ac.AddPattern([]byte("<script>"))
	ac.AddPattern([]byte("/etc/passwd"))
	ac.Build()

	payload := make([]byte, 1024)
	copy(payload[500:], []byte("... <script> alert(1); </script> ..."))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.Search(payload)
	}
}
