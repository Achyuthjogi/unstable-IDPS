package rules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
)

// LoadRulesFromDirectory loads all .rules files from a directory into the engine.
func LoadRulesFromDirectory(dir string, engine *Engine) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	loaded := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".rules" {
			path := filepath.Join(dir, entry.Name())
			file, err := os.Open(path)
			if err != nil {
				fmt.Printf("Warning: failed to open rule file %s: %v\n", path, err)
				continue
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				rule, err := ParseRule(line)
				if err != nil {
					fmt.Printf("Warning: failed to parse rule: %v\n", err)
					continue
				}
				if rule != nil {
					engine.AddRule(rule)
					loaded++
				}
			}
			file.Close()
		}
	}

	fmt.Printf("Loaded %d rules from %s\n", loaded, dir)
	return nil
}
