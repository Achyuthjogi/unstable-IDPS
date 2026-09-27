package main

import (
	"fmt"
	"idps-backend/rules"
)

func main() {
	engine := rules.NewEngine()
	rules.LoadRulesFromDirectory("rules", engine)
	fmt.Printf("Engine loaded %d rules\n", len(engine.Rules))
}
