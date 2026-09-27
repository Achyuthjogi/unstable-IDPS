package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	file, err := os.Open("rules/community.rules")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	valid, invalid, empty := 0, 0, 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			empty++
			continue
		}
		parts := strings.SplitN(line, "(", 2)
		if len(parts) != 2 {
			invalid++
			continue
		}
		header := strings.Fields(strings.TrimSpace(parts[0]))
		if len(header) != 7 {
			invalid++
			continue
		}
		valid++
	}
	fmt.Printf("Valid headers: %d, Invalid: %d, Empty/Comments: %d\n", valid, invalid, empty)
}
