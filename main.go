package main

import (
	"fmt"
	"os"

	"forgeguard/scanner"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: forgeguard <path_to_workflow.yml>")
		fmt.Println("Example: forgeguard test-workflow.yml")
		os.Exit(1)
	}
	
	targetFile := os.Args[1]
	fmt.Printf("🛡️  ForgeGuard - CI/CD Supply Chain Scanner\n")
	fmt.Printf("🔍 Scanning %s...\n\n", targetFile)

	results, err := scanner.ScanFile(targetFile)
	if err != nil {
		fmt.Printf("❌ Error scanning file: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Println("✅ Secure! No supply chain vulnerabilities found.")
		return
	}

	fmt.Printf("⚠️  Found %d potential vulnerabilities:\n", len(results))
	fmt.Println("------------------------------------------------")
	for i, res := range results {
		fmt.Printf("%d. [%s]\n", i+1, res.Rule)
		fmt.Printf("   %s\n", res.Message)
		fmt.Println("------------------------------------------------")
	}
}
