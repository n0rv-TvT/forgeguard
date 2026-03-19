package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"forgeguard/scanner"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: forgeguard <path_to_workflow.yml_or_directory>")
		fmt.Println("Example: forgeguard .github/workflows/")
		os.Exit(1)
	}

	targetPath := os.Args[1]
	fmt.Printf("🛡️  ForgeGuard - CI/CD Supply Chain Scanner\n")
	fmt.Printf("🔍 Scanning target: %s\n\n", targetPath)

	fileInfo, err := os.Stat(targetPath)
	if err != nil {
		fmt.Printf("❌ Error accessing path: %v\n", err)
		os.Exit(1)
	}

	var filesToScan []string

	if fileInfo.IsDir() {
		err := filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml")) {
				filesToScan = append(filesToScan, path)
			}
			return nil
		})
		if err != nil {
			fmt.Printf("❌ Error walking directory: %v\n", err)
			os.Exit(1)
		}
	} else {
		filesToScan = append(filesToScan, targetPath)
	}

	if len(filesToScan) == 0 {
		fmt.Println("❌ No YAML files found to scan.")
		os.Exit(1)
	}

	totalVulnerabilities := 0

	for _, file := range filesToScan {
		results, err := scanner.ScanFile(file)
		if err != nil {
			fmt.Printf("⚠️  Skipping %s (Error parsing YAML)\n", file)
			continue
		}

		if len(results) > 0 {
			fmt.Printf("🛑 Found %d vulnerabilities in: %s\n", len(results), file)
			fmt.Println("------------------------------------------------")
			for i, res := range results {
				fmt.Printf("%d. [%s]\n", i+1, res.Rule)
				fmt.Printf("   %s\n", res.Message)
				fmt.Println("------------------------------------------------")
			}
			totalVulnerabilities += len(results)
		} else {
			fmt.Printf("✅ %s is secure.\n", file)
		}
	}

	fmt.Printf("\n📊 Scan Complete. Total vulnerabilities found: %d\n", totalVulnerabilities)
}
