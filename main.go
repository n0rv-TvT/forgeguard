package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"forgeguard/scanner"
)

const banner = `
  _____                    _____                     _ 
 |  ___|__  _ __ __ _  ___|  __ \ _   _  __ _ _ __  | |
 | |_ / _ \| '__/ _` + "`" + ` |/ _ \ |  \/| | | |/ _` + "`" + ` | '__| | |
 |  _| (_) | | | (_| |  __/ |__| | |_| | (_| | |    |_|
 |_|  \___/|_|  \__, |\___|_____/ \__,_|\__,_|_|    (_)
                |___/                                  
    CI/CD Supply Chain Security Scanner v1.0
`

func main() {
	if len(os.Args) < 2 {
		fmt.Println(banner)
		fmt.Println("Usage: forgeguard <path_to_workflow.yml_or_directory>")
		fmt.Println("Example: forgeguard .github/workflows/")
		os.Exit(1)
	}

	targetPath := os.Args[1]
	fmt.Println(banner)
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

	fmt.Printf("\n📊 Scan Complete. Total files: %d | Total vulnerabilities found: %d\n", len(filesToScan), totalVulnerabilities)
}
