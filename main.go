package main

import (
	"encoding/json"
	"flag"
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

// Output format for JSON
type ScanReport struct {
	FilesScanned          int      `json:"files_scanned"`
	TotalVulnerabilities  int      `json:"total_vulnerabilities"`
	Results               []Result `json:"results"`
}

type Result struct {
	File   string          `json:"file"`
	Issues []scanner.Issue `json:"issues"`
}

func printSeverity(sev string) string {
	switch sev {
	case "CRITICAL":
		return "\033[1;31m[CRITICAL]\033[0m" // Bold Red
	case "HIGH":
		return "\033[31m[HIGH]\033[0m"     // Red
	case "MEDIUM":
		return "\033[33m[MEDIUM]\033[0m"   // Yellow
	case "LOW":
		return "\033[36m[LOW]\033[0m"      // Cyan
	default:
		return "[" + sev + "]"
	}
}

func main() {
	// Define flags
	outputFormat := flag.String("output", "text", "Output format (text, json)")
	flag.Parse()

	args := flag.Args()

	if len(args) < 1 {
		if *outputFormat == "text" {
			fmt.Println(banner)
			fmt.Println("Usage: forgeguard [options] <path_to_workflow.yml_or_directory>")
			fmt.Println("Options:")
			flag.PrintDefaults()
			fmt.Println("Example: forgeguard --output json .github/workflows/")
		}
		os.Exit(1)
	}

	targetPath := args[0]
	
	if *outputFormat == "text" {
		fmt.Println(banner)
		fmt.Printf("🔍 Scanning target: %s\n\n", targetPath)
	}

	fileInfo, err := os.Stat(targetPath)
	if err != nil {
		if *outputFormat == "text" {
			fmt.Printf("❌ Error accessing path: %v\n", err)
		}
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
			if *outputFormat == "text" {
				fmt.Printf("❌ Error walking directory: %v\n", err)
			}
			os.Exit(1)
		}
	} else {
		filesToScan = append(filesToScan, targetPath)
	}

	if len(filesToScan) == 0 {
		if *outputFormat == "text" {
			fmt.Println("❌ No YAML files found to scan.")
		} else {
			fmt.Println("{}")
		}
		os.Exit(1)
	}

	totalVulnerabilities := 0
	var jsonResults []Result

	for _, file := range filesToScan {
		issues, err := scanner.ScanFile(file)
		if err != nil {
			if *outputFormat == "text" {
				fmt.Printf("⚠️  Skipping %s (Error parsing YAML)\n", file)
			}
			continue
		}

		if len(issues) > 0 {
			totalVulnerabilities += len(issues)
			
			if *outputFormat == "json" {
				jsonResults = append(jsonResults, Result{
					File:   file,
					Issues: issues,
				})
			} else {
				fmt.Printf("🛑 Found %d vulnerabilities in: %s\n", len(issues), file)
				fmt.Println("------------------------------------------------")
				for i, res := range issues {
					fmt.Printf("%d. %s %s\n", i+1, printSeverity(res.Severity), res.Rule)
					fmt.Printf("   %s\n", res.Message)
					fmt.Println("------------------------------------------------")
				}
			}
		} else {
			if *outputFormat == "text" {
				fmt.Printf("✅ %s is secure.\n", file)
			}
		}
	}

	if *outputFormat == "json" {
		report := ScanReport{
			FilesScanned:         len(filesToScan),
			TotalVulnerabilities: totalVulnerabilities,
			Results:              jsonResults,
		}
		jsonBytes, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			fmt.Println(string(jsonBytes))
		}
	} else {
		fmt.Printf("\n📊 Scan Complete. Total files: %d | Total vulnerabilities found: %d\n", len(filesToScan), totalVulnerabilities)
		if totalVulnerabilities > 0 {
			os.Exit(1) // Return non-zero exit code if vulnerabilities found (useful for CI/CD)
		}
	}
}
