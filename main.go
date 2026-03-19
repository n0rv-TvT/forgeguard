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

// Version is injected at build time using -ldflags
var Version = "dev"

func getBanner() string {
	return `
  _____                    _____                     _ 
 |  ___|__  _ __ __ _  ___|  __ \ _   _  __ _ _ __  | |
 | |_ / _ \| '__/ _` + "`" + ` |/ _ \ |  \/| | | |/ _` + "`" + ` | '__| | |
 |  _| (_) | | | (_| |  __/ |__| | |_| | (_| | |    |_|
 |_|  \___/|_|  \__, |\___|_____/ \__,_|\__,_|_|    (_)
                |___/                                  
    CI/CD Supply Chain Security Scanner v` + Version + `
`
}

// Output format for JSON
type ScanReport struct {
	FilesScanned         int      `json:"files_scanned"`
	TotalVulnerabilities int      `json:"total_vulnerabilities"`
	Results              []Result `json:"results"`
}

type Result struct {
	File   string          `json:"file"`
	Type   string          `json:"type"` // GitHub or GitLab
	Issues []scanner.Issue `json:"issues"`
}

func printSeverity(sev string) string {
	switch sev {
	case "CRITICAL":
		return "\033[1;31m[CRITICAL]\033[0m" // Bold Red
	case "HIGH":
		return "\033[31m[HIGH]\033[0m" // Red
	case "MEDIUM":
		return "\033[33m[MEDIUM]\033[0m" // Yellow
	case "LOW":
		return "\033[36m[LOW]\033[0m" // Cyan
	default:
		return "[" + sev + "]"
	}
}

func printUsage() {
	fmt.Print(getBanner())
	fmt.Println("Usage: forgeguard <command> [options] <target>")
	fmt.Println("\nCommands:")
	fmt.Println("  scan      Scan a CI/CD configuration file or directory")
	fmt.Println("  monitor   Monitor a directory for CI/CD configuration changes (coming soon)")
	fmt.Println("  version   Print version information")
	fmt.Println("  help      Show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  forgeguard scan .github/workflows/")
	fmt.Println("  forgeguard scan -output json .gitlab-ci.yml")
}

func run() int {
	if len(os.Args) < 2 {
		printUsage()
		return 1
	}

	command := os.Args[1]

	switch command {
	case "scan":
		return runScan(os.Args[2:])
	case "monitor":
		fmt.Println("🚀 The 'monitor' command is under development! Stay tuned for real-time CI/CD protection.")
		return 0
	case "version", "--version", "-v":
		fmt.Printf("ForgeGuard v%s\n", Version)
		return 0
	case "help", "--help", "-h":
		printUsage()
		return 0
	default:
		// Check if it's a legacy invocation (e.g. `forgeguard .github/workflows/`)
		if !strings.HasPrefix(command, "-") {
			fmt.Printf("⚠️  Warning: Implicit 'scan' command is deprecated. Please use 'forgeguard scan %s'\n\n", strings.Join(os.Args[1:], " "))
			return runScan(os.Args[1:])
		}

		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		return 1
	}
}

func runScan(args []string) int {
	scanCmd := flag.NewFlagSet("scan", flag.ContinueOnError)
	outputFormat := scanCmd.String("output", "text", "Output format (text, json)")

	err := scanCmd.Parse(args)
	if err != nil {
		return 1
	}

	if scanCmd.NArg() < 1 {
		if *outputFormat == "text" {
			fmt.Println("Usage: forgeguard scan [options] <path_to_workflow.yml_or_directory>")
			scanCmd.PrintDefaults()
		}
		return 1
	}

	targetPath := scanCmd.Arg(0)

	if *outputFormat == "text" {
		fmt.Print(getBanner())
		fmt.Printf("🔍 Scanning target: %s\n\n", targetPath)
	}

	fileInfo, err := os.Stat(targetPath)
	if err != nil {
		if *outputFormat == "text" {
			fmt.Printf("❌ Error accessing path: %v\n", err)
		}
		return 1
	}

	var filesToScan []string

	if fileInfo.IsDir() {
		err := filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Only look for YAML files
			if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml")) {
				filesToScan = append(filesToScan, path)
			}
			return nil
		})
		if err != nil {
			if *outputFormat == "text" {
				fmt.Printf("❌ Error walking directory: %v\n", err)
			}
			return 1
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
		return 1
	}

	totalVulnerabilities := 0
	var jsonResults []Result

	for _, file := range filesToScan {
		var issues []scanner.Issue
		var scanErr error
		var ciType string

		// Auto-detect based on filename or path
		fileName := filepath.Base(file)
		if fileName == ".gitlab-ci.yml" || fileName == "test-gitlab-ci.yml" || strings.Contains(file, ".gitlab") {
			issues, scanErr = scanner.ScanGitlabFile(file)
			ciType = "GitLab"
		} else {
			// Default to GitHub Actions
			issues, scanErr = scanner.ScanFile(file)
			ciType = "GitHub"
		}

		if scanErr != nil {
			if *outputFormat == "text" {
				fmt.Printf("⚠️  Skipping %s (Error parsing YAML: %v)\n", file, scanErr)
			}
			continue
		}

		if len(issues) > 0 {
			totalVulnerabilities += len(issues)

			if *outputFormat == "json" {
				jsonResults = append(jsonResults, Result{
					File:   file,
					Type:   ciType,
					Issues: issues,
				})
			} else {
				fmt.Printf("🛑 Found %d vulnerabilities in [%s CI]: %s\n", len(issues), ciType, file)
				fmt.Println("------------------------------------------------")
				for i, res := range issues {
					fmt.Printf("%d. %s %s\n", i+1, printSeverity(res.Severity), res.Rule)
					fmt.Printf("   %s\n", res.Message)
					fmt.Println("------------------------------------------------")
				}
			}
		} else {
			if *outputFormat == "text" {
				fmt.Printf("✅ %s ([%s CI]) is secure.\n", file, ciType)
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
	}

	if totalVulnerabilities > 0 {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run())
}
