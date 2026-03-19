package scanner

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Issue represents a detected vulnerability
type Issue struct {
	Rule    string
	Message string
}

// Workflow represents the structure of a GitHub Actions YAML
type Workflow struct {
	Name        string         `yaml:"name"`
	Permissions interface{}    `yaml:"permissions"` // Can be a string ("write-all") or a map
	Jobs        map[string]Job `yaml:"jobs"`
}

type Job struct {
	Permissions interface{} `yaml:"permissions"`
	Steps       []Step      `yaml:"steps"`
}

type Step struct {
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	Run  string `yaml:"run"`
}

// Helper to check for overly permissive tokens
func checkPermissions(perms interface{}, scope string) []Issue {
	var issues []Issue
	
	// Check if permissions is just "write-all"
	if pStr, ok := perms.(string); ok {
		if pStr == "write-all" {
			issues = append(issues, Issue{
				Rule:    "Overly Permissive Tokens",
				Message: scope + " has 'permissions: write-all'.\n   Risk: Compromised runner can overwrite code, releases, and packages.\n   Fix: Use principle of least privilege (e.g., 'contents: read').",
			})
		}
	} else if pMap, ok := perms.(map[string]interface{}); ok {
		// Check for specific dangerous granular permissions
		for k, v := range pMap {
			if v == "write" && (k == "contents" || k == "packages" || k == "security-events") {
				issues = append(issues, Issue{
					Rule:    "Dangerous Token Permission",
					Message: scope + " has 'permissions: " + k + ": write'.\n   Risk: Grants write access to critical repository components.\n   Fix: Ensure this workflow strictly requires write access.",
				})
			}
		}
	}
	return issues
}

// ScanFile parses the YAML and applies security rules
func ScanFile(filepath string) ([]Issue, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var workflow Workflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return nil, err
	}

	var issues []Issue

	// Rule 3: Global Permissions Check
	if workflow.Permissions != nil {
		issues = append(issues, checkPermissions(workflow.Permissions, "Global workflow")...)
	}

	// Regex for catching curl|wget piped into bash|sh
	curlBashRegex := regexp.MustCompile(`(?i)(curl|wget).*\|\s*(bash|sh)`)

	for jobName, job := range workflow.Jobs {
		// Rule 3b: Job-level Permissions Check
		if job.Permissions != nil {
			issues = append(issues, checkPermissions(job.Permissions, "Job '"+jobName+"'")...)
		}

		for _, step := range job.Steps {
			// Rule 1: Unpinned Dependency
			if step.Uses != "" {
				if strings.Contains(step.Uses, "@") {
					parts := strings.Split(step.Uses, "@")
					if len(parts) == 2 {
						version := parts[1]
						matched, _ := regexp.MatchString(`^[a-fA-F0-9]{40}$`, version)
						if !matched {
							issues = append(issues, Issue{
								Rule:    "Unpinned Action Dependency",
								Message: "Job '" + jobName + "' uses unpinned action '" + step.Uses + "'.\n   Risk: If the action owner is compromised, malicious code can be injected into your build.\n   Fix: Pin dependencies to a full 40-character commit SHA.",
							})
						}
					}
				}
			}

			if step.Run != "" {
				// Rule 2: Potential Command Injection via Context Variables
				untrustedContexts := []string{
					"github.event.issue.title",
					"github.event.issue.body",
					"github.event.pull_request.title",
					"github.event.pull_request.body",
					"github.head_ref",
				}
				for _, ctx := range untrustedContexts {
					if strings.Contains(step.Run, "${{") && strings.Contains(step.Run, ctx) {
						issues = append(issues, Issue{
							Rule:    "Command Injection Risk",
							Message: "Job '" + jobName + "' directly evaluates untrusted context '" + ctx + "' in a shell script.\n   Risk: An attacker can submit a malicious PR title to execute arbitrary code on your runner.\n   Fix: Pass the context via environment variables instead.",
						})
						break 
					}
				}

				// Rule 4: Dangerous Curl to Bash
				if curlBashRegex.MatchString(step.Run) {
					issues = append(issues, Issue{
						Rule:    "Remote Code Execution (Curl to Bash)",
						Message: "Job '" + jobName + "' downloads and executes a script directly via pipe.\n   Risk: If the remote server is compromised or MITM'd, you will execute malware.\n   Fix: Download the script, verify its SHA256 checksum, then execute it.",
					})
				}
			}
		}
	}

	return issues, nil
}
