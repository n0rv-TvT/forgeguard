package scanner

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// GitlabJob represents a job in a .gitlab-ci.yml file
type GitlabJob struct {
	Image  string   `yaml:"image"`
	Script []string `yaml:"script"`
	Before []string `yaml:"before_script"`
	After  []string `yaml:"after_script"`
}

// ScanGitlabFile reads and parses a GitLab CI file
func ScanGitlabFile(filepath string) ([]Issue, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return ScanGitlabData(data)
}

// ScanGitlabData applies security rules to GitLab CI YAML
func ScanGitlabData(data []byte) ([]Issue, error) {
	// GitLab CI YAML structure is very dynamic. Jobs can be top-level keys.
	// We'll unmarshal into a generic map to handle this structure.
	var gitlabCI map[string]interface{}
	if err := yaml.Unmarshal(data, &gitlabCI); err != nil {
		return nil, err
	}

	var issues []Issue

	// Regex for secrets (AWS Keys, Passwords, etc) - Shared with GitHub Scanner
	awsKeyRegex := regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	passwordRegex := regexp.MustCompile(`(?i)(password|passwd|secret|token|api_key)\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{8,}['"]?`)
	curlBashRegex := regexp.MustCompile(`(?i)(curl|wget).*\|\s*(bash|sh)`)

	contentStr := string(data)
	
	// Rule: Hardcoded Secrets globally in file
	if awsKeyRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Hardcoded AWS Key",
			Severity: "CRITICAL",
			Message:  "Found a hardcoded AWS Access Key (AKIA...) in the GitLab workflow file.\n   Risk: Anyone who can read this repo can compromise your AWS environment.\n   Fix: Move this to GitLab CI/CD Variables.",
		})
	}
	if passwordRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Potential Hardcoded Secret",
			Severity: "HIGH",
			Message:  "Found a potential hardcoded password/token/secret in the GitLab workflow file.\n   Risk: Hardcoding secrets leads to accidental leaks and credential theft.\n   Fix: Move this to GitLab CI/CD Variables.",
		})
	}

	// Iterate through the generic map to find job definitions
	for key, value := range gitlabCI {
		// Ignore reserved GitLab keywords like stages, variables, include, etc.
		if key == "stages" || key == "variables" || key == "include" || key == "default" || key == "workflow" || key == "cache" {
			continue
		}

		// Try to parse the value as a job map
		jobMap, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for specific security issues in the job's scripts
		checkScripts := func(scriptInterface interface{}, scriptType string) {
			if scriptInterface == nil {
				return
			}
			
			// Scripts can be a single string or a list of strings in GitLab
			var scripts []string
			if sList, ok := scriptInterface.([]interface{}); ok {
				for _, s := range sList {
					if str, ok := s.(string); ok {
						scripts = append(scripts, str)
					} else {
						// Fallback: marshal the map/complex type back to string for regex scanning
						yamlBytes, err := yaml.Marshal(s)
						if err == nil {
							scripts = append(scripts, string(yamlBytes))
						}
					}
				}
			} else if sStr, ok := scriptInterface.(string); ok {
				scripts = append(scripts, sStr)
			}

			for _, scriptLine := range scripts {
				// Rule: Dangerous Curl to Bash
				if curlBashRegex.MatchString(scriptLine) {
					issues = append(issues, Issue{
						Rule:     "Remote Code Execution (Curl to Bash)",
						Severity: "HIGH",
						Message:  "Job '" + key + "' downloads and executes a script directly via pipe in " + scriptType + ".\n   Risk: If the remote server is compromised or MITM'd, you will execute malware.\n   Fix: Download the script, verify its SHA256 checksum, then execute it.",
					})
				}

				// Rule: Potential Command Injection via GitLab Predefined Variables
				// e.g., CI_COMMIT_MESSAGE, CI_MERGE_REQUEST_TITLE can be manipulated by users
				untrustedVars := []string{
					"$CI_COMMIT_MESSAGE",
					"${CI_COMMIT_MESSAGE}",
					"$CI_MERGE_REQUEST_TITLE",
					"${CI_MERGE_REQUEST_TITLE}",
				}
				for _, untrustedVar := range untrustedVars {
					if strings.Contains(scriptLine, untrustedVar) {
						// Simple heuristic: if it's evaluated inside the script line directly
						issues = append(issues, Issue{
							Rule:     "Command Injection Risk",
							Severity: "CRITICAL",
							Message:  "Job '" + key + "' evaluates untrusted variable '" + untrustedVar + "' directly in a shell script.\n   Risk: An attacker can submit a malicious commit message or MR title to execute arbitrary code.\n   Fix: Pass the variable safely to a script file rather than executing it inline.",
						})
						break
					}
				}
			}
		}

		// Check script, before_script, after_script blocks
		checkScripts(jobMap["script"], "script")
		checkScripts(jobMap["before_script"], "before_script")
		checkScripts(jobMap["after_script"], "after_script")

		// Rule: Unpinned Docker Image
		if image, ok := jobMap["image"].(string); ok {
			if image != "" && !strings.Contains(image, "@sha256:") {
				if strings.Contains(image, ":latest") || !strings.Contains(image, ":") {
					issues = append(issues, Issue{
						Rule:     "Unpinned Docker Image",
						Severity: "MEDIUM",
						Message:  "Job '" + key + "' uses an unpinned Docker image '" + image + "'.\n   Risk: The underlying image can change unexpectedly, introducing vulnerabilities or breaking builds.\n   Fix: Pin the image to a specific SHA256 hash.",
					})
				}
			}
		}
	}

	return issues, nil
}
