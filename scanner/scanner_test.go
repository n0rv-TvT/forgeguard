package scanner

import (
	"testing"
)

func TestScanData_CommandInjection(t *testing.T) {
	yamlData := []byte(`
name: Test
on: push
jobs:
  test:
    timeout-minutes: 10
    steps:
      - name: Inject
        run: echo "${{ github.event.issue.title }}"
`)

	issues, err := ScanData(yamlData)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	found := false
	for _, issue := range issues {
		if issue.Rule == "Command Injection Risk" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find Command Injection Risk, but didn't")
	}
}

func TestScanData_UnpinnedDependency(t *testing.T) {
	yamlData := []byte(`
name: Test
on: push
jobs:
  test:
    timeout-minutes: 10
    steps:
      - name: Checkout
        uses: actions/checkout@v3
`)

	issues, err := ScanData(yamlData)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	found := false
	for _, issue := range issues {
		if issue.Rule == "Unpinned Action Dependency" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find Unpinned Action Dependency, but didn't")
	}
}

func TestScanData_SecureWorkflow(t *testing.T) {
	yamlData := []byte(`
name: Secure
on: push
permissions:
  contents: read
jobs:
  test:
    timeout-minutes: 10
    steps:
      - name: Checkout
        uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - name: Safe run
        run: echo "Hello World"
`)

	issues, err := ScanData(yamlData)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(issues) > 0 {
		t.Errorf("Expected 0 issues for secure workflow, found %d: %v", len(issues), issues)
	}
}
