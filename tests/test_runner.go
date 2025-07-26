package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Test runner script for comprehensive testing
func main() {
	fmt.Println("🧪 Running AskFrank Test Suite")
	fmt.Println("================================")

	// Define test suites
	testSuites := []struct {
		name        string
		path        string
		description string
		tags        []string
	}{
		{
			name:        "Unit Tests",
			path:        "./tests/service/...",
			description: "Testing business logic and service layer",
			tags:        []string{"unit"},
		},
		{
			name:        "Validator Tests",
			path:        "./tests/validator/...",
			description: "Testing input validation logic",
			tags:        []string{"unit", "validator"},
		},
		{
			name:        "Integration Tests",
			path:        "./tests/integration/...",
			description: "Testing database and API integration",
			tags:        []string{"integration"},
		},
	}

	var failed bool

	// Run each test suite
	for _, suite := range testSuites {
		fmt.Printf("\n📋 %s\n", suite.name)
		fmt.Printf("   %s\n", suite.description)
		fmt.Printf("   Tags: %s\n", strings.Join(suite.tags, ", "))
		fmt.Println("   " + strings.Repeat("-", 50))

		// Run tests
		cmd := exec.Command("go", "test", "-v", "-race", "-coverprofile=coverage.out", suite.path)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("❌ %s failed: %v\n", suite.name, err)
			failed = true
		} else {
			fmt.Printf("✅ %s passed\n", suite.name)
		}
	}

	// Run coverage report
	fmt.Println("\n📊 Test Coverage Report")
	fmt.Println("========================")
	coverageCmd := exec.Command("go", "tool", "cover", "-func=coverage.out")
	coverageCmd.Stdout = os.Stdout
	coverageCmd.Stderr = os.Stderr
	coverageCmd.Run()

	// Summary
	fmt.Println("\n📋 Test Summary")
	fmt.Println("================")
	if failed {
		fmt.Println("❌ Some tests failed")
		os.Exit(1)
	} else {
		fmt.Println("✅ All tests passed!")
	}
}
