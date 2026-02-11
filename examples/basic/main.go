package main

import (
	"fmt"
	"log"

	"github.com/kaitu-io/k2rule"
)

func main() {
	// Example 0: Remote initialization (recommended - out of the box!)
	fmt.Println("=== Example 0: Remote initialization (auto-download) ===")
	remoteURL := "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz"
	// Use "" for default cache directory (~/.cache/k2rule/)
	// For iOS: use "/path/to/Library/Caches/k2rule" to prevent iCloud sync
	// Fallback target is automatically read from the .k2r file header
	err := k2rule.InitRemote(remoteURL, "")
	if err != nil {
		log.Printf("Warning: failed to init from remote: %v", err)

		// Fallback to local file if remote fails
		fmt.Println("\n=== Example 1: Loading from local k2r file (fallback) ===")
		err = k2rule.InitFromFile("../../output/cn_blacklist.k2r.gz")
		if err != nil {
			log.Printf("Warning: failed to load k2r file: %v (this is expected if file doesn't exist)", err)
		}
	}

	if err == nil {
		// Match domains
		testDomains := []string{
			"google.com",
			"baidu.com",
			"youtube.com",
			"qq.com",
		}

		fmt.Println("\nDomain matching results:")
		for _, domain := range testDomains {
			target := k2rule.MatchDomain(domain)
			fmt.Printf("  %s -> %s\n", domain, target)
		}

		// Match IPs
		testIPs := []string{
			"8.8.8.8",
			"114.114.114.114",
		}

		fmt.Println("\nIP matching results:")
		for _, ip := range testIPs {
			target := k2rule.Match(ip)
			fmt.Printf("  %s -> %s\n", ip, target)
		}
	}

	// Example 2: Porn detection (heuristic)
	fmt.Println("\n=== Example 2: Porn detection (heuristic) ===")

	pornDomains := []string{
		"pornhub.com",
		"xvideos.com",
		"google.com",
		"freeporn.net",
		"example.xxx",
		"microsoft.com",
	}

	fmt.Println("\nHeuristic porn detection:")
	for _, domain := range pornDomains {
		isPorn := k2rule.IsPornHeuristic(domain)
		status := "✓ PORN"
		if !isPorn {
			status = "✗ Clean"
		}
		fmt.Printf("  %s: %s\n", domain, status)
	}

	// Example 3: Automatic type detection
	fmt.Println("\n=== Example 3: Automatic type detection ===")

	testInputs := []string{
		"google.com",
		"192.168.1.1",
		"baidu.com",
		"8.8.8.8",
	}

	fmt.Println("\nAuto-detecting and matching:")
	for _, input := range testInputs {
		var inputType string
		if k2rule.IsIPAddress(input) {
			inputType = "IP"
		} else if k2rule.IsDomain(input) {
			inputType = "Domain"
		} else {
			inputType = "Unknown"
		}
		fmt.Printf("  %s (%s)\n", input, inputType)
	}

	// Example 4: Target enum usage
	fmt.Println("\n=== Example 4: Target enum usage ===")

	targets := []k2rule.Target{
		k2rule.TargetDirect,
		k2rule.TargetProxy,
		k2rule.TargetReject,
	}

	fmt.Println("\nTarget values:")
	for _, target := range targets {
		fmt.Printf("  %s (value: %d)\n", target, target)
	}

	// Parse target from string
	if target, err := k2rule.ParseTarget("proxy"); err == nil {
		fmt.Printf("\nParsed 'proxy' to: %s\n", target)
	}
}
