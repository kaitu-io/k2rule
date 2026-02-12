package main

import (
	"fmt"
	"log"

	"github.com/kaitu-io/k2rule"
)

func main() {
	// Example 1: Config-based initialization (v1.0.0+)
	fmt.Println("=== Example 1: Unified Config Initialization ===")

	config := &k2rule.Config{
		RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
		GeoIPURL: "", // Default MaxMind
		PornURL:  "", // Default CDN
		CacheDir: "", // Default ~/.cache/k2rule/
		IsGlobal: false,
	}

	err := k2rule.Init(config)
	if err != nil {
		log.Fatalf("Init failed: %v", err)
	}
	fmt.Println("✓ K2Rule initialized")

	// Example 2: Matching with automatic LAN bypass
	fmt.Println("\n=== Example 2: Matching with LAN Bypass ===")

	testInputs := []string{
		"google.com",            // Domain
		"192.168.1.1",           // LAN IPv4 → DIRECT
		"10.0.0.1",              // LAN IPv4 → DIRECT
		"8.8.8.8",               // Public IPv4
		"::1",                   // LAN IPv6 → DIRECT
		"2001:4860:4860::8888",  // Public IPv6
	}

	for _, input := range testInputs {
		target := k2rule.Match(input)
		lanStatus := ""
		if k2rule.IsPrivateIP(input) {
			lanStatus = " [LAN]"
		}
		fmt.Printf("  %-25s → %s%s\n", input, target, lanStatus)
	}

	// Example 3: Global proxy mode toggle
	fmt.Println("\n=== Example 3: Global Mode Toggle ===")

	fmt.Println("Rule-based mode:")
	k2rule.ToggleGlobal(false)
	fmt.Printf("  google.com → %s\n", k2rule.Match("google.com"))

	fmt.Println("\nGlobal proxy mode:")
	k2rule.ToggleGlobal(true)
	fmt.Printf("  google.com → %s\n", k2rule.Match("google.com"))
	fmt.Printf("  192.168.1.1 → %s (LAN bypass)\n", k2rule.Match("192.168.1.1"))

	// Switch back to rule-based mode for remaining examples
	k2rule.ToggleGlobal(false)

	// Example 4: Get current config
	fmt.Println("\n=== Example 4: Get Current Config ===")

	currentConfig := k2rule.GetConfig()
	fmt.Printf("  Global mode: %v\n", currentConfig.IsGlobal)
	fmt.Printf("  Global target: %s\n", currentConfig.GlobalTarget)
	fmt.Printf("  Cache dir: %s\n", currentConfig.CacheDir)

	// Example 5: Porn detection
	fmt.Println("\n=== Example 5: Porn Detection ===")

	pornTests := []string{
		"pornhub.com",
		"google.com",
		"xvideos.com",
		"example.xxx",
	}

	for _, domain := range pornTests {
		isPorn := k2rule.IsPorn(domain)
		status := "Clean"
		if isPorn {
			status = "PORN"
		}
		fmt.Printf("  %-20s → %s\n", domain, status)
	}

	// Example 6: Pure Global Mode (no rules)
	fmt.Println("\n=== Example 6: Pure Global Mode (VPN-style) ===")

	globalConfig := &k2rule.Config{
		IsGlobal:     true,
		GlobalTarget: k2rule.TargetProxy,
	}

	err = k2rule.Init(globalConfig)
	if err != nil {
		log.Printf("Warning: failed to init global mode: %v", err)
	} else {
		fmt.Println("✓ Global mode initialized (no rules)")
		fmt.Printf("  anything.com → %s\n", k2rule.Match("anything.com"))
		fmt.Printf("  10.0.0.1 → %s (LAN bypass)\n", k2rule.Match("10.0.0.1"))
	}
}
