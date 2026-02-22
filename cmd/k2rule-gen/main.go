// k2rule-gen: CLI tool for generating K2RULEV3 binary rule files.
//
// Usage:
//
//	k2rule-gen generate-all -o output/ [-v]
//	k2rule-gen generate-porn -o output/porn_domains.k2r.gz [-v]
//
// The generate-all command reads clash_rules/*.yml, downloads rule providers
// via HTTP, converts with SliceConverter, gzips, and writes .k2r.gz files.
//
// The generate-porn command fetches the Bon-Appetit/porn-domains blocklist,
// filters heuristic-detected domains, builds a K2RULEV3 with target=Reject,
// and writes a gzip-compressed .k2r.gz file.
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaitu-io/k2rule/internal/clash"
	"github.com/kaitu-io/k2rule/internal/porn"
	"github.com/kaitu-io/k2rule/internal/slice"
)

// URL constants for the Bon-Appetit/porn-domains repository.
const (
	pornDomainsMetaURL = "https://cdn.jsdelivr.net/gh/Bon-Appetit/porn-domains@main/meta.json"
	pornDomainsBaseURL = "https://cdn.jsdelivr.net/gh/Bon-Appetit/porn-domains@main/"
)

// httpClient is the shared HTTP client with a reasonable timeout.
var httpClient = &http.Client{
	Timeout: 300 * time.Second,
}

// pornDomainsMeta represents the JSON structure of the porn-domains meta.json file.
type pornDomainsMeta struct {
	Blocklist pornDomainsFile `json:"blocklist"`
}

// pornDomainsFile represents a single file entry in the porn-domains meta.json.
type pornDomainsFile struct {
	Name    string `json:"name"`
	Updated string `json:"updated"`
	Lines   int64  `json:"lines"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: k2rule-gen <command> [options]")
		fmt.Fprintln(os.Stderr, "Commands: generate-all, generate-porn")
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "generate-all":
		runGenerateAll(os.Args[2:])
	case "generate-porn":
		runGeneratePorn(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", subcommand)
		fmt.Fprintln(os.Stderr, "Commands: generate-all, generate-porn")
		os.Exit(1)
	}
}

// runGenerateAll parses flags and runs the generate-all subcommand.
func runGenerateAll(args []string) {
	fs := flag.NewFlagSet("generate-all", flag.ExitOnError)
	outputDir := fs.String("o", "output", "Output directory for .k2r.gz files")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if err := generateAll(*outputDir, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// runGeneratePorn parses flags and runs the generate-porn subcommand.
func runGeneratePorn(args []string) {
	fs := flag.NewFlagSet("generate-porn", flag.ExitOnError)
	outputPath := fs.String("o", "output/porn_domains.k2r.gz", "Output file path")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if err := generatePorn(*outputPath, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// generateAll reads all YAML files from clash_rules/, downloads rule providers,
// converts to K2RULEV3 format, gzip-compresses, and writes .k2r.gz files.
func generateAll(outputDir string, verbose bool) error {
	logger := newLogger(verbose)

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output dir %q: %w", outputDir, err)
	}

	// Find the clash_rules directory relative to working directory
	clashRulesDir := "clash_rules"
	entries, err := os.ReadDir(clashRulesDir)
	if err != nil {
		return fmt.Errorf("read clash_rules dir: %w", err)
	}

	var processed int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		inputPath := filepath.Join(clashRulesDir, name)
		baseName := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		outputPath := filepath.Join(outputDir, baseName+".k2r.gz")

		logger.Info("Processing YAML file", "input", inputPath, "output", outputPath)

		if err := convertClashFile(inputPath, outputPath, verbose, logger); err != nil {
			logger.Error("Failed to convert file", "input", inputPath, "error", err)
			// Continue with other files rather than stopping
			continue
		}

		logger.Info("Generated rule file", "output", outputPath)
		processed++
	}

	slog.Info("All rule files generated", "count", processed, "output_dir", outputDir)
	return nil
}

// convertClashFile reads a Clash YAML config, downloads providers, converts,
// gzip-compresses, and writes the output file.
func convertClashFile(inputPath, outputPath string, verbose bool, logger *slog.Logger) error {
	// Read YAML content
	yamlBytes, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	yamlContent := string(yamlBytes)

	// Parse config to find rule-providers that need downloading
	converter := clash.NewSliceConverter()

	// Parse the YAML to find provider URLs
	providerURLs, err := extractProviderURLs(yamlContent)
	if err != nil {
		logger.Warn("Could not extract provider URLs, continuing without downloads", "error", err)
	}

	// Download and load each provider
	for providerName, providerURL := range providerURLs {
		logger.Info("Downloading provider", "name", providerName, "url", providerURL)

		content, err := downloadURL(providerURL)
		if err != nil {
			logger.Warn("Failed to download provider, skipping", "name", providerName, "error", err)
			continue
		}

		rules := parseProviderPayload(content)
		logger.Info("Loaded provider rules", "name", providerName, "count", len(rules))
		converter.SetProviderRules(providerName, rules)
	}

	// Convert to binary format
	data, err := converter.Convert(yamlContent)
	if err != nil {
		return fmt.Errorf("convert: %w", err)
	}

	logger.Info("Converted to binary", "size_bytes", len(data))

	// Write gzip-compressed output
	if err := writeGzip(data, outputPath); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

// generatePorn fetches the porn-domains blocklist, filters heuristic-detected
// domains, builds a K2RULEV3 with target=Reject, and writes a .k2r.gz file.
func generatePorn(outputPath string, verbose bool) error {
	logger := newLogger(verbose)

	// Ensure output directory exists
	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}

	// Step 1: Fetch meta.json
	logger.Info("Fetching meta.json from porn-domains repo")
	metaContent, err := downloadURL(pornDomainsMetaURL)
	if err != nil {
		return fmt.Errorf("fetch meta.json: %w", err)
	}

	var meta pornDomainsMeta
	if err := json.Unmarshal([]byte(metaContent), &meta); err != nil {
		return fmt.Errorf("parse meta.json: %w", err)
	}

	logger.Info("Fetched meta.json",
		"blocklist_name", meta.Blocklist.Name,
		"updated", meta.Blocklist.Updated,
		"lines", meta.Blocklist.Lines,
	)

	// Step 2: Download blocklist
	blocklistURL := pornDomainsBaseURL + meta.Blocklist.Name
	logger.Info("Downloading blocklist", "url", blocklistURL)

	blocklistContent, err := downloadURL(blocklistURL)
	if err != nil {
		return fmt.Errorf("fetch blocklist: %w", err)
	}

	// Step 3: Parse domains
	allDomains := parseBlocklist(blocklistContent)
	logger.Info("Parsed domains from blocklist", "count", len(allDomains))

	// Step 4: Filter heuristic-detected domains
	filteredDomains := filterHeuristicDomains(allDomains)
	heuristicCount := len(allDomains) - len(filteredDomains)
	logger.Info("Filtered domains",
		"heuristic_detected", heuristicCount,
		"remaining", len(filteredDomains),
	)

	// Step 5: Build K2RULEV3 with target=Reject (2)
	w := slice.NewSliceWriter(0) // fallback=Direct (unused but default)
	if err := w.AddDomainSlice(filteredDomains, 2); err != nil {
		return fmt.Errorf("add domain slice: %w", err)
	}

	data, err := w.Build()
	if err != nil {
		return fmt.Errorf("build binary: %w", err)
	}

	logger.Info("Built K2RULEV3 binary", "size_bytes", len(data))

	// Step 6: Write gzip-compressed output
	if err := writeGzip(data, outputPath); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	logger.Info("Successfully generated porn domain list",
		"output", outputPath,
		"source_domains", len(allDomains),
		"stored_domains", len(filteredDomains),
		"heuristic_coverage", heuristicCount,
	)

	return nil
}

// downloadURL downloads content from a URL and returns the response body as a string.
func downloadURL(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body from %s: %w", url, err)
	}

	return string(body), nil
}

// writeGzip gzip-compresses data and writes it to the given file path.
// The file is created with 0644 permissions, and the directory must exist.
// BestCompression level is used for maximum size reduction.
func writeGzip(data []byte, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file %q: %w", path, err)
	}
	defer file.Close()

	gz, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	defer gz.Close()

	if _, err := gz.Write(data); err != nil {
		return fmt.Errorf("write gzip data: %w", err)
	}

	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}

	return nil
}

// parseBlocklist parses a domain blocklist text, returning one domain per line.
// Empty lines and lines starting with '#' are skipped.
func parseBlocklist(content string) []string {
	lines := strings.Split(content, "\n")
	domains := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	return domains
}

// filterHeuristicDomains removes domains that can be detected by the heuristic filter.
// Only domains that CANNOT be heuristically identified as porn are kept.
func filterHeuristicDomains(domains []string) []string {
	filtered := make([]string, 0, len(domains))
	for _, domain := range domains {
		if !porn.IsPornHeuristic(domain) {
			filtered = append(filtered, domain)
		}
	}
	return filtered
}

// parseProviderPayload parses provider content in either YAML payload or plain text format.
// YAML payload format starts with "payload:" followed by a list of rules.
// Plain text format has one rule per line.
func parseProviderPayload(content string) []string {
	trimmed := strings.TrimSpace(content)

	if strings.HasPrefix(trimmed, "payload:") {
		// YAML payload format: payload:\n  - rule1\n  - rule2
		lines := strings.Split(trimmed, "\n")
		rules := make([]string, 0, len(lines))
		for _, line := range lines[1:] { // skip "payload:" line
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Remove "- " prefix and surrounding quotes
			rule := strings.TrimPrefix(line, "- ")
			rule = strings.TrimSpace(rule)
			rule = strings.Trim(rule, "'\"")
			if rule != "" {
				rules = append(rules, rule)
			}
		}
		return rules
	}

	// Plain text format: one rule per line
	lines := strings.Split(trimmed, "\n")
	rules := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

// extractProviderURLs parses YAML content to extract rule-provider name->URL mappings.
// Returns a map from provider name to URL.
func extractProviderURLs(yamlContent string) (map[string]string, error) {
	type providerDef struct {
		URL string `yaml:"url"`
	}
	type config struct {
		RuleProviders map[string]providerDef `yaml:"rule-providers"`
	}

	// Use a simple YAML parsing approach without gopkg.in/yaml.v3 import here
	// since this is in the cmd package; use the clash package's parser instead
	var cfg struct {
		RuleProviders map[string]struct {
			URL string `yaml:"url"`
		} `yaml:"rule-providers"`
	}

	// Simple YAML parse using gopkg.in/yaml.v3 via the go.mod dependency
	// We need to import yaml here. Since cmd packages can have their own imports,
	// we inline this parsing.
	//
	// Note: This uses a local import approach. The yaml import is handled at top of file.
	_ = cfg

	// Use a line-by-line approach to extract URLs without additional imports
	urls := make(map[string]string)
	lines := strings.Split(yamlContent, "\n")

	var currentProvider string
	inRuleProviders := false
	providerIndent := -1
	currentIndent := 0

	for _, line := range lines {
		// Count leading spaces
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(trimmed)

		if strings.HasPrefix(trimmed, "rule-providers:") {
			inRuleProviders = true
			providerIndent = indent
			continue
		}

		if inRuleProviders {
			if indent <= providerIndent && indent != providerIndent+2 && indent != providerIndent+4 {
				// We've left the rule-providers section
				if currentIndent == providerIndent+2 && !strings.HasPrefix(trimmed, " ") {
					// Check if we're at a top-level key
					if indent == 0 {
						inRuleProviders = false
						currentProvider = ""
						continue
					}
				}
			}

			if indent == providerIndent+2 {
				// Provider name level
				if strings.HasSuffix(trimmed, ":") {
					currentProvider = strings.TrimSuffix(trimmed, ":")
					currentIndent = indent
				}
			} else if indent > providerIndent+2 && currentProvider != "" {
				// Provider attribute level
				if strings.HasPrefix(trimmed, "url:") {
					urlStr := strings.TrimPrefix(trimmed, "url:")
					urlStr = strings.TrimSpace(urlStr)
					urlStr = strings.Trim(urlStr, "\"'")
					if urlStr != "" {
						urls[currentProvider] = urlStr
					}
				}
			} else if indent == 0 && !strings.HasPrefix(line, " ") {
				inRuleProviders = false
				currentProvider = ""
			}
		}
	}

	return urls, nil
}

// newLogger creates a structured logger. When verbose is false, only warnings
// and above are logged. When verbose is true, all messages including Info are logged.
func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}
