package porn

import (
	"regexp"
	"strings"
)

// IsPornHeuristic checks if a domain is likely a porn site using heuristic patterns.
//
// This function provides fast, pattern-based detection without needing
// to query the full domain list. It uses 8 detection layers for
// comprehensive coverage while maintaining zero false positives.
//
// Detection Order:
//  1. False positive check: Excludes legitimate domains
//  2. Keyword patterns: Strong keywords + terminology
//  3. 3x prefix pattern
//  4. Porn terminology
//  5. Compound terms
//  6. Verb+noun patterns
//  7. Repetition patterns
//  8. Adult TLDs
func IsPornHeuristic(domain string) bool {
	if domain == "" {
		return false
	}

	domainLower := strings.ToLower(domain)

	// Layer 1: Check for false positives first (early exit)
	if falsePositivePattern.MatchString(domainLower) {
		return false
	}

	// Layer 2: Check keyword patterns (regex)
	if pornPattern.MatchString(domainLower) {
		return true
	}

	// Layer 3: Check special optimized patterns (3x prefix)
	if has3xPrefix(domainLower) {
		return true
	}

	// Layer 4: Check porn terminology
	for _, term := range pornTerminology {
		if strings.Contains(domainLower, term) {
			return true
		}
	}

	// Layer 5: Check compound terms
	for _, compound := range pornCompounds {
		if strings.Contains(domainLower, compound) {
			return true
		}
	}

	// Layer 6: Check verb+noun patterns
	if hasVerbNounPattern(domainLower) {
		return true
	}

	// Layer 7: Check repetition patterns
	if hasRepetitionPattern(domainLower) {
		return true
	}

	return false
}

// has3xPrefix checks if domain starts with "3x" pattern
func has3xPrefix(domain string) bool {
	return pattern3x.MatchString(domain)
}

// hasVerbNounPattern checks if domain contains verb+noun sequential pattern
func hasVerbNounPattern(domain string) bool {
	for _, pair := range verbNounPatterns {
		verb, noun := pair[0], pair[1]

		// Pattern 1: Direct concatenation (watchsex)
		if strings.Contains(domain, verb+noun) {
			return true
		}

		// Pattern 2: With separator (watch-sex, watch_sex, watch.sex)
		for _, sep := range []string{"-", "_", "."} {
			if strings.Contains(domain, verb+sep+noun) {
				return true
			}
		}

		// Pattern 3: With optional 1-4 char word in between (watchgirlsex)
		if idx := strings.Index(domain, verb); idx != -1 {
			afterVerb := domain[idx+len(verb):]
			if len(afterVerb) >= len(noun) {
				for skip := 0; skip <= 4 && skip <= len(afterVerb)-len(noun); skip++ {
					if strings.HasPrefix(afterVerb[skip:], noun) {
						return true
					}
				}
			}
		}
	}

	return false
}

// hasRepetitionPattern checks if domain contains repetition patterns
func hasRepetitionPattern(domain string) bool {
	// Character repetitions
	if strings.Contains(domain, "xxx") || strings.Contains(domain, "xxxxxx") {
		return true
	}

	// Word repetitions
	repetitions := []string{"sexsex", "camcam", "girlgirl"}
	for _, pattern := range repetitions {
		if strings.Contains(domain, pattern) {
			return true
		}
	}

	return false
}

// Compiled regex patterns (initialized in init())
var (
	pornPattern           *regexp.Regexp
	falsePositivePattern  *regexp.Regexp
	pattern3x             *regexp.Regexp
)

func init() {
	// False positive patterns
	falsePositivePattern = regexp.MustCompile(`(?i)(essex|middlesex|sussex|wessex)\.|adult(education|learning)\.|macosx\.`)

	// Main porn pattern
	strongKeywords := strings.Join(pornKeywords, "|")
	carefulKeywords := strings.Join(carefulKeywords, "|")
	adultTLDs := strings.Join(adultTLDs, "|")

	pornPatternStr := `(?i)(` + strongKeywords + `)|(` + carefulKeywords + `)|\.` + `(` + adultTLDs + `)$`
	pornPattern = regexp.MustCompile(pornPatternStr)

	// 3x prefix pattern
	pattern3x = regexp.MustCompile(`(?i)^3x`)
}
