#!/usr/bin/env python3
"""
Analyze verb+noun sequential patterns in porn domains.

Goal: Find patterns like "watch" + "sex" that appear sequentially in domains:
- watchsex.com
- watch-sex.com
- watchgirlsex.com

These combinations are HIGHLY specific and have near-zero false positive rate.
"""

import re
from collections import Counter, defaultdict
from typing import List, Set, Tuple, Dict


def load_domains(file_path="/tmp/porn_domains.txt") -> List[str]:
    """Load cached domain list."""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


# Common action verbs in adult content contexts
ACTION_VERBS = {
    "watch", "see", "view", "show", "live", "free", "meet",
    "find", "get", "download", "stream", "chat", "cam",
}

# Explicit nouns that indicate adult content
EXPLICIT_NOUNS = {
    "porn", "sex", "xxx", "adult", "nude", "naked",
    "video", "videos", "movie", "movies", "cam", "cams",
    "girl", "girls", "boy", "boys", "teen", "teens",
    "gay", "lesbian", "trans", "shemale",
    "milf", "babe", "babes",
    "anal", "oral",
}


def extract_word_sequence(domain: str) -> List[str]:
    """
    Extract sequential words from domain, handling separators.

    Examples:
        "watchsex.com" -> ["watch", "sex"]
        "watch-sex.com" -> ["watch", "sex"]
        "watchgirlsex.com" -> ["watch", "girl", "sex"]
        "freepornvideos.net" -> ["free", "porn", "videos"]
    """
    # Remove TLD
    domain_core = re.sub(r'\.[a-z]+$', '', domain.lower())

    # Split on separators (-, _, .)
    parts = re.split(r'[-_.]', domain_core)

    words = []
    for part in parts:
        # Try to split concatenated words using a simple heuristic
        # Look for known verbs and nouns
        current_pos = 0
        part_len = len(part)

        while current_pos < part_len:
            found = False

            # Try to match verbs and nouns from longest to shortest
            for length in range(min(10, part_len - current_pos), 2, -1):
                substring = part[current_pos:current_pos + length]

                if substring in ACTION_VERBS or substring in EXPLICIT_NOUNS:
                    words.append(substring)
                    current_pos += length
                    found = True
                    break

            if not found:
                # Try shorter substrings (3-5 chars)
                for length in range(min(5, part_len - current_pos), 2, -1):
                    substring = part[current_pos:current_pos + length]
                    if substring.isalpha():
                        words.append(substring)
                        current_pos += length
                        found = True
                        break

            if not found:
                current_pos += 1

    return words


def find_verb_noun_sequences(domains: List[str]) -> Dict[Tuple[str, str], List[str]]:
    """
    Find all verb+noun sequential patterns in domains.

    Returns a dict mapping (verb, noun) -> list of example domains
    """
    patterns = defaultdict(list)

    for domain in domains:
        words = extract_word_sequence(domain)

        # Look for verb followed by noun (adjacent or within 1 word)
        for i in range(len(words)):
            if words[i] in ACTION_VERBS:
                # Check immediate next word
                if i + 1 < len(words) and words[i + 1] in EXPLICIT_NOUNS:
                    pattern = (words[i], words[i + 1])
                    if len(patterns[pattern]) < 20:  # Keep examples
                        patterns[pattern].append(domain)

                # Check word after next (e.g., "watch-girl-sex")
                if i + 2 < len(words) and words[i + 2] in EXPLICIT_NOUNS:
                    # Middle word should be short or also explicit
                    middle = words[i + 1]
                    if len(middle) <= 4 or middle in EXPLICIT_NOUNS:
                        pattern = (words[i], words[i + 2])
                        if len(patterns[pattern]) < 20:
                            patterns[pattern].append(domain)

    return patterns


def test_pattern_in_domain(domain: str, verb: str, noun: str) -> bool:
    """
    Test if verb+noun pattern appears in domain.
    Handles: verb-noun, verbnoun, verb.noun, verbXnoun (where X is optional short word)
    """
    domain_lower = domain.lower()

    # Pattern 1: Direct concatenation (watchsex)
    if verb + noun in domain_lower:
        return True

    # Pattern 2: With separator (watch-sex, watch.sex, watch_sex)
    pattern_with_sep = re.escape(verb) + r'[-_.]' + re.escape(noun)
    if re.search(pattern_with_sep, domain_lower):
        return True

    # Pattern 3: With 1-4 char word in between (watchgirlsex)
    pattern_with_middle = re.escape(verb) + r'[a-z]{0,4}' + re.escape(noun)
    if re.search(pattern_with_middle, domain_lower):
        return True

    return False


def estimate_coverage(domains: List[str], patterns: List[Tuple[str, str]]) -> Tuple[int, Set[str]]:
    """Estimate how many domains would be matched by these patterns."""
    matched_domains = set()

    for domain in domains:
        for verb, noun in patterns:
            if test_pattern_in_domain(domain, verb, noun):
                matched_domains.add(domain)
                break

    return len(matched_domains), matched_domains


def main():
    print("=" * 80)
    print("VERB+NOUN SEQUENTIAL PATTERN ANALYSIS")
    print("=" * 80)
    print()

    print("Loading domains...")
    domains = load_domains()
    print(f"Total domains: {len(domains):,}")
    print()

    print("Extracting verb+noun sequential patterns...")
    print()

    patterns = find_verb_noun_sequences(domains)

    # Sort by frequency
    sorted_patterns = sorted(
        [(pattern, examples) for pattern, examples in patterns.items()],
        key=lambda x: len(x[1]),
        reverse=True
    )

    print(f"Found {len(sorted_patterns)} unique verb+noun patterns")
    print()

    print("=" * 80)
    print("TOP VERB+NOUN PATTERNS")
    print("=" * 80)
    print()

    high_confidence_patterns = []

    for (verb, noun), examples in sorted_patterns[:100]:
        count = len(examples)

        # Show top patterns with examples
        if count >= 10:  # At least 10 occurrences
            high_confidence_patterns.append((verb, noun))

            print(f"{verb} + {noun}: {count:>4} occurrences")
            print(f"  Examples: {', '.join(examples[:5])}")
            print()

    print("=" * 80)
    print("HIGH CONFIDENCE PATTERNS (10+ occurrences)")
    print("=" * 80)
    print()

    print(f"Total patterns: {len(high_confidence_patterns)}")
    print()

    # Group by verb
    verb_groups = defaultdict(list)
    for verb, noun in high_confidence_patterns:
        verb_groups[verb].append(noun)

    print("Grouped by verb:")
    for verb in sorted(verb_groups.keys()):
        nouns = verb_groups[verb]
        print(f"  {verb:10s} -> {', '.join(sorted(nouns))}")
    print()

    # Group by noun
    noun_groups = defaultdict(list)
    for verb, noun in high_confidence_patterns:
        noun_groups[noun].append(verb)

    print("Grouped by noun:")
    for noun in sorted(noun_groups.keys()):
        verbs = noun_groups[noun]
        print(f"  {noun:10s} <- {', '.join(sorted(verbs))}")
    print()

    print("=" * 80)
    print("COVERAGE ESTIMATION")
    print("=" * 80)
    print()

    # Test different threshold levels
    for min_count in [50, 20, 10, 5]:
        threshold_patterns = [
            (v, n) for (v, n), examples in sorted_patterns
            if len(examples) >= min_count
        ]

        matched_count, matched_domains = estimate_coverage(domains, threshold_patterns)
        coverage_pct = (matched_count / len(domains)) * 100

        print(f"Patterns with {min_count:>2}+ occurrences: {len(threshold_patterns):>3} patterns")
        print(f"  Coverage: {matched_count:>7,} / {len(domains):,} ({coverage_pct:5.2f}%)")
        print()

    print("=" * 80)
    print("RECOMMENDED IMPLEMENTATION")
    print("=" * 80)
    print()

    # Get top patterns (10+ occurrences)
    recommended = [
        (v, n) for (v, n), examples in sorted_patterns
        if len(examples) >= 10
    ]

    print(f"Recommend implementing {len(recommended)} verb+noun patterns:")
    print()

    print("```rust")
    print("// Verb+noun sequential patterns")
    print("const VERB_NOUN_PATTERNS: &[((&str, &str)] = &[")

    for verb, noun in sorted(recommended):
        print(f'    ("{verb}", "{noun}"),')

    print("];")
    print()
    print("fn has_verb_noun_pattern(domain: &str) -> bool {")
    print("    let domain_lower = domain.to_lowercase();")
    print("    ")
    print("    for (verb, noun) in VERB_NOUN_PATTERNS {")
    print("        // Pattern 1: Direct concatenation (watchsex)")
    print("        if domain_lower.contains(&format!(\"{}{}\", verb, noun)) {")
    print("            return true;")
    print("        }")
    print("        ")
    print("        // Pattern 2: With separator (watch-sex, watch.sex)")
    print("        let pattern_sep = format!(\"{}[-_.]{}\", verb, noun);")
    print("        if regex::Regex::new(&pattern_sep).unwrap().is_match(&domain_lower) {")
    print("            return true;")
    print("        }")
    print("        ")
    print("        // Pattern 3: With 1-4 char in between (watchgirlsex)")
    print("        let pattern_mid = format!(\"{}[a-z]{{0,4}}{}\", verb, noun);")
    print("        if regex::Regex::new(&pattern_mid).unwrap().is_match(&domain_lower) {")
    print("            return true;")
    print("        }")
    print("    }")
    print("    ")
    print("    false")
    print("}")
    print("```")
    print()

    print("=" * 80)
    print("TESTING RECOMMENDATIONS")
    print("=" * 80)
    print()

    # Test some examples
    test_cases = [
        ("watchsex.com", True),
        ("watch-sex.com", True),
        ("watchgirlsex.com", True),
        ("freeporn.net", True),
        ("livecam.com", True),
        ("google.com", False),
        ("facebook.com", False),
        ("watch.com", False),  # verb alone
        ("sex.com", False),    # noun alone (but would match on keyword)
    ]

    print("Testing pattern matching:")
    for domain, expected in test_cases:
        matched = False
        for verb, noun in recommended:
            if test_pattern_in_domain(domain, verb, noun):
                matched = True
                break

        result = "✓" if matched == expected else "✗"
        print(f"  {result} {domain:30s} -> {'MATCH' if matched else 'no match':10s} (expected: {'MATCH' if expected else 'no match'})")
    print()


if __name__ == "__main__":
    main()
