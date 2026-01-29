#!/usr/bin/env python3
"""
Fast verb+noun pattern analysis using regex.

Directly search for verb+noun patterns without complex parsing.
"""

import re
from collections import Counter
from typing import List, Tuple, Set


def load_domains(file_path="/tmp/porn_domains.txt") -> List[str]:
    """Load cached domain list."""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


# Action verbs
VERBS = [
    "watch", "see", "view", "show", "live", "free", "meet",
    "find", "get", "download", "stream", "chat", "cam",
]

# Explicit nouns
NOUNS = [
    "porn", "sex", "xxx", "adult", "nude", "naked",
    "video", "videos", "movie", "movies", "cam", "cams",
    "girl", "girls", "boy", "boys", "teen", "teens",
    "gay", "lesbian", "trans", "shemale",
    "milf", "babe", "babes",
    "anal", "oral",
]


def find_patterns_fast(domains: List[str]) -> Counter:
    """Fast pattern finding using simple regex."""
    pattern_counter = Counter()

    print(f"Analyzing {len(domains):,} domains...")
    print()

    for i, (verb, noun) in enumerate([(v, n) for v in VERBS for n in NOUNS]):
        if i % 50 == 0:
            print(f"  Progress: {i}/{len(VERBS) * len(NOUNS)} patterns checked...")

        # Pattern: verb followed by noun (with optional 0-4 chars or separator)
        # Examples: watchsex, watch-sex, watchgirlsex
        pattern = re.compile(
            rf'{re.escape(verb)}(?:[-_.]|[a-z]{{0,4}})?{re.escape(noun)}',
            re.IGNORECASE
        )

        count = 0
        for domain in domains:
            if pattern.search(domain):
                count += 1

        if count > 0:
            pattern_counter[(verb, noun)] = count

    print()
    return pattern_counter


def main():
    print("=" * 80)
    print("FAST VERB+NOUN PATTERN ANALYSIS")
    print("=" * 80)
    print()

    domains = load_domains()
    print(f"Total domains: {len(domains):,}")
    print(f"Verbs: {len(VERBS)}")
    print(f"Nouns: {len(NOUNS)}")
    print(f"Total patterns to test: {len(VERBS) * len(NOUNS)}")
    print()

    # Find patterns
    pattern_counts = find_patterns_fast(domains)

    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    print()

    print(f"Found {len(pattern_counts)} patterns with matches")
    print()

    # Sort by count
    sorted_patterns = sorted(
        pattern_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    # Show all patterns with 10+ matches
    high_conf = [(v, n, c) for (v, n), c in sorted_patterns if c >= 10]

    print(f"Patterns with 10+ matches: {len(high_conf)}")
    print()

    for verb, noun, count in high_conf:
        pct = (count / len(domains)) * 100
        print(f"  {verb:10s} + {noun:10s} = {count:>6,} ({pct:5.2f}%)")

    print()

    # Group by verb
    print("=" * 80)
    print("GROUPED BY VERB (10+ matches)")
    print("=" * 80)
    print()

    from collections import defaultdict
    verb_groups = defaultdict(list)
    for verb, noun, count in high_conf:
        verb_groups[verb].append((noun, count))

    for verb in sorted(verb_groups.keys()):
        nouns_counts = verb_groups[verb]
        total = sum(c for _, c in nouns_counts)
        print(f"{verb:10s} ({total:>6,} total):")
        for noun, count in sorted(nouns_counts, key=lambda x: x[1], reverse=True):
            print(f"    + {noun:10s} = {count:>6,}")
        print()

    # Group by noun
    print("=" * 80)
    print("GROUPED BY NOUN (10+ matches)")
    print("=" * 80)
    print()

    noun_groups = defaultdict(list)
    for verb, noun, count in high_conf:
        noun_groups[noun].append((verb, count))

    for noun in sorted(noun_groups.keys()):
        verbs_counts = noun_groups[noun]
        total = sum(c for _, c in verbs_counts)
        print(f"{noun:10s} ({total:>6,} total):")
        for verb, count in sorted(verbs_counts, key=lambda x: x[1], reverse=True):
            print(f"    {verb:10s} + = {count:>6,}")
        print()

    # Coverage estimation
    print("=" * 80)
    print("COVERAGE ESTIMATION")
    print("=" * 80)
    print()

    # Test coverage at different thresholds
    for threshold in [50, 20, 10, 5]:
        patterns = [(v, n) for (v, n), c in sorted_patterns if c >= threshold]
        total_matches = sum(c for (v, n), c in sorted_patterns if c >= threshold)

        print(f"Threshold: {threshold:>2}+ matches")
        print(f"  Patterns: {len(patterns):>3}")
        print(f"  Total matches: {total_matches:>7,}")
        print(f"  Coverage: {total_matches / len(domains) * 100:5.2f}%")
        print()

    # Generate Rust code
    print("=" * 80)
    print("RUST IMPLEMENTATION")
    print("=" * 80)
    print()

    print("```rust")
    print("// Verb+Noun sequential patterns (10+ occurrences)")
    print("const VERB_NOUN_PATTERNS: &[(&str, &str)] = &[")

    for verb, noun, count in high_conf:
        print(f'    ("{verb}", "{noun}"),  // {count} matches')

    print("];")
    print()
    print("/// Check if domain contains verb+noun sequential pattern.")
    print("fn has_verb_noun_pattern(domain: &str) -> bool {")
    print("    let domain_lower = domain.to_lowercase();")
    print()
    print("    for (verb, noun) in VERB_NOUN_PATTERNS {")
    print("        // Direct concatenation: watchsex")
    print("        let direct = format!(\"{}{}\", verb, noun);")
    print("        if domain_lower.contains(&direct) {")
    print("            return true;")
    print("        }")
    print()
    print("        // With separator: watch-sex, watch_sex, watch.sex")
    print("        for sep in &['-', '_', '.'] {")
    print("            let with_sep = format!(\"{}{}{}\", verb, sep, noun);")
    print("            if domain_lower.contains(&with_sep) {")
    print("                return true;")
    print("            }")
    print("        }")
    print("    }")
    print()
    print("    false")
    print("}")
    print("```")


if __name__ == "__main__":
    main()
