#!/usr/bin/env python3
"""
Deep analysis to find better heuristic patterns.

Focus on finding patterns that can cover more domains without false positives.
"""

import re
from collections import Counter, defaultdict
from typing import List, Set, Tuple

def load_domains(file_path="/tmp/porn_domains.txt") -> List[str]:
    """Load cached domain list."""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def test_current_heuristic(domain: str) -> bool:
    """Test if current heuristic would match this domain."""
    domain_lower = domain.lower()

    # Current keywords from src/porn_heuristic.rs
    keywords = {
        "porn", "xvideo", "xnxx", "hentai", "redtube", "youporn",
        "spankbang", "xhamster", "brazzers", "bangbros", "porntrex",
        "porntube", "pornstar", "xxx", "sex", "adult"
    }

    # Check for false positives
    false_positives = ["essex", "sussex", "middlesex", "wessex", "macosx",
                       "adulteducation", "adultlearning"]
    for fp in false_positives:
        if fp in domain_lower:
            return False

    # Check keywords
    return any(kw in domain_lower for kw in keywords)


def analyze_uncovered_domains(domains: List[str]) -> None:
    """Analyze domains that are NOT covered by current heuristic."""

    uncovered = [d for d in domains if not test_current_heuristic(d)]

    print(f"Uncovered domains: {len(uncovered):,} / {len(domains):,} ({len(uncovered)/len(domains)*100:.1f}%)")
    print()

    # Analyze patterns in uncovered domains
    print("=" * 80)
    print("PATTERNS IN UNCOVERED DOMAINS")
    print("=" * 80)
    print()

    # 1. TLD distribution
    print("1. Top TLDs in uncovered domains:")
    tld_counter = Counter()
    for domain in uncovered:
        match = re.search(r'\.([a-z0-9]+)$', domain.lower())
        if match:
            tld_counter[match.group(1)] += 1

    for tld, count in tld_counter.most_common(20):
        pct = (count / len(uncovered)) * 100
        print(f"   .{tld:15s} {count:>8,} ({pct:5.1f}%)")
    print()

    # 2. Common substrings (3-10 chars)
    print("2. Common substrings in uncovered domains (min 500 occurrences):")
    substring_counter = Counter()

    for domain in uncovered[:50000]:  # Sample for performance
        domain_lower = domain.lower()
        # Extract domain without TLD
        domain_core = re.sub(r'\.[a-z]+$', '', domain_lower)

        # Count all substrings of length 3-10
        for length in range(3, 11):
            for i in range(len(domain_core) - length + 1):
                substring = domain_core[i:i+length]
                if substring.isalpha():  # Only alphabetic
                    substring_counter[substring] += 1

    # Filter to high-count substrings
    common_substrings = [(s, c) for s, c in substring_counter.items() if c >= 500]
    common_substrings.sort(key=lambda x: x[1], reverse=True)

    for substring, count in common_substrings[:50]:
        # Test if adding this would cause false positives
        risk_level = "?"
        if substring in {"the", "and", "for", "com", "net", "org"}:
            risk_level = "HIGH"
        elif substring in {"tumblr", "blogspot", "blog", "pages"}:
            risk_level = "PLATFORM"
        elif any(x in substring for x in ["sex", "porn", "xxx", "nude", "cam", "adult"]):
            risk_level = "SAFE"

        pct = (count / len(uncovered)) * 100
        print(f"   {substring:15s} {count:>8,} ({pct:5.1f}%) [{risk_level}]")
    print()

    # 3. Multi-byte patterns (non-ASCII)
    print("3. Non-ASCII domain analysis:")
    non_ascii = [d for d in uncovered if not d.isascii()]
    print(f"   Non-ASCII domains: {len(non_ascii):,} ({len(non_ascii)/len(uncovered)*100:.1f}%)")
    if non_ascii:
        print(f"   Examples: {', '.join(non_ascii[:10])}")
    print()

    # 4. Platform-specific analysis
    print("4. Platform/service domains:")
    platforms = {
        "tumblr": 0,
        "blogspot": 0,
        "wordpress": 0,
        "blogger": 0,
        "wix": 0,
        "weebly": 0,
        "webnode": 0,
        "jimdo": 0,
        "itch": 0,
    }

    for domain in uncovered:
        for platform in platforms:
            if platform in domain.lower():
                platforms[platform] += 1

    print("   Platform subdomain counts:")
    for platform, count in sorted(platforms.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            pct = (count / len(uncovered)) * 100
            print(f"     {platform:15s} {count:>8,} ({pct:5.1f}%)")
    print()

    # 5. Number patterns
    print("5. Number-heavy domains:")
    number_heavy = [d for d in uncovered if sum(c.isdigit() for c in d) >= 4]
    print(f"   Domains with 4+ digits: {len(number_heavy):,} ({len(number_heavy)/len(uncovered)*100:.1f}%)")
    if number_heavy:
        print(f"   Examples: {', '.join(number_heavy[:10])}")
    print()

    # 6. Promising new keywords
    print("6. Candidate keywords for expansion (appearing in 1000+ uncovered domains):")

    # Extract all words
    word_counter = Counter()
    for domain in uncovered:
        # Tokenize
        tokens = re.findall(r'[a-z]{3,}', domain.lower())
        for token in tokens:
            word_counter[token] += 1

    # Filter for adult content keywords
    adult_indicators = []
    for word, count in word_counter.items():
        if count < 1000:
            continue

        # Skip platform names
        if word in {"tumblr", "blogspot", "wordpress", "blog", "pages", "canalblog"}:
            continue

        # Skip common words
        if word in {"the", "and", "for", "com", "net", "org", "www", "http", "https"}:
            continue

        # Look for adult content patterns
        if any(indicator in word for indicator in [
            "cam", "chat", "escort", "nude", "naked", "strip", "bdsm",
            "fetish", "kinky", "erotic", "amateur", "milf", "teen",
            "gay", "lesbian", "trans", "shemale", "anal", "oral",
            "tube", "video", "live", "show", "model", "girl", "boy"
        ]):
            adult_indicators.append((word, count))

    adult_indicators.sort(key=lambda x: x[1], reverse=True)

    for word, count in adult_indicators[:30]:
        pct = (count / len(uncovered)) * 100
        print(f"     {word:20s} {count:>8,} ({pct:5.1f}%)")
    print()


def estimate_expanded_coverage(domains: List[str], new_keywords: Set[str]) -> None:
    """Estimate coverage with expanded keyword list."""
    print("=" * 80)
    print("COVERAGE ESTIMATION WITH EXPANDED KEYWORDS")
    print("=" * 80)
    print()

    current_keywords = {
        "porn", "xvideo", "xnxx", "hentai", "redtube", "youporn",
        "spankbang", "xhamster", "brazzers", "bangbros", "porntrex",
        "porntube", "pornstar", "xxx", "sex", "adult"
    }

    # Test current
    current_matched = sum(1 for d in domains if test_current_heuristic(d))
    current_pct = (current_matched / len(domains)) * 100

    # Test with new keywords
    all_keywords = current_keywords | new_keywords

    new_matched = 0
    for domain in domains:
        domain_lower = domain.lower()

        # Check false positives
        false_positives = ["essex", "sussex", "middlesex", "wessex", "macosx",
                           "adulteducation", "adultlearning"]
        if any(fp in domain_lower for fp in false_positives):
            continue

        # Check all keywords
        if any(kw in domain_lower for kw in all_keywords):
            new_matched += 1

    new_pct = (new_matched / len(domains)) * 100
    improvement = new_matched - current_matched

    print(f"Current heuristic:  {current_matched:>8,} / {len(domains):,} ({current_pct:5.1f}%)")
    print(f"With new keywords:  {new_matched:>8,} / {len(domains):,} ({new_pct:5.1f}%)")
    print(f"Improvement:        {improvement:>8,} domains (+{new_pct - current_pct:.1f}%)")
    print()
    print(f"FST size reduction: {len(domains) - new_matched:,} domains ({100 - new_pct:.1f}%)")
    print()


def main():
    print("=" * 80)
    print("DEEP HEURISTIC ANALYSIS - FINDING BETTER PATTERNS")
    print("=" * 80)
    print()

    domains = load_domains()
    print(f"Total domains: {len(domains):,}")
    print()

    # Analyze what we're missing
    analyze_uncovered_domains(domains)

    # Propose new keywords
    print("=" * 80)
    print("RECOMMENDED NEW KEYWORDS")
    print("=" * 80)
    print()

    recommended = {
        # Explicit activity keywords
        "cam", "webcam", "livecam", "camgirl", "camshow",
        "chat", "livechat", "sexchat", "videochat",
        "escort", "escorts",
        "strip", "stripchat", "striptease",
        "nude", "nudes", "naked",
        "bdsm", "fetish", "kinky",

        # Content type keywords
        "tube", "videos", "movie", "movies", "film",
        "porno", "porna", "pornos",
        "erotic", "erotica",

        # Demographic keywords (high confidence)
        "milf", "teen", "teens",
        "gay", "lesbian", "trans", "shemale",
        "amateur",

        # Body part / activity (explicit)
        "anal", "oral",

        # Brand names / platforms
        "chaturbate", "bongacams", "stripchat", "livejasmin",
        "onlyfans", "manyvids",

        # Multi-lingual variations
        "sexe", "sexo",  # French, Spanish
        "porno", "pornos",  # Various languages
    }

    print("Proposed additions:")
    for kw in sorted(recommended):
        print(f"   \"{kw}\"")
    print()
    print(f"Total new keywords: {len(recommended)}")
    print()

    # Estimate impact
    estimate_expanded_coverage(domains, recommended)


if __name__ == "__main__":
    main()
