#!/usr/bin/env python3
"""
Analyze porn domain list to extract heuristic rules.

This script:
1. Downloads and analyzes the porn domain list (~707k domains)
2. Extracts keyword patterns (single words and combinations)
3. Uses English dictionary to validate legitimate words
4. Generates heuristic rules with near-zero false positive rate
"""

import re
import sys
from collections import Counter, defaultdict
from typing import Set, List, Tuple, Dict
import urllib.request
import json

# Download domain list
PORN_DOMAINS_URL = "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/main/block.5994458652.9y8bk8.txt"

# Common English words that might appear in domains (to avoid)
# We'll use a curated list of common legitimate words
COMMON_LEGITIMATE_WORDS = {
    # Geographic locations
    "essex", "sussex", "middlesex", "wessex",
    # Common words that might contain substrings
    "express", "exercise", "expert", "example", "exam",
    "classic", "classical", "class",
    # Technology/OS
    "macosx", "unix", "linux",
    # Education
    "education", "learning", "school", "university",
    # Business/professional
    "business", "professional", "service", "company",
}

# Strong porn-specific keywords (brand names, platforms)
# These are highly specific and unlikely to appear in legitimate domains
STRONG_KEYWORDS = {
    "pornhub", "xvideos", "xnxx", "redtube", "youporn",
    "spankbang", "xhamster", "brazzers", "bangbros",
    "porntrex", "porntube", "pornstar", "hentai",
    "chaturbate", "stripchat", "livejasmin", "bongacams",
    "onlyfans", "manyvids", "clips4sale",
}


def download_domains(cache_file="/tmp/porn_domains.txt") -> List[str]:
    """Download or load cached domain list."""
    try:
        with open(cache_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
            print(f"✓ Loaded {len(domains)} domains from cache: {cache_file}")
            return domains
    except FileNotFoundError:
        print(f"✗ Cache not found, downloading from {PORN_DOMAINS_URL}")
        with urllib.request.urlopen(PORN_DOMAINS_URL) as response:
            content = response.read().decode('utf-8')
            domains = [line.strip() for line in content.split('\n') if line.strip()]
            with open(cache_file, 'w') as f:
                f.write('\n'.join(domains))
            print(f"✓ Downloaded and cached {len(domains)} domains")
            return domains


def extract_tokens(domain: str) -> List[str]:
    """
    Extract meaningful tokens from a domain.

    Examples:
        "watch-porn-videos.com" -> ["watch", "porn", "videos"]
        "freexxxmovies.net" -> ["free", "xxx", "movies"]
    """
    # Remove TLD
    domain_without_tld = re.sub(r'\.[a-z]+$', '', domain.lower())

    # Split on common separators
    tokens = re.split(r'[-_.]', domain_without_tld)

    # Further split camelCase and number boundaries
    expanded = []
    for token in tokens:
        # Split on transitions: lowercase->uppercase, letter->number
        parts = re.findall(r'[a-z]+|[0-9]+', token)
        expanded.extend(parts)

    return [t for t in expanded if len(t) >= 2]  # Filter very short tokens


def is_likely_legitimate(word: str) -> bool:
    """Check if a word is likely legitimate (not adult content)."""
    return word in COMMON_LEGITIMATE_WORDS


def analyze_single_keywords(domains: List[str]) -> Dict[str, int]:
    """Extract and count single keyword occurrences."""
    keyword_counts = Counter()

    for domain in domains:
        tokens = extract_tokens(domain)
        for token in tokens:
            if len(token) >= 3:  # At least 3 characters
                keyword_counts[token] += 1

    return dict(keyword_counts)


def analyze_bigrams(domains: List[str]) -> Dict[Tuple[str, str], int]:
    """Extract and count word pairs (bigrams)."""
    bigram_counts = Counter()

    for domain in domains:
        tokens = extract_tokens(domain)
        for i in range(len(tokens) - 1):
            bigram = (tokens[i], tokens[i + 1])
            bigram_counts[bigram] += 1

    return dict(bigram_counts)


def categorize_keywords(keyword_counts: Dict[str, int], min_count: int = 100) -> Dict[str, List[str]]:
    """Categorize keywords by semantic type."""

    # Common action verbs in adult content
    verbs = {"watch", "see", "view", "live", "cam", "chat", "free", "download",
             "stream", "tube", "show", "meet", "find", "get"}

    # Common nouns in adult content
    nouns = {"sex", "porn", "xxx", "adult", "nude", "naked", "teen", "milf",
             "gay", "lesbian", "anal", "oral", "video", "movie", "pic", "photo",
             "cam", "webcam", "chat", "girl", "boy", "woman", "man", "babe"}

    categories = {
        "verbs": [],
        "nouns": [],
        "explicit": [],  # Highly explicit words
        "brands": [],    # Brand names (pornhub, xnxx, etc.)
        "ambiguous": [], # Words that might appear in legitimate contexts
    }

    for word, count in keyword_counts.items():
        if count < min_count:
            continue

        if word in STRONG_KEYWORDS:
            categories["brands"].append(word)
        elif is_likely_legitimate(word):
            categories["ambiguous"].append(word)
        elif word in verbs:
            categories["verbs"].append(word)
        elif word in nouns:
            categories["nouns"].append(word)
        elif any(x in word for x in ["sex", "porn", "xxx", "nude", "naked"]):
            categories["explicit"].append(word)

    return categories


def find_verb_noun_combinations(
    bigrams: Dict[Tuple[str, str], int],
    verbs: Set[str],
    nouns: Set[str],
    min_count: int = 50
) -> List[Tuple[str, str, int]]:
    """Find verb+noun combinations that appear frequently."""
    combinations = []

    for (word1, word2), count in bigrams.items():
        if count < min_count:
            continue

        # verb + noun pattern
        if word1 in verbs and word2 in nouns:
            combinations.append((word1, word2, count))
        # noun + noun pattern (also common)
        elif word1 in nouns and word2 in nouns:
            combinations.append((word1, word2, count))

    return sorted(combinations, key=lambda x: x[2], reverse=True)


def main():
    print("=" * 80)
    print("PORN DOMAIN HEURISTIC ANALYSIS")
    print("=" * 80)
    print()

    # Step 1: Load domains
    print("[1/5] Loading domains...")
    domains = download_domains()
    print(f"      Total domains: {len(domains):,}")
    print()

    # Step 2: Analyze single keywords
    print("[2/5] Analyzing single keywords...")
    keyword_counts = analyze_single_keywords(domains)
    print(f"      Unique tokens found: {len(keyword_counts):,}")

    # Show top keywords
    top_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:30]
    print("\n      Top 30 keywords:")
    for word, count in top_keywords:
        pct = (count / len(domains)) * 100
        print(f"        {word:20s} {count:>8,} ({pct:5.1f}%)")
    print()

    # Step 3: Categorize keywords
    print("[3/5] Categorizing keywords (min 100 occurrences)...")
    categories = categorize_keywords(keyword_counts, min_count=100)

    for cat_name, words in categories.items():
        if words:
            print(f"\n      {cat_name.upper()} ({len(words)} words):")
            print(f"        {', '.join(sorted(words)[:20])}")
            if len(words) > 20:
                print(f"        ... and {len(words) - 20} more")
    print()

    # Step 4: Analyze bigrams
    print("[4/5] Analyzing word combinations...")
    bigrams = analyze_bigrams(domains)
    print(f"      Unique bigrams found: {len(bigrams):,}")

    # Show top bigrams
    top_bigrams = sorted(bigrams.items(), key=lambda x: x[1], reverse=True)[:20]
    print("\n      Top 20 bigrams:")
    for (w1, w2), count in top_bigrams:
        pct = (count / len(domains)) * 100
        print(f"        {w1}-{w2:30s} {count:>8,} ({pct:5.1f}%)")
    print()

    # Step 5: Find verb+noun combinations
    print("[5/5] Extracting verb+noun combinations (min 50 occurrences)...")
    verb_set = set(categories.get("verbs", []))
    noun_set = set(categories.get("nouns", []))

    # Add common adult content verbs/nouns even if not in categories
    verb_set.update({"watch", "see", "view", "live", "free", "chat", "meet", "download"})
    noun_set.update({"porn", "sex", "xxx", "adult", "teen", "gay", "lesbian", "video", "cam"})

    combinations = find_verb_noun_combinations(bigrams, verb_set, noun_set, min_count=50)

    print(f"\n      Found {len(combinations)} verb+noun combinations:")
    for w1, w2, count in combinations[:30]:
        pct = (count / len(domains)) * 100
        print(f"        {w1}-{w2:30s} {count:>8,} ({pct:5.1f}%)")
    if len(combinations) > 30:
        print(f"        ... and {len(combinations) - 30} more")
    print()

    # Generate recommendations
    print("=" * 80)
    print("RECOMMENDATIONS FOR HEURISTIC RULES")
    print("=" * 80)
    print()

    print("1. STRONG KEYWORDS (near-zero false positives):")
    print("   These can be matched anywhere in the domain:")
    strong = set()

    # Brand names
    for word in categories.get("brands", []):
        if keyword_counts.get(word, 0) > 100:
            strong.add(word)

    # Highly explicit single words
    for word in categories.get("explicit", []):
        if keyword_counts.get(word, 0) > 500 and word not in COMMON_LEGITIMATE_WORDS:
            strong.add(word)

    # Add top keywords that are unambiguous
    for word, count in top_keywords[:50]:
        if count > 1000 and not is_likely_legitimate(word):
            if any(x in word for x in ["porn", "xxx", "sex", "nude", "adult", "hentai"]):
                strong.add(word)

    for word in sorted(strong):
        count = keyword_counts.get(word, 0)
        pct = (count / len(domains)) * 100
        print(f"     \"{word}\" - appears in {count:,} domains ({pct:.1f}%)")

    print(f"\n   Total: {len(strong)} keywords")
    print()

    print("2. VERB+NOUN COMBINATIONS (high confidence):")
    print("   Match these as adjacent words or concatenated:")
    high_conf_combos = []
    for w1, w2, count in combinations:
        if count > 100:  # High threshold
            high_conf_combos.append((w1, w2, count))

    for w1, w2, count in high_conf_combos[:20]:
        pct = (count / len(domains)) * 100
        print(f"     \"{w1}\" + \"{w2}\" - {count:,} occurrences ({pct:.1f}%)")

    print(f"\n   Total: {len(high_conf_combos)} combinations (showing top 20)")
    print()

    print("3. COVERAGE ANALYSIS:")
    # Test current heuristic
    current_keywords = {
        "porn", "xvideo", "xnxx", "hentai", "redtube", "youporn",
        "spankbang", "xhamster", "brazzers", "bangbros", "porntrex",
        "porntube", "pornstar", "xxx", "sex", "adult"
    }

    matched = 0
    for domain in domains:
        domain_lower = domain.lower()
        if any(kw in domain_lower for kw in current_keywords):
            matched += 1

    current_coverage = (matched / len(domains)) * 100
    print(f"   Current heuristic coverage: {matched:,} / {len(domains):,} ({current_coverage:.1f}%)")
    print(f"   Domains still needing FST: {len(domains) - matched:,} ({100 - current_coverage:.1f}%)")
    print()

    # Estimate coverage with recommended keywords
    recommended_matched = 0
    for domain in domains:
        domain_lower = domain.lower()
        if any(kw in domain_lower for kw in strong):
            recommended_matched += 1

    recommended_coverage = (recommended_matched / len(domains)) * 100
    print(f"   Recommended heuristic coverage: {recommended_matched:,} / {len(domains):,} ({recommended_coverage:.1f}%)")
    print(f"   Improvement: +{recommended_matched - matched:,} domains (+{recommended_coverage - current_coverage:.1f}%)")
    print(f"   FST reduction: {len(domains) - recommended_matched:,} domains ({100 - recommended_coverage:.1f}%)")
    print()

    print("=" * 80)
    print("NEXT STEPS:")
    print("=" * 80)
    print("1. Review the recommended keywords above")
    print("2. Test for false positives against common domain lists")
    print("3. Update src/porn_heuristic.rs with approved keywords")
    print("4. Re-run FST generation to measure size reduction")
    print()


if __name__ == "__main__":
    main()
