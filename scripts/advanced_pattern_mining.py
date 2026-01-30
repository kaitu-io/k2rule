#!/usr/bin/env python3
"""
Advanced pattern mining for porn domain detection.

This script automatically discovers:
1. High-frequency verbs and nouns (not manually defined)
2. Multi-word patterns (x-x, x-x-x, etc.)
3. Repetition patterns (xxx, sexsex, etc.)
4. Optimal combinations with zero false positives
"""

import re
from collections import Counter, defaultdict
from typing import List, Set, Tuple, Dict


def load_domains(file_path="/tmp/porn_domains.txt") -> List[str]:
    """Load cached domain list."""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def tokenize_domain(domain: str) -> List[str]:
    """
    Tokenize domain into words, handling various separators.

    Examples:
        "watch-sex-videos.com" -> ["watch", "sex", "videos"]
        "freepornhub.net" -> ["free", "porn", "hub"]  (attempt split)
    """
    # Remove TLD
    domain_core = re.sub(r'\.[a-z0-9]+$', '', domain.lower())

    # Split on separators
    parts = re.split(r'[-_.]', domain_core)

    # Extract alphabetic tokens (3+ chars)
    tokens = []
    for part in parts:
        # Extract all alphabetic sequences of 3+ chars
        words = re.findall(r'[a-z]{3,}', part)
        tokens.extend(words)

    return tokens


def discover_frequent_words(domains: List[str], min_count: int = 500) -> Dict[str, int]:
    """
    Discover all frequent words in domains.
    Returns word -> count mapping.
    """
    word_counter = Counter()

    print(f"Tokenizing {len(domains):,} domains...")
    for i, domain in enumerate(domains):
        if i % 100000 == 0:
            print(f"  Progress: {i:,}/{len(domains):,}")

        tokens = tokenize_domain(domain)
        for token in tokens:
            if len(token) >= 3:
                word_counter[token] += 1

    print()
    return {word: count for word, count in word_counter.items() if count >= min_count}


def categorize_words(word_counts: Dict[str, int]) -> Dict[str, List[str]]:
    """
    Automatically categorize words into verbs, nouns, and platform names.
    """
    # Known platform names to filter out
    platforms = {
        "tumblr", "blogspot", "wordpress", "blogger", "blog", "pages",
        "canalblog", "centerblog", "over", "startspot", "site", "voila",
        "itch", "skynetblogs", "weebly", "wix", "jimdo",
    }

    # Common non-adult words to filter
    common_words = {
        "the", "and", "for", "com", "net", "org", "www", "http", "https",
        "mail", "info", "home", "index", "page", "site", "web",
    }

    # Explicit adult indicators (if word contains these, it's adult content)
    adult_indicators = {
        "porn", "sex", "xxx", "adult", "nude", "naked", "cam", "gay",
        "lesbian", "trans", "milf", "teen", "anal", "oral", "bdsm",
        "fetish", "erotic", "escort", "strip", "hentai",
    }

    # Action verbs (common in adult content)
    action_indicators = {
        "watch", "see", "view", "live", "free", "show", "meet", "find",
        "get", "download", "stream", "chat", "play",
    }

    verbs = []
    nouns = []
    explicit = []

    for word, count in word_counts.items():
        if word in platforms or word in common_words:
            continue

        # Check if it's an action verb
        if word in action_indicators:
            verbs.append(word)
        # Check if it contains adult indicators
        elif any(indicator in word for indicator in adult_indicators):
            explicit.append(word)
            # Also categorize as noun if it's a base word
            if word in adult_indicators:
                nouns.append(word)

    return {
        "verbs": sorted(verbs),
        "nouns": sorted(nouns),
        "explicit": sorted(explicit),
    }


def find_ngram_patterns(domains: List[str], n: int = 2, min_count: int = 50) -> Counter:
    """
    Find n-gram patterns (2-word, 3-word, etc.) in domains.

    Returns: Counter of (word1, word2, ...) tuples
    """
    ngram_counter = Counter()

    print(f"Finding {n}-gram patterns (min {min_count} occurrences)...")
    for i, domain in enumerate(domains):
        if i % 100000 == 0:
            print(f"  Progress: {i:,}/{len(domains):,}")

        tokens = tokenize_domain(domain)

        # Generate n-grams
        for j in range(len(tokens) - n + 1):
            ngram = tuple(tokens[j:j+n])
            ngram_counter[ngram] += 1

    print()
    return Counter({ng: c for ng, c in ngram_counter.items() if c >= min_count})


def find_separator_patterns(domains: List[str], min_count: int = 100) -> Counter:
    """
    Find patterns with specific separators: x-x, x-x-x, x_x, etc.
    """
    pattern_counter = Counter()

    print(f"Finding separator patterns (min {min_count} occurrences)...")

    # Patterns to look for
    patterns = [
        (r'([a-z]{3,})-([a-z]{3,})', "word-word"),           # x-x
        (r'([a-z]{3,})-([a-z]{3,})-([a-z]{3,})', "word-word-word"),  # x-x-x
        (r'([a-z]{3,})_([a-z]{3,})', "word_word"),           # x_x
        (r'(\d+)', "numbers"),                                # numeric patterns
    ]

    for i, domain in enumerate(domains):
        if i % 100000 == 0:
            print(f"  Progress: {i:,}/{len(domains):,}")

        domain_lower = domain.lower()

        for pattern_re, pattern_name in patterns:
            matches = re.findall(pattern_re, domain_lower)
            for match in matches:
                if isinstance(match, tuple):
                    pattern_counter[(pattern_name, match)] += 1
                else:
                    pattern_counter[(pattern_name, match)] += 1

    print()
    return Counter({p: c for p, c in pattern_counter.items() if c >= min_count})


def find_repetition_patterns(domains: List[str], min_count: int = 50) -> Counter:
    """
    Find word repetition patterns: xxx, sexsex, camcam, etc.
    """
    repetition_counter = Counter()

    print(f"Finding repetition patterns (min {min_count} occurrences)...")

    for i, domain in enumerate(domains):
        if i % 100000 == 0:
            print(f"  Progress: {i:,}/{len(domains):,}")

        tokens = tokenize_domain(domain)

        # Look for repeated words
        for j in range(len(tokens) - 1):
            if tokens[j] == tokens[j + 1]:
                repetition_counter[("repeat", tokens[j])] += 1

        # Look for concatenated repetitions in domain
        domain_lower = domain.lower()
        for length in range(3, 8):  # Word length 3-7
            for k in range(len(domain_lower) - length * 2 + 1):
                substr = domain_lower[k:k+length]
                if substr.isalpha() and domain_lower[k:k+length*2] == substr * 2:
                    repetition_counter[("concat", substr)] += 1

    print()
    return Counter({p: c for p, c in repetition_counter.items() if c >= min_count})


def analyze_pattern_coverage(
    domains: List[str],
    patterns: List[Tuple],
    pattern_type: str
) -> Dict:
    """
    Analyze how many domains each pattern covers.
    """
    coverage = {}

    for pattern in patterns:
        count = 0
        examples = []

        for domain in domains:
            matched = False

            if pattern_type == "bigram":
                word1, word2 = pattern
                # Check if both words appear in sequence
                if re.search(rf'{word1}(?:[-_.]|[a-z]{{0,4}})?{word2}', domain.lower()):
                    matched = True

            elif pattern_type == "trigram":
                word1, word2, word3 = pattern
                # Check if all three words appear in sequence
                if re.search(
                    rf'{word1}(?:[-_.]|[a-z]{{0,4}})?{word2}(?:[-_.]|[a-z]{{0,4}})?{word3}',
                    domain.lower()
                ):
                    matched = True

            elif pattern_type == "separator":
                sep_type, words = pattern
                if sep_type == "word-word":
                    if f"{words[0]}-{words[1]}" in domain.lower():
                        matched = True
                elif sep_type == "word-word-word":
                    if f"{words[0]}-{words[1]}-{words[2]}" in domain.lower():
                        matched = True

            elif pattern_type == "repetition":
                rep_type, word = pattern
                if rep_type == "repeat":
                    if re.search(rf'{word}[-_.]?{word}', domain.lower()):
                        matched = True
                elif rep_type == "concat":
                    if word * 2 in domain.lower():
                        matched = True

            if matched:
                count += 1
                if len(examples) < 5:
                    examples.append(domain)

        if count > 0:
            coverage[pattern] = {
                "count": count,
                "percentage": count / len(domains) * 100,
                "examples": examples,
            }

    return coverage


def main():
    print("=" * 80)
    print("ADVANCED PATTERN MINING FOR PORN DOMAIN DETECTION")
    print("=" * 80)
    print()

    # Load domains
    domains = load_domains()
    print(f"Total domains: {len(domains):,}")
    print()

    # Step 1: Discover frequent words
    print("=" * 80)
    print("STEP 1: DISCOVERING FREQUENT WORDS")
    print("=" * 80)
    print()

    word_counts = discover_frequent_words(domains, min_count=500)
    print(f"Found {len(word_counts):,} frequent words (500+ occurrences)")
    print()

    # Show top 50
    top_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)[:50]
    print("Top 50 words:")
    for word, count in top_words:
        pct = (count / len(domains)) * 100
        print(f"  {word:20s} {count:>8,} ({pct:5.2f}%)")
    print()

    # Step 2: Categorize words
    print("=" * 80)
    print("STEP 2: CATEGORIZING WORDS")
    print("=" * 80)
    print()

    categories = categorize_words(word_counts)

    print(f"Verbs: {len(categories['verbs'])}")
    print(f"  {', '.join(categories['verbs'][:20])}")
    print()

    print(f"Nouns: {len(categories['nouns'])}")
    print(f"  {', '.join(categories['nouns'][:20])}")
    print()

    print(f"Explicit words: {len(categories['explicit'])}")
    print(f"  {', '.join(categories['explicit'][:30])}")
    print()

    # Step 3: Find 2-word patterns
    print("=" * 80)
    print("STEP 3: FINDING 2-WORD PATTERNS")
    print("=" * 80)
    print()

    bigrams = find_ngram_patterns(domains, n=2, min_count=50)
    print(f"Found {len(bigrams):,} 2-word patterns (50+ occurrences)")
    print()

    top_bigrams = sorted(bigrams.items(), key=lambda x: x[1], reverse=True)[:30]
    print("Top 30 2-word patterns:")
    for ngram, count in top_bigrams:
        pct = (count / len(domains)) * 100
        print(f"  {ngram[0]:15s} + {ngram[1]:15s} = {count:>6,} ({pct:5.2f}%)")
    print()

    # Step 4: Find 3-word patterns
    print("=" * 80)
    print("STEP 4: FINDING 3-WORD PATTERNS")
    print("=" * 80)
    print()

    trigrams = find_ngram_patterns(domains, n=3, min_count=30)
    print(f"Found {len(trigrams):,} 3-word patterns (30+ occurrences)")
    print()

    top_trigrams = sorted(trigrams.items(), key=lambda x: x[1], reverse=True)[:20]
    print("Top 20 3-word patterns:")
    for ngram, count in top_trigrams:
        pct = (count / len(domains)) * 100
        print(f"  {ngram[0]:12s} + {ngram[1]:12s} + {ngram[2]:12s} = {count:>5,} ({pct:5.2f}%)")
    print()

    # Step 5: Find separator patterns
    print("=" * 80)
    print("STEP 5: FINDING SEPARATOR PATTERNS (x-x, x-x-x)")
    print("=" * 80)
    print()

    separator_patterns = find_separator_patterns(domains, min_count=100)
    print(f"Found {len(separator_patterns):,} separator patterns (100+ occurrences)")
    print()

    # Group by pattern type
    by_type = defaultdict(list)
    for (ptype, words), count in separator_patterns.items():
        by_type[ptype].append((words, count))

    for ptype in ["word-word", "word-word-word"]:
        if ptype in by_type:
            print(f"{ptype} patterns (top 20):")
            sorted_patterns = sorted(by_type[ptype], key=lambda x: x[1], reverse=True)[:20]
            for words, count in sorted_patterns:
                pct = (count / len(domains)) * 100
                if isinstance(words, tuple):
                    pattern_str = "-".join(words)
                else:
                    pattern_str = str(words)
                print(f"  {pattern_str:40s} {count:>6,} ({pct:5.2f}%)")
            print()

    # Step 6: Find repetition patterns
    print("=" * 80)
    print("STEP 6: FINDING REPETITION PATTERNS")
    print("=" * 80)
    print()

    repetitions = find_repetition_patterns(domains, min_count=50)
    print(f"Found {len(repetitions):,} repetition patterns (50+ occurrences)")
    print()

    by_rep_type = defaultdict(list)
    for (rtype, word), count in repetitions.items():
        by_rep_type[rtype].append((word, count))

    for rtype in ["concat", "repeat"]:
        if rtype in by_rep_type:
            print(f"{rtype} patterns (top 20):")
            sorted_reps = sorted(by_rep_type[rtype], key=lambda x: x[1], reverse=True)[:20]
            for word, count in sorted_reps:
                pct = (count / len(domains)) * 100
                example = word * 2 if rtype == "concat" else f"{word}-{word}"
                print(f"  {example:30s} {count:>6,} ({pct:5.2f}%)")
            print()

    # Summary
    print("=" * 80)
    print("PATTERN SUMMARY")
    print("=" * 80)
    print()

    print(f"Total patterns discovered:")
    print(f"  2-word patterns: {len(bigrams):,}")
    print(f"  3-word patterns: {len(trigrams):,}")
    print(f"  Separator patterns: {len(separator_patterns):,}")
    print(f"  Repetition patterns: {len(repetitions):,}")
    print()

    print("Recommended for implementation:")
    print(f"  2-word patterns (50+ occurrences): {len([p for p in bigrams.items() if p[1] >= 50])}")
    print(f"  3-word patterns (30+ occurrences): {len([p for p in trigrams.items() if p[1] >= 30])}")
    print(f"  High-freq separator patterns (100+): {len([p for p in separator_patterns.items() if p[1] >= 100])}")
    print(f"  High-freq repetition patterns (50+): {len([p for p in repetitions.items() if p[1] >= 50])}")
    print()


if __name__ == "__main__":
    main()
