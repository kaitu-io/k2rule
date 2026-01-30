#!/usr/bin/env python3
"""
Extract porn industry-specific terminology.

Focus on:
1. Industry jargon (jav, av, 3x, xxx)
2. Sexual orientation terms (gay, lesbian, trans, bi)
3. Demographic categories (milf, teen, asian, ebony)
4. Explicit body parts (pussy, cock, tits, ass)
5. Activity terms (fuck, suck, anal, oral)
6. Genre terms (hentai, bdsm, fetish, kinky)
7. Platform/format terms (cam, webcam, tube, live)
"""

import re
from collections import Counter
from typing import List, Set, Dict, Tuple


def load_domains(file_path="/tmp/porn_domains.txt") -> List[str]:
    """Load cached domain list."""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def tokenize(domain: str) -> Set[str]:
    """Extract all words from domain."""
    domain_lower = domain.lower()
    # Remove TLD
    domain_core = re.sub(r'\.[a-z0-9]+$', '', domain_lower)
    # Extract alphabetic tokens (3+ chars)
    tokens = re.findall(r'[a-z]{3,}', domain_core)
    return set(tokens)


def analyze_porn_terminology(domains: List[str]) -> Dict[str, int]:
    """Extract porn-specific terminology with frequency counts."""

    # Porn industry terminology categories
    terminology = {
        # Industry jargon
        "industry_jargon": {
            "jav", "av", "xxx", "3x", "porn", "porno", "pornstar",
            "tube", "hub", "flix", "toon", "hentai", "doujin",
        },

        # Sexual orientation
        "orientation": {
            "gay", "lesbian", "bi", "bisexual", "trans", "transgender",
            "shemale", "tranny", "ladyboy", "femboy",
        },

        # Demographic categories
        "demographics": {
            "milf", "gilf", "teen", "teens", "young", "mature",
            "asian", "ebony", "latina", "indian", "japanese", "chinese",
            "korean", "thai", "arab", "russian", "european",
            "amateur", "homemade", "college", "schoolgirl",
        },

        # Body parts (explicit)
        "body_parts": {
            "pussy", "cock", "dick", "penis", "tits", "boobs", "ass",
            "butt", "booty", "nipple", "nipples", "vagina", "clit",
            "breasts", "boobies", "titties",
        },

        # Activities (explicit)
        "activities": {
            "fuck", "fucking", "fucked", "sex", "anal", "oral", "blowjob",
            "handjob", "footjob", "rimming", "fisting", "gangbang",
            "creampie", "cumshot", "facial", "squirt", "orgasm",
            "masturbate", "masturbation", "jerk", "stroke",
        },

        # Genres/fetishes
        "genres": {
            "bdsm", "bondage", "fetish", "kinky", "domination", "submission",
            "slave", "master", "mistress", "latex", "leather", "feet",
            "footfetish", "voyeur", "exhibitionist", "cuckold", "swinger",
            "orgy", "threesome", "foursome", "group",
        },

        # Roles/archetypes
        "roles": {
            "slut", "whore", "escort", "hooker", "prostitute", "stripper",
            "dancer", "model", "pornstar", "actress", "babe", "babes",
            "girl", "girls", "boy", "boys", "daddy", "mommy",
        },

        # Platform/format
        "platform": {
            "cam", "cams", "webcam", "livecam", "chaturbate", "onlyfans",
            "live", "stream", "video", "videos", "movie", "movies",
            "clip", "clips", "photo", "photos", "pic", "pics",
        },

        # Descriptive terms
        "descriptive": {
            "hot", "sexy", "naked", "nude", "nudes", "erotic", "dirty",
            "nasty", "wild", "hardcore", "softcore", "extreme",
            "taboo", "forbidden", "private", "secret", "hidden",
        },

        # Geographic/cultural
        "geographic": {
            "tokyo", "bangkok", "amsterdam", "vegas", "california",
        },
    }

    # Flatten all terms
    all_terms = set()
    for category_terms in terminology.values():
        all_terms.update(category_terms)

    # Count occurrences
    term_counts = Counter()

    print(f"Analyzing {len(domains):,} domains for porn terminology...")
    for i, domain in enumerate(domains):
        if i % 100000 == 0:
            print(f"  Progress: {i:,}/{len(domains):,}")

        tokens = tokenize(domain)
        for token in tokens:
            if token in all_terms:
                term_counts[token] += 1

    print()
    return dict(term_counts), terminology


def find_numeric_patterns(domains: List[str]) -> Counter:
    """Find numeric patterns like 3x, 69, etc."""
    pattern_counter = Counter()

    patterns = {
        "3x": re.compile(r'\b3x\b', re.IGNORECASE),
        "69": re.compile(r'\b69\b'),
        "18+": re.compile(r'\b18\+'),
        "21+": re.compile(r'\b21\+'),
        "xxx": re.compile(r'\bxxx\b', re.IGNORECASE),
    }

    for domain in domains:
        for name, pattern in patterns.items():
            if pattern.search(domain):
                pattern_counter[name] += 1

    return pattern_counter


def find_compound_terms(domains: List[str], min_count: int = 100) -> Counter:
    """Find compound porn terms like sexshop, pornhub, etc."""
    compound_counter = Counter()

    # Common prefixes and suffixes in porn domains
    prefixes = ["sex", "porn", "xxx", "hot", "live", "free", "real", "true"]
    suffixes = ["sex", "porn", "hub", "tube", "cam", "show", "site", "zone", "land"]

    for domain in domains:
        domain_lower = domain.lower()

        # Check for prefix+suffix combinations
        for prefix in prefixes:
            for suffix in suffixes:
                compound = prefix + suffix
                if compound in domain_lower and prefix != suffix:
                    compound_counter[compound] += 1

    return Counter({term: count for term, count in compound_counter.items() if count >= min_count})


def main():
    print("=" * 80)
    print("PORN INDUSTRY TERMINOLOGY EXTRACTION")
    print("=" * 80)
    print()

    # Load domains
    domains = load_domains()
    print(f"Total domains: {len(domains):,}")
    print()

    # Analyze terminology
    term_counts, terminology = analyze_porn_terminology(domains)

    print("=" * 80)
    print("RESULTS BY CATEGORY")
    print("=" * 80)
    print()

    # Sort terms by category
    for category, terms in terminology.items():
        print(f"{category.upper().replace('_', ' ')}:")
        print("-" * 60)

        # Get counts for terms in this category
        category_counts = {term: term_counts.get(term, 0) for term in terms}
        sorted_terms = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)

        # Show all terms with their counts
        for term, count in sorted_terms:
            if count > 0:
                pct = (count / len(domains)) * 100
                print(f"  {term:20s} {count:>8,} ({pct:5.2f}%)")

        print()

    # Numeric patterns
    print("NUMERIC PATTERNS:")
    print("-" * 60)
    numeric = find_numeric_patterns(domains)
    for pattern, count in numeric.most_common():
        pct = (count / len(domains)) * 100
        print(f"  {pattern:20s} {count:>8,} ({pct:5.2f}%)")
    print()

    # Compound terms
    print("COMPOUND TERMS (100+ occurrences):")
    print("-" * 60)
    compounds = find_compound_terms(domains, min_count=100)
    for term, count in compounds.most_common(30):
        pct = (count / len(domains)) * 100
        print(f"  {term:20s} {count:>8,} ({pct:5.2f}%)")
    print()

    # Summary statistics
    print("=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print()

    total_matches = sum(1 for d in domains if any(tokenize(d) & set(term_counts.keys())))
    coverage_pct = (total_matches / len(domains)) * 100

    print(f"Total unique terms found: {len(term_counts)}")
    print(f"Domains matching at least one term: {total_matches:,} ({coverage_pct:.2f}%)")
    print()

    # Top terms overall
    print("TOP 50 TERMS (by frequency):")
    print("-" * 60)
    for term, count in sorted(term_counts.items(), key=lambda x: x[1], reverse=True)[:50]:
        pct = (count / len(domains)) * 100
        print(f"  {term:20s} {count:>8,} ({pct:5.2f}%)")
    print()

    # Recommendations
    print("=" * 80)
    print("RECOMMENDATIONS FOR HEURISTIC RULES")
    print("=" * 80)
    print()

    # High-confidence terms (500+ occurrences, zero false positive risk)
    high_conf = [(term, count) for term, count in term_counts.items() if count >= 500]
    high_conf.sort(key=lambda x: x[1], reverse=True)

    print(f"HIGH CONFIDENCE TERMS (500+ occurrences, {len(high_conf)} terms):")
    print()
    print("```rust")
    print("const PORN_TERMINOLOGY: &[&str] = &[")
    for term, count in high_conf:
        print(f'    "{term}",  // {count:,} occurrences')
    print("];")
    print("```")
    print()

    # Medium-confidence terms (100-499 occurrences)
    med_conf = [(term, count) for term, count in term_counts.items() if 100 <= count < 500]
    med_conf.sort(key=lambda x: x[1], reverse=True)

    print(f"MEDIUM CONFIDENCE TERMS (100-499 occurrences, {len(med_conf)} terms):")
    print(f"  (Recommend manual review for false positives)")
    for term, count in med_conf[:20]:
        print(f"  {term:20s} {count:>6,}")
    if len(med_conf) > 20:
        print(f"  ... and {len(med_conf) - 20} more")
    print()

    # Coverage estimation
    print("COVERAGE ESTIMATION:")
    print()

    # Current keywords
    current = {"porn", "xvideo", "xnxx", "hentai", "redtube", "youporn",
               "spankbang", "xhamster", "brazzers", "bangbros", "porntrex",
               "porntube", "pornstar", "xxx", "sex", "adult"}

    current_matches = sum(1 for d in domains if any(t in d.lower() for t in current))

    # With high-confidence terms
    all_terms = current | {term for term, _ in high_conf}
    all_matches = sum(1 for d in domains if any(t in d.lower() for t in all_terms))

    print(f"Current keywords:          {current_matches:>8,} / {len(domains):,} ({current_matches/len(domains)*100:5.2f}%)")
    print(f"+ High-conf terminology:   {all_matches:>8,} / {len(domains):,} ({all_matches/len(domains)*100:5.2f}%)")
    print(f"Improvement:               {all_matches - current_matches:>8,} domains (+{(all_matches - current_matches)/len(domains)*100:.2f}%)")
    print()


if __name__ == "__main__":
    main()
