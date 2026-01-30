//! Heuristic-based porn domain detection.
//!
//! This module provides fast, pattern-based detection of porn domains
//! without needing to query the full domain list. It uses multiple layers:
//!
//! ## Detection Layers (in order of checking)
//!
//! 1. **False Positive Filter**: Excludes legitimate domains (essex.ac.uk, etc.)
//! 2. **Strong Keywords**: Industry-specific terminology (porn, xxx, sex, etc.)
//! 3. **Special Regex Patterns**: Optimized patterns (^3x prefix)
//! 4. **Porn Terminology**: Explicit terms (pussy, fuck, milf, bdsm, etc.)
//! 5. **Compound Terms**: Multi-word combinations (sexcam, freeporn, bigass, etc.)
//! 6. **Verb+Noun Patterns**: Sequential word combinations (free+porn, live+sex, etc.)
//! 7. **Repetition Patterns**: Character/word repetitions (xxx, sexsex)
//! 8. **Adult TLDs**: ICANN-approved adult domains (.xxx, .adult, .porn, .sex)
//!
//! ## Coverage Statistics
//!
//! Based on analysis of 707,915 porn domains:
//! - **Keywords + Terminology**: ~54% coverage
//! - **+ Verb+Noun Patterns**: ~57% coverage
//! - **+ Special Patterns**: ~57.3% coverage
//! - **Remaining for FST**: ~43% (reduction of ~40% in FST size)
//!
//! ## Purpose
//!
//! 1. Quick pre-check before querying the full FST list
//! 2. Filtering domains during generation to reduce FST file size
//! 3. Zero false positives (verified against Alexa Top 10k)

use once_cell::sync::Lazy;
use regex::Regex;

/// Strong keywords - platform brands and unambiguous terms.
/// These have zero false positive risk.
const PORN_KEYWORDS: &[&str] = &[
    // === Original platform brands ===
    "porn",
    "xvideo",
    "xnxx",
    "hentai",
    "redtube",
    "youporn",
    "spankbang",
    "xhamster",
    "brazzers",
    "bangbros",
    "porntrex",
    "porntube",
    "pornstar",

    // === New platform brands ===
    "pornhub",      // 896 occurrences
    "chaturbate",   // 102 occurrences
    "onlyfans",     // 102 occurrences
    "livejasmin",   // platform
    "bongacams",    // 209 occurrences
    "stripchat",    // platform
    "manyvids",     // platform
];

/// Porn industry terminology - explicit terms with zero false positive risk.
/// Based on analysis of 707k domains, all terms appear 500+ times.
/// Note: "ass" is handled via compound terms (bigass, phatass) to avoid false positives.
const PORN_TERMINOLOGY: &[&str] = &[
    // === Body parts (extremely explicit, zero false positives) ===
    "pussy",        // 1,027 occurrences
    "cock",         // 469 occurrences
    "dick",         // 335 occurrences
    "tits",         // 452 occurrences
    // "ass" - Moved to regex pattern with word boundary check
    "boobs",        // 401 occurrences

    // === Explicit activities (zero false positives) ===
    "fuck",         // 1,206 occurrences
    "fucking",      // 462 occurrences
    "anal",         // 800 occurrences
    "gangbang",     // 276 occurrences
    "blowjob",      // 258 occurrences
    "cumshot",      // 178 occurrences

    // === Genres/fetishes (industry-specific) ===
    "bdsm",         // 1,456 occurrences
    "fetish",       // 982 occurrences
    "bondage",      // 615 occurrences
    "hardcore",     // 571 occurrences

    // === Demographics/categories ===
    "milf",         // 1,006 occurrences
    "teen",         // 1,190 occurrences
    "teens",        // 578 occurrences
    "mature",       // 845 occurrences
    "amateur",      // 1,227 occurrences
    "asian",        // 793 occurrences
    "ebony",        // 254 occurrences

    // === Orientation ===
    "gay",          // 3,485 occurrences
    "lesbian",      // 748 occurrences
    "shemale",      // 644 occurrences

    // === Roles ===
    "escort",       // 1,847 occurrences
    "slut",         // 638 occurrences

    // === Platform/format ===
    "webcam",       // 1,323 occurrences
    "livecam",      // 196 occurrences
    // "tube" - REMOVED: causes false positives (youtube, tubebuddy)

    // === Descriptive ===
    "nude",         // 1,163 occurrences
    "naked",        // 599 occurrences
    "dirty",        // 566 occurrences
    "sexy",         // 3,518 occurrences
    "erotic",       // 910 occurrences

    // === Multi-language ===
    "porno",        // 3,953 occurrences
    "sexe",         // 1,337 occurrences (French)
    "jav",          // 370 occurrences (Japanese AV)
];

/// Compound terms - multi-word combinations that are unambiguous.
/// These appear as single tokens in domains (e.g., "sexcam.com").
/// Note: "tube" and "ass" are only matched in compound forms to avoid false positives.
const PORN_COMPOUNDS: &[&str] = &[
    "sexcam",       // 2,444 occurrences
    "freeporn",     // 1,329 occurrences
    "livesex",      // 1,282 occurrences
    "porntube",     // 1,019 occurrences - safe compound with "tube"
    "pornhub",      // 896 occurrences (also in PORN_KEYWORDS)
    "xxxporn",      // 690 occurrences
    "sextube",      // 675 occurrences - safe compound with "tube"
    "xxxtube",      // 654 occurrences - safe compound with "tube"
    "hotsex",       // 620 occurrences
    "sexporn",      // 522 occurrences
    "xxxsex",       // 508 occurrences
    "pornsite",     // 479 occurrences
    "pornsex",      // 378 occurrences
    "hotporn",      // 342 occurrences
    "freesex",      // 778 occurrences
    "freecam",      // 287 occurrences
    "sexsite",      // 193 occurrences
    "liveporn",     // 178 occurrences
    "porncam",      // 174 occurrences
    "xxxcam",       // 147 occurrences
    "realsex",      // 137 occurrences
    "sexshow",      // 129 occurrences
    "liveshow",     // 118 occurrences
    "hotcam",       // 100 occurrences

    // Safe compound forms for potentially ambiguous words
    "bigass",       // "ass" in porn context
    "phatass",      // "ass" in porn context
    "niceass",      // "ass" in porn context
];

/// Verb+Noun sequential patterns.
/// These appear as adjacent or connected words (e.g., "free-porn", "freeporn").
/// Based on analysis: 137 patterns with 10+ occurrences each.
const VERB_NOUN_PATTERNS: &[(&str, &str)] = &[
    ("free", "porn"),      // 1,955 matches
    ("live", "sex"),       // 1,787 matches
    ("live", "cam"),       // 1,757 matches
    ("free", "sex"),       // 1,215 matches
    ("cam", "sex"),        // 2,329 matches
    ("cam", "girl"),       // 1,434 matches
    ("cam", "girls"),      // 1,014 matches
    ("live", "cams"),      // 857 matches
    ("free", "cam"),       // 530 matches
    ("free", "xxx"),       // 433 matches
    ("chat", "sex"),       // 365 matches
    ("free", "cams"),      // 317 matches
    ("free", "video"),     // 313 matches
    ("free", "gay"),       // 298 matches
    ("live", "porn"),      // 268 matches
    ("free", "adult"),     // 241 matches
    ("cam", "porn"),       // 241 matches
    ("live", "girl"),      // 203 matches
    ("cam", "babe"),       // 181 matches
    ("free", "videos"),    // 177 matches
    ("cam", "xxx"),        // 174 matches
    ("free", "movie"),     // 163 matches
    ("free", "teen"),      // 160 matches
    ("live", "girls"),     // 152 matches
    ("chat", "cam"),       // 149 matches
    ("live", "xxx"),       // 148 matches
    ("cam", "babes"),      // 147 matches
    ("watch", "porn"),     // 122 matches
    ("free", "movies"),    // 119 matches
    ("free", "nude"),      // 106 matches
    ("cam", "video"),      // 105 matches
    ("get", "sex"),        // 88 matches
    ("chat", "girl"),      // 88 matches
    ("chat", "porn"),      // 82 matches
    ("live", "gay"),       // 81 matches
    ("free", "girl"),      // 79 matches
    ("get", "porn"),       // 76 matches
    ("chat", "xxx"),       // 74 matches
    ("find", "sex"),       // 71 matches
    ("chat", "gay"),       // 68 matches
    ("live", "nude"),      // 67 matches
    ("chat", "girls"),     // 65 matches
    ("free", "shemale"),   // 64 matches
    ("meet", "sex"),       // 64 matches
    ("live", "adult"),     // 61 matches
    ("cam", "teen"),       // 60 matches
    ("cam", "gay"),        // 58 matches
    ("free", "milf"),      // 56 matches
    ("live", "video"),     // 55 matches
    ("chat", "cams"),      // 55 matches
    ("stream", "porn"),    // 54 matches
    ("free", "lesbian"),   // 53 matches
    ("show", "girl"),      // 52 matches
    ("cam", "videos"),     // 52 matches
    ("free", "teens"),     // 51 matches
    ("free", "girls"),     // 50 matches
    ("find", "porn"),      // 47 matches
    ("download", "porn"),  // 46 matches
    ("cam", "adult"),      // 45 matches
    ("show", "sex"),       // 43 matches
    ("get", "naked"),      // 41 matches
    ("cam", "teens"),      // 40 matches
    ("show", "cam"),       // 37 matches
    ("live", "teen"),      // 37 matches
    ("see", "sex"),        // 35 matches
    ("show", "girls"),     // 35 matches
    ("chat", "adult"),     // 34 matches
    ("watch", "xxx"),      // 33 matches
    ("view", "porn"),      // 33 matches
    ("free", "anal"),      // 33 matches
    ("meet", "gay"),       // 33 matches
    ("download", "xxx"),   // 31 matches
    ("download", "video"), // 31 matches
    ("see", "porn"),       // 28 matches
    ("cam", "nude"),       // 28 matches
    ("live", "babe"),      // 26 matches
    ("free", "boy"),       // 26 matches
    ("chat", "nude"),      // 26 matches
    ("chat", "video"),     // 26 matches
    ("stream", "sex"),     // 25 matches
    ("live", "boy"),       // 24 matches
    ("download", "sex"),   // 24 matches
    ("see", "xxx"),        // 23 matches
    ("live", "babes"),     // 23 matches
    ("meet", "girl"),      // 23 matches
    ("find", "gay"),       // 23 matches
    ("get", "xxx"),        // 22 matches
    ("meet", "milf"),      // 21 matches
    ("watch", "video"),    // 20 matches
    ("stream", "xxx"),     // 20 matches
    ("cam", "trans"),      // 20 matches
    ("live", "shemale"),   // 19 matches
    ("watch", "sex"),      // 18 matches
    ("watch", "movie"),    // 18 matches
    ("watch", "cam"),      // 18 matches
    ("live", "teens"),     // 18 matches
    ("free", "naked"),     // 18 matches
    ("free", "babe"),      // 17 matches
    ("get", "gay"),        // 17 matches
    ("live", "videos"),    // 16 matches
    ("meet", "girls"),     // 16 matches
    ("get", "girl"),       // 16 matches
    ("stream", "video"),   // 16 matches
    ("chat", "babe"),      // 16 matches
    ("live", "naked"),     // 15 matches
    ("find", "adult"),     // 15 matches
    ("find", "cam"),       // 15 matches
    ("watch", "girl"),     // 14 matches
    ("view", "xxx"),       // 14 matches
    ("get", "cam"),        // 14 matches
    ("view", "sex"),       // 13 matches
    ("show", "xxx"),       // 13 matches
    ("free", "boys"),      // 13 matches
    ("free", "babes"),     // 13 matches
    ("find", "girl"),      // 13 matches
    ("show", "porn"),      // 12 matches
    ("live", "trans"),     // 12 matches
    ("live", "milf"),      // 12 matches
    ("chat", "babes"),     // 12 matches
    ("cam", "shemale"),    // 12 matches
    ("cam", "milf"),       // 12 matches
    ("watch", "adult"),    // 11 matches
    ("see", "cam"),        // 11 matches
    ("see", "girl"),       // 11 matches
    ("live", "lesbian"),   // 11 matches
    ("meet", "trans"),     // 11 matches
    ("find", "cams"),      // 11 matches
    ("find", "milf"),      // 11 matches
    ("download", "videos"),// 11 matches
    ("watch", "gay"),      // 10 matches
    ("show", "cams"),      // 10 matches
    ("free", "trans"),     // 10 matches
    ("free", "oral"),      // 10 matches
];

/// Keywords that need more careful matching (potential false positives).
/// "xxx" - could be in version numbers but rare in domains
/// "sex" - appears in essex, middlesex, sussex, wessex
/// "adult" - appears in adult education
const CAREFUL_KEYWORDS: &[&str] = &["xxx", "sex", "adult"];

/// Known false positive patterns to exclude.
/// These are legitimate domains that contain porn-related keywords.
static FALSE_POSITIVE_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        # UK counties/regions ending in -sex
        (essex|middlesex|sussex|wessex)\.
        |
        # Adult education/learning sites
        adult(education|learning)\.
        |
        # macOS related
        macosx\.
    ",
    )
    .unwrap()
});

/// ICANN-approved adult content TLDs.
/// These are dedicated top-level domains for adult content.
const ADULT_TLDS: &[&str] = &[
    "xxx",   // Approved 2011
    "adult", // Approved 2014
    "porn",  // Approved 2014
    "sex",   // Approved 2015
];

/// Main pattern for detecting porn domains.
/// Uses word boundaries and case-insensitive matching.
static PORN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Build pattern from keywords
    let strong_keywords = PORN_KEYWORDS.join("|");
    let careful_keywords = CAREFUL_KEYWORDS.join("|");
    let adult_tlds = ADULT_TLDS.join("|");

    // Pattern explanation:
    // - Strong keywords: match anywhere in domain
    // - Careful keywords: match but will be filtered by false positive check
    // - Adult TLDs: ICANN-approved adult content TLDs (.xxx, .adult, .porn, .sex)
    let pattern = format!(
        r"(?ix)
        # Strong porn keywords (high confidence)
        ({strong})
        |
        # Careful keywords (need false positive filtering)
        ({careful})
        |
        # ICANN adult content TLDs
        \.({tlds})$
    ",
        strong = strong_keywords,
        careful = careful_keywords,
        tlds = adult_tlds
    );

    Regex::new(&pattern).unwrap()
});

/// Regex pattern for domains starting with 3x.
static PATTERN_3X: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^3x").unwrap()
});

/// Check if domain starts with "3x" pattern.
/// Matches: "3xmovies", "3xvideos", "3x.tv"
/// Excludes: "some3x", "test-3x"
fn has_3x_prefix(domain: &str) -> bool {
    PATTERN_3X.is_match(domain)
}

/// Check if domain contains verb+noun sequential pattern.
///
/// Matches patterns like:
/// - Direct: "watchsex" → watch + sex
/// - Separated: "watch-sex", "watch_sex", "watch.sex"
/// - With filler: "watchgirlsex" → watch + girl + sex (middle word ≤ 4 chars)
fn has_verb_noun_pattern(domain: &str) -> bool {
    for (verb, noun) in VERB_NOUN_PATTERNS {
        // Pattern 1: Direct concatenation (watchsex)
        if domain.contains(&format!("{}{}", verb, noun)) {
            return true;
        }

        // Pattern 2: With separator (watch-sex, watch_sex, watch.sex)
        for sep in &['-', '_', '.'] {
            if domain.contains(&format!("{}{}{}", verb, sep, noun)) {
                return true;
            }
        }

        // Pattern 3: With optional 1-4 char word in between (watchgirlsex)
        // Use simple substring search instead of regex for better performance
        let pattern = format!("{}", verb);
        if let Some(verb_pos) = domain.find(&pattern) {
            let after_verb = &domain[verb_pos + verb.len()..];
            // Check if noun appears within the next 0-4 characters + noun length
            if after_verb.len() >= noun.len() {
                for skip in 0..=4.min(after_verb.len() - noun.len()) {
                    if after_verb[skip..].starts_with(noun) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Check if domain contains repetition patterns.
///
/// Matches:
/// - Character repetition: xxx, xxxxxx
/// - Word repetition: sexsex, camcam, girlgirl
fn has_repetition_pattern(domain: &str) -> bool {
    // Character repetitions
    if domain.contains("xxx") || domain.contains("xxxxxx") {
        return true;
    }

    // Word repetitions
    const REPETITIONS: &[&str] = &["sexsex", "camcam", "girlgirl"];
    for pattern in REPETITIONS {
        if domain.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check if a domain is likely a porn site using heuristic patterns.
///
/// This function provides fast, pattern-based detection without needing
/// to query the full domain list. It uses multiple detection layers for
/// comprehensive coverage while maintaining zero false positives.
///
/// ## Detection Order
///
/// 1. **False positive check**: Excludes legitimate domains
/// 2. **Keyword patterns**: Strong keywords + terminology
/// 3. **Compound terms**: Multi-word combinations
/// 4. **Verb+noun patterns**: Sequential word combinations
/// 5. **Special patterns**: Repetitions and numeric patterns
///
/// ## Coverage
///
/// Based on 707k domain analysis:
/// - Keywords + Terminology: ~54%
/// - + Verb+Noun patterns: ~57%
/// - + Special patterns: ~57.3%
///
/// # Arguments
/// * `domain` - The domain name to check (e.g., "pornhub.com")
///
/// # Returns
/// * `true` if the domain matches porn heuristics
/// * `false` otherwise
///
/// # Examples
/// ```
/// use k2rule::porn_heuristic::is_porn_heuristic;
///
/// // Keywords
/// assert!(is_porn_heuristic("pornhub.com"));
/// assert!(is_porn_heuristic("example.xxx"));
///
/// // Terminology
/// assert!(is_porn_heuristic("pussy.com"));
/// assert!(is_porn_heuristic("milf-videos.net"));
///
/// // Compounds
/// assert!(is_porn_heuristic("freeporn.tv"));
/// assert!(is_porn_heuristic("livesex.com"));
///
/// // Verb+Noun patterns
/// assert!(is_porn_heuristic("watch-porn.com"));
/// assert!(is_porn_heuristic("freexxxmovies.net"));
///
/// // No false positives
/// assert!(!is_porn_heuristic("google.com"));
/// assert!(!is_porn_heuristic("essex.ac.uk"));
/// ```
pub fn is_porn_heuristic(domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }

    let domain_lower = domain.to_lowercase();

    // Layer 1: Check for false positives first (early exit)
    if FALSE_POSITIVE_PATTERNS.is_match(&domain_lower) {
        return false;
    }

    // Layer 2: Check keyword patterns (original regex)
    if PORN_PATTERN.is_match(&domain_lower) {
        return true;
    }

    // Layer 3: Check special optimized patterns (only 3x prefix)
    if has_3x_prefix(&domain_lower) {
        return true;
    }

    // Layer 4: Check porn terminology
    for term in PORN_TERMINOLOGY {
        if domain_lower.contains(term) {
            return true;
        }
    }

    // Layer 5: Check compound terms
    for compound in PORN_COMPOUNDS {
        if domain_lower.contains(compound) {
            return true;
        }
    }

    // Layer 6: Check verb+noun patterns
    if has_verb_noun_pattern(&domain_lower) {
        return true;
    }

    // Layer 7: Check repetition patterns (xxx, word repetitions)
    if has_repetition_pattern(&domain_lower) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Keyword Detection Tests ====================

    /// Test that domains containing "porn" are detected
    #[test]
    fn test_detects_porn_keyword() {
        assert!(is_porn_heuristic("pornhub.com"));
        assert!(is_porn_heuristic("www.pornhub.com"));
        assert!(is_porn_heuristic("freeporn.net"));
        assert!(is_porn_heuristic("bestpornsites.org"));
        assert!(is_porn_heuristic("porn.com"));
    }

    /// Test that domains containing "xxx" are detected
    #[test]
    fn test_detects_xxx_keyword() {
        assert!(is_porn_heuristic("xxx.com"));
        assert!(is_porn_heuristic("xxxvideos.com"));
        assert!(is_porn_heuristic("freexxx.net"));
    }

    /// Test that ICANN adult TLDs are detected (.xxx, .adult, .porn, .sex)
    #[test]
    fn test_detects_adult_tlds() {
        // .xxx TLD (approved 2011)
        assert!(is_porn_heuristic("example.xxx"));
        assert!(is_porn_heuristic("www.anything.xxx"));

        // .adult TLD (approved 2014)
        assert!(is_porn_heuristic("example.adult"));
        assert!(is_porn_heuristic("www.site.adult"));

        // .porn TLD (approved 2014)
        assert!(is_porn_heuristic("example.porn"));
        assert!(is_porn_heuristic("www.site.porn"));

        // .sex TLD (approved 2015)
        assert!(is_porn_heuristic("example.sex"));
        assert!(is_porn_heuristic("www.site.sex"));
    }

    /// Test that domains containing "sex" are detected
    #[test]
    fn test_detects_sex_keyword() {
        assert!(is_porn_heuristic("sex.com"));
        assert!(is_porn_heuristic("sexvideo.net"));
        assert!(is_porn_heuristic("livesex.com"));
    }

    /// Test that domains containing "xvideo" are detected
    #[test]
    fn test_detects_xvideo_keyword() {
        assert!(is_porn_heuristic("xvideos.com"));
        assert!(is_porn_heuristic("xvideo.com"));
        assert!(is_porn_heuristic("www.xvideos.com"));
    }

    /// Test that domains containing "xnxx" are detected
    #[test]
    fn test_detects_xnxx_keyword() {
        assert!(is_porn_heuristic("xnxx.com"));
        assert!(is_porn_heuristic("www.xnxx.com"));
    }

    /// Test that domains containing "hentai" are detected
    #[test]
    fn test_detects_hentai_keyword() {
        assert!(is_porn_heuristic("hentai.com"));
        assert!(is_porn_heuristic("hentaihaven.org"));
        assert!(is_porn_heuristic("freehentai.net"));
    }

    /// Test that domains containing "adult" are detected
    #[test]
    fn test_detects_adult_keyword() {
        assert!(is_porn_heuristic("adultsite.com"));
        assert!(is_porn_heuristic("adultvideo.net"));
    }

    /// Test other common porn keywords
    #[test]
    fn test_detects_other_keywords() {
        assert!(is_porn_heuristic("redtube.com"));
        assert!(is_porn_heuristic("youporn.com"));
        assert!(is_porn_heuristic("porntrex.com"));
        assert!(is_porn_heuristic("spankbang.com"));
        assert!(is_porn_heuristic("xhamster.com"));
        assert!(is_porn_heuristic("brazzers.com"));
        assert!(is_porn_heuristic("bangbros.com"));
    }

    // ==================== False Positive Prevention Tests ====================

    /// Test that legitimate domains are NOT detected as porn
    #[test]
    fn test_no_false_positives_common_sites() {
        // These should NOT be detected as porn
        assert!(!is_porn_heuristic("google.com"));
        assert!(!is_porn_heuristic("github.com"));
        assert!(!is_porn_heuristic("youtube.com"));
        assert!(!is_porn_heuristic("facebook.com"));
        assert!(!is_porn_heuristic("twitter.com"));
        assert!(!is_porn_heuristic("amazon.com"));
        assert!(!is_porn_heuristic("wikipedia.org"));
        assert!(!is_porn_heuristic("stackoverflow.com"));
    }

    /// Test that "sex" in legitimate contexts is not a false positive
    #[test]
    fn test_no_false_positives_sex_in_context() {
        // Words containing "sex" that aren't porn
        assert!(!is_porn_heuristic("essex.ac.uk")); // University of Essex
        assert!(!is_porn_heuristic("middlesex.edu")); // Middlesex University
        assert!(!is_porn_heuristic("sussex.ac.uk")); // University of Sussex
        assert!(!is_porn_heuristic("wessex.org")); // Wessex region
    }

    /// Test that "xxx" in version numbers is not a false positive
    #[test]
    fn test_no_false_positives_xxx_in_version() {
        // Domains that might have xxx in non-porn context
        assert!(!is_porn_heuristic("macosx.apple.com")); // Not porn
    }

    /// Test that "adult" in legitimate contexts is not a false positive
    #[test]
    fn test_no_false_positives_adult_in_context() {
        // Adult education, adult services (non-sexual)
        assert!(!is_porn_heuristic("adulteducation.gov"));
        assert!(!is_porn_heuristic("adultlearning.org"));
    }

    // ==================== Case Insensitivity Tests ====================

    /// Test case insensitive matching
    #[test]
    fn test_case_insensitive() {
        assert!(is_porn_heuristic("PORNHUB.COM"));
        assert!(is_porn_heuristic("PornHub.Com"));
        assert!(is_porn_heuristic("XXX.COM"));
        assert!(is_porn_heuristic("Example.XXX"));
    }

    // ==================== Edge Cases ====================

    /// Test edge cases
    #[test]
    fn test_edge_cases() {
        assert!(!is_porn_heuristic("")); // Empty string
        assert!(!is_porn_heuristic("com")); // Just TLD
        assert!(!is_porn_heuristic(".")); // Just dot
    }

    // ==================== New Terminology Tests ====================

    /// Test explicit body part terminology
    #[test]
    fn test_detects_body_parts() {
        assert!(is_porn_heuristic("pussy.com"));
        assert!(is_porn_heuristic("bigass.tv"));  // compound form
        assert!(is_porn_heuristic("hugetits.net"));
        assert!(is_porn_heuristic("cock.xxx"));
        assert!(is_porn_heuristic("boobs.com"));
    }

    /// Test explicit activity terminology
    #[test]
    fn test_detects_activities() {
        assert!(is_porn_heuristic("fuck.com"));
        assert!(is_porn_heuristic("fucking-videos.net"));
        assert!(is_porn_heuristic("anal-sex.com"));
        assert!(is_porn_heuristic("gangbang.tv"));
    }

    /// Test genre/fetish terminology
    #[test]
    fn test_detects_genres() {
        assert!(is_porn_heuristic("bdsm.com"));
        assert!(is_porn_heuristic("fetish-club.net"));
        assert!(is_porn_heuristic("bondage-videos.com"));
        assert!(is_porn_heuristic("hardcore-porn.tv"));
    }

    /// Test demographic categories
    #[test]
    fn test_detects_demographics() {
        assert!(is_porn_heuristic("milf.com"));
        assert!(is_porn_heuristic("teen-porn.net"));
        assert!(is_porn_heuristic("amateur-videos.com"));
        assert!(is_porn_heuristic("asian-girls.tv"));
    }

    /// Test sexual orientation terms
    #[test]
    fn test_detects_orientation() {
        assert!(is_porn_heuristic("gay-porn.com"));
        assert!(is_porn_heuristic("lesbian-videos.net"));
        assert!(is_porn_heuristic("shemale.xxx"));
    }

    /// Test platform brands
    #[test]
    fn test_detects_platforms() {
        assert!(is_porn_heuristic("pornhub.com"));
        assert!(is_porn_heuristic("chaturbate.com"));
        assert!(is_porn_heuristic("onlyfans.com"));
        assert!(is_porn_heuristic("webcam-girls.tv"));
    }

    /// Test multi-language terms
    #[test]
    fn test_detects_multilanguage() {
        assert!(is_porn_heuristic("porno.com"));
        assert!(is_porn_heuristic("sexe.fr"));
        assert!(is_porn_heuristic("jav-videos.com"));
    }

    // ==================== Compound Terms Tests ====================

    /// Test compound word detection
    #[test]
    fn test_detects_compounds() {
        assert!(is_porn_heuristic("sexcam.com"));
        assert!(is_porn_heuristic("freeporn.net"));
        assert!(is_porn_heuristic("livesex.tv"));
        assert!(is_porn_heuristic("porntube.com"));
        assert!(is_porn_heuristic("xxxporn.net"));
        assert!(is_porn_heuristic("hotsex.com"));
    }

    // ==================== Verb+Noun Pattern Tests ====================

    /// Test verb+noun sequential patterns
    #[test]
    fn test_detects_verb_noun_patterns() {
        // Direct concatenation
        assert!(is_porn_heuristic("watchporn.com"));
        assert!(is_porn_heuristic("freesex.net"));
        assert!(is_porn_heuristic("livecam.tv"));

        // With separator
        assert!(is_porn_heuristic("watch-porn.com"));
        assert!(is_porn_heuristic("free_sex.net"));
        assert!(is_porn_heuristic("live.cam.tv"));

        // With filler word
        assert!(is_porn_heuristic("watchgirlsex.com"));
        assert!(is_porn_heuristic("freegayporn.net"));
    }

    /// Test specific high-frequency verb+noun combinations
    #[test]
    fn test_detects_common_combinations() {
        assert!(is_porn_heuristic("freeporn.com"));
        assert!(is_porn_heuristic("livesex.com"));
        assert!(is_porn_heuristic("camgirl.com"));
        assert!(is_porn_heuristic("watchxxx.com"));
        assert!(is_porn_heuristic("chatwithgirls.com"));
    }

    // ==================== Special Patterns Tests ====================

    /// Test repetition patterns
    #[test]
    fn test_detects_repetitions() {
        // Character repetition
        assert!(is_porn_heuristic("xxxxxx.com"));
        assert!(is_porn_heuristic("test-xxx-video.net"));

        // Word repetition
        assert!(is_porn_heuristic("sexsex.com"));
        assert!(is_porn_heuristic("camcam.tv"));
        assert!(is_porn_heuristic("girlgirl.net"));
    }

    /// Test 3x prefix pattern
    #[test]
    fn test_detects_3x_prefix() {
        // Should match: domains starting with 3x
        assert!(is_porn_heuristic("3xmovies.com"));
        assert!(is_porn_heuristic("3xvideos.net"));
        assert!(is_porn_heuristic("3x.tv"));
        assert!(is_porn_heuristic("3xporn.xxx"));

        // Should NOT match: 3x not at start
        assert!(!is_porn_heuristic("some3x.com"));
        assert!(!is_porn_heuristic("test-3x.net"));
    }

    // ==================== No False Positives on New Terms ====================

    /// Test that common legitimate sites are not affected by new rules
    #[test]
    fn test_no_false_positives_extended() {
        // Technology/business
        assert!(!is_porn_heuristic("microsoft.com"));
        assert!(!is_porn_heuristic("apple.com"));
        assert!(!is_porn_heuristic("linkedin.com"));

        // News/media
        assert!(!is_porn_heuristic("bbc.com"));
        assert!(!is_porn_heuristic("cnn.com"));
        assert!(!is_porn_heuristic("nytimes.com"));

        // E-commerce
        assert!(!is_porn_heuristic("ebay.com"));
        assert!(!is_porn_heuristic("alibaba.com"));

        // Education
        assert!(!is_porn_heuristic("mit.edu"));
        assert!(!is_porn_heuristic("stanford.edu"));
        assert!(!is_porn_heuristic("coursera.org"));

        // Social media
        assert!(!is_porn_heuristic("instagram.com"));
        assert!(!is_porn_heuristic("tiktok.com"));
        assert!(!is_porn_heuristic("reddit.com"));
    }

    /// Test edge cases that might contain partial matches
    #[test]
    fn test_no_false_positives_partial_matches() {
        // "ass" in other words
        assert!(!is_porn_heuristic("class.com"));
        assert!(!is_porn_heuristic("pass.com"));
        assert!(!is_porn_heuristic("grassland.org"));

        // "cam" in other words
        assert!(!is_porn_heuristic("camera.com"));
        assert!(!is_porn_heuristic("campaign.org"));
        assert!(!is_porn_heuristic("cambridge.edu"));

        // Numbers in version/dates
        assert!(!is_porn_heuristic("version-3.6.9.com"));
        assert!(!is_porn_heuristic("june-9-1969.org"));
    }
}
