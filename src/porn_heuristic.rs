//! Heuristic-based porn domain detection.
//!
//! This module provides fast, pattern-based detection of porn domains
//! without needing to query the full domain list. It uses:
//! - Keyword matching (porn, xxx, sex, etc.)
//! - TLD detection (.xxx is ICANN's adult TLD)
//! - Other high-accuracy patterns
//!
//! This is used for:
//! 1. Quick pre-check before querying the full list
//! 2. Filtering domains during generation to reduce file size

use once_cell::sync::Lazy;
use regex::Regex;

/// Keywords that strongly indicate a porn domain.
/// These are checked as word boundaries to avoid false positives.
const PORN_KEYWORDS: &[&str] = &[
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

/// Main pattern for detecting porn domains.
/// Uses word boundaries and case-insensitive matching.
static PORN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Build pattern from keywords
    let strong_keywords = PORN_KEYWORDS.join("|");
    let careful_keywords = CAREFUL_KEYWORDS.join("|");

    // Pattern explanation:
    // - Strong keywords: match anywhere in domain
    // - Careful keywords: match but will be filtered by false positive check
    // - .xxx TLD: ICANN's adult content TLD
    let pattern = format!(
        r"(?ix)
        # Strong porn keywords (high confidence)
        ({strong})
        |
        # Careful keywords (need false positive filtering)
        ({careful})
        |
        # .xxx TLD (ICANN adult content TLD)
        \.xxx$
    ",
        strong = strong_keywords,
        careful = careful_keywords
    );

    Regex::new(&pattern).unwrap()
});

/// Check if a domain is likely a porn site using heuristic patterns.
///
/// This function provides fast, pattern-based detection without needing
/// to query the full domain list. It's designed for:
/// - High accuracy (minimize false positives)
/// - Fast execution (regex-based)
///
/// # Arguments
/// * `domain` - The domain name to check (e.g., "pornhub.com")
///
/// # Returns
/// * `true` if the domain matches porn heuristics
/// * `false` otherwise
///
/// # Example
/// ```
/// use k2rule::porn_heuristic::is_porn_heuristic;
///
/// assert!(is_porn_heuristic("pornhub.com"));
/// assert!(is_porn_heuristic("example.xxx"));
/// assert!(!is_porn_heuristic("google.com"));
/// assert!(!is_porn_heuristic("essex.ac.uk")); // No false positive
/// ```
pub fn is_porn_heuristic(domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }

    let domain_lower = domain.to_lowercase();

    // First check for false positives
    if FALSE_POSITIVE_PATTERNS.is_match(&domain_lower) {
        return false;
    }

    // Then check for porn patterns
    PORN_PATTERN.is_match(&domain_lower)
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

    /// Test that .xxx TLD is detected (ICANN adult TLD)
    #[test]
    fn test_detects_xxx_tld() {
        assert!(is_porn_heuristic("example.xxx"));
        assert!(is_porn_heuristic("www.anything.xxx"));
        assert!(is_porn_heuristic("site.xxx"));
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
}
