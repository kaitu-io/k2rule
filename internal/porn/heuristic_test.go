package porn

import "testing"

func TestIsPornHeuristic(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		// Strong keywords
		{"pornhub", "pornhub.com", true},
		{"xvideos", "xvideos.com", true},
		{"porn keyword", "freeporn.net", true},

		// Terminology
		{"explicit term 1", "pussy.com", true},
		{"explicit term 2", "milf-videos.net", true},
		{"explicit term 3", "fuck.xxx", true},

		// Compounds
		{"compound 1", "sexcam.tv", true},
		{"compound 2", "livesex.com", true},
		{"compound 3", "freeporn.org", true},

		// Verb+noun patterns
		{"pattern 1", "watch-porn.com", true},
		{"pattern 2", "freesex.net", true},
		{"pattern 3", "livecam.tv", true},

		// Repetitions
		{"xxx repetition", "xxx.com", true},
		{"word repetition", "sexsex.com", true},

		// 3x prefix
		{"3x prefix", "3xmovies.com", true},
		{"3x prefix 2", "3xvids.net", true},

		// Adult TLDs
		{"adult tld 1", "example.xxx", true},
		{"adult tld 2", "test.porn", true},
		{"adult tld 3", "site.adult", true},
		{"adult tld 4", "demo.sex", true},

		// False positives (should NOT match)
		{"google", "google.com", false},
		{"microsoft", "microsoft.com", false},
		{"essex university", "essex.ac.uk", false},
		{"sussex", "sussex.edu", false},
		{"adult education", "adulteducation.org", false},
		{"macosx", "macosx.com", false},

		// Edge cases
		{"empty", "", false},
		{"single char", "a", false},
		{"numbers only", "123.456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPornHeuristic(tt.domain); got != tt.want {
				t.Errorf("IsPornHeuristic(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsPornHeuristic_Subdomains(t *testing.T) {
	// Test that subdomains also match
	tests := []struct {
		domain string
		want   bool
	}{
		{"www.pornhub.com", true},
		{"mobile.xvideos.com", true},
		{"en.freeporn.net", true},
		{"www.google.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := IsPornHeuristic(tt.domain); got != tt.want {
				t.Errorf("IsPornHeuristic(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func BenchmarkIsPornHeuristic(b *testing.B) {
	domains := []string{
		"pornhub.com",
		"google.com",
		"freeporn.net",
		"microsoft.com",
		"xxx.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := domains[i%len(domains)]
		IsPornHeuristic(domain)
	}
}
