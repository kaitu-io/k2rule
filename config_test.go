package k2rule

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with RuleURL",
			config: &Config{
				RuleURL: "https://example.com/rules.k2r.gz",
			},
			wantErr: false,
		},
		{
			name: "valid config with RuleFile",
			config: &Config{
				RuleFile: "./rules/test.k2r.gz",
			},
			wantErr: false,
		},
		{
			name: "valid config with both empty (pure global mode)",
			config: &Config{
				IsGlobal:     true,
				GlobalTarget: TargetProxy,
			},
			wantErr: false,
		},
		{
			name: "invalid: both RuleURL and RuleFile set",
			config: &Config{
				RuleURL:  "https://example.com/rules.k2r.gz",
				RuleFile: "./rules/test.k2r.gz",
			},
			wantErr: true,
			errMsg:  "cannot specify both RuleURL and RuleFile",
		},
		{
			name: "invalid: both GeoIPURL and GeoIPFile set",
			config: &Config{
				GeoIPURL:  "https://example.com/geoip.mmdb.gz",
				GeoIPFile: "./geoip/test.mmdb",
			},
			wantErr: true,
			errMsg:  "cannot specify both GeoIPURL and GeoIPFile",
		},
		{
			name: "invalid: both PornURL and PornFile set",
			config: &Config{
				PornURL:  "https://example.com/porn.fst.gz",
				PornFile: "./porn/test.fst.gz",
			},
			wantErr: true,
			errMsg:  "cannot specify both PornURL and PornFile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error, got nil")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("Validate() error = %v, want %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		check  func(*testing.T, *Config)
	}{
		{
			name:   "sets default GlobalTarget",
			config: &Config{},
			check: func(t *testing.T, c *Config) {
				if c.GlobalTarget != TargetProxy {
					t.Errorf("GlobalTarget = %v, want %v", c.GlobalTarget, TargetProxy)
				}
			},
		},
		{
			name: "preserves existing GlobalTarget",
			config: &Config{
				GlobalTarget: TargetReject,
			},
			check: func(t *testing.T, c *Config) {
				if c.GlobalTarget != TargetReject {
					t.Errorf("GlobalTarget = %v, want %v", c.GlobalTarget, TargetReject)
				}
			},
		},
		{
			name:   "sets default CacheDir",
			config: &Config{},
			check: func(t *testing.T, c *Config) {
				homeDir, _ := os.UserHomeDir()
				expectedDir := filepath.Join(homeDir, ".cache", "k2rule")
				if c.CacheDir != expectedDir {
					t.Errorf("CacheDir = %v, want %v", c.CacheDir, expectedDir)
				}
			},
		},
		{
			name: "preserves existing CacheDir",
			config: &Config{
				CacheDir: "/custom/cache",
			},
			check: func(t *testing.T, c *Config) {
				if c.CacheDir != "/custom/cache" {
					t.Errorf("CacheDir = %v, want /custom/cache", c.CacheDir)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.SetDefaults()
			tt.check(t, tt.config)
		})
	}
}
