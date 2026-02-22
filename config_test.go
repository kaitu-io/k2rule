package k2rule

import (
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
				CacheDir: "/tmp/test",
				RuleURL:  "https://example.com/rules.k2r.gz",
			},
			wantErr: false,
		},
		{
			name: "valid config with RuleFile",
			config: &Config{
				CacheDir: "/tmp/test",
				RuleFile: "./rules/test.k2r.gz",
			},
			wantErr: false,
		},
		{
			name: "valid config with both empty (pure global mode)",
			config: &Config{
				CacheDir:     "/tmp/test",
				IsGlobal:     true,
				GlobalTarget: TargetProxy,
			},
			wantErr: false,
		},
		{
			name: "invalid: both RuleURL and RuleFile set",
			config: &Config{
				CacheDir: "/tmp/test",
				RuleURL:  "https://example.com/rules.k2r.gz",
				RuleFile: "./rules/test.k2r.gz",
			},
			wantErr: true,
			errMsg:  "cannot specify both RuleURL and RuleFile",
		},
		{
			name: "invalid: both GeoIPURL and GeoIPFile set",
			config: &Config{
				CacheDir:  "/tmp/test",
				GeoIPURL:  "https://example.com/geoip.mmdb.gz",
				GeoIPFile: "./geoip/test.mmdb",
			},
			wantErr: true,
			errMsg:  "cannot specify both GeoIPURL and GeoIPFile",
		},
		{
			name: "invalid: both PornURL and PornFile set",
			config: &Config{
				CacheDir: "/tmp/test",
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

func TestConfig_Validate_EmptyCacheDir(t *testing.T) {
	config := &Config{CacheDir: ""}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for empty CacheDir")
	}
	if err.Error() != "CacheDir is required" {
		t.Errorf("got %q, want %q", err.Error(), "CacheDir is required")
	}
}

func TestConfig_SetDefaults_NoCacheDirAutoFill(t *testing.T) {
	config := &Config{}
	config.SetDefaults()
	if config.CacheDir != "" {
		t.Errorf("SetDefaults() should not auto-fill CacheDir, got %q", config.CacheDir)
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
			name:   "CacheDir stays empty after SetDefaults",
			config: &Config{},
			check: func(t *testing.T, c *Config) {
				if c.CacheDir != "" {
					t.Errorf("CacheDir = %v, want empty string", c.CacheDir)
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
