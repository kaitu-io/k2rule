package k2rule

import "testing"

func TestTargetString(t *testing.T) {
	tests := []struct {
		target Target
		want   string
	}{
		{TargetDirect, "DIRECT"},
		{TargetProxy, "PROXY"},
		{TargetReject, "REJECT"},
		{Target(99), "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.target.String(); got != tt.want {
				t.Errorf("Target.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Target
		wantErr bool
	}{
		{"direct lowercase", "direct", TargetDirect, false},
		{"direct uppercase", "DIRECT", TargetDirect, false},
		{"proxy lowercase", "proxy", TargetProxy, false},
		{"proxy uppercase", "PROXY", TargetProxy, false},
		{"reject lowercase", "reject", TargetReject, false},
		{"reject uppercase", "REJECT", TargetReject, false},
		{"invalid", "invalid", 0, true},
		{"empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTarget(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}
