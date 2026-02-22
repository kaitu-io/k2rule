package k2rule

import (
	"os"
	"os/exec"
	"testing"
)

// TestNoRustFilesExist verifies that all Rust source code has been removed from the repository.
func TestNoRustFilesExist(t *testing.T) {
	// Verify no src/ directory (Rust source tree)
	if _, err := os.Stat("src"); !os.IsNotExist(err) {
		t.Error("src/ directory still exists — Rust code not deleted")
	}

	// Verify no Cargo.toml
	if _, err := os.Stat("Cargo.toml"); !os.IsNotExist(err) {
		t.Error("Cargo.toml still exists — Rust code not deleted")
	}

	// Verify no Cargo.lock
	if _, err := os.Stat("Cargo.lock"); !os.IsNotExist(err) {
		t.Error("Cargo.lock still exists — Rust code not deleted")
	}

	// Verify no tests/ directory (Rust-only integration tests)
	if _, err := os.Stat("tests"); !os.IsNotExist(err) {
		t.Error("tests/ directory still exists — Rust integration tests not deleted")
	}
}

// TestGoGeneratorBuilds verifies that the Go generator binary compiles successfully.
func TestGoGeneratorBuilds(t *testing.T) {
	cmd := exec.Command("go", "build", "./cmd/k2rule-gen")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./cmd/k2rule-gen failed: %v\n%s", err, out)
	}
}
