package config

import (
	"testing"
)

func TestRejectUnsupportedProjectScope(t *testing.T) {
	cfg := Defaults()
	cfg.Project.Include = []string{"src/**"}
	if err := Validate(cfg); err == nil {
		t.Fatal("non-default project.include must be rejected")
	}
	cfg = Defaults()
	cfg.Project.Exclude = []string{"vendor/**"}
	if err := Validate(cfg); err == nil {
		t.Fatal("project.exclude must be rejected")
	}
	cfg = Defaults()
	if err := Validate(cfg); err != nil {
		t.Fatalf("default scope must validate: %v", err)
	}
}
