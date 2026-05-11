package vault

import (
	"testing"
)

func TestParseCheckEnvFile_Basic(t *testing.T) {
	content := "FOO=bar\nBAZ=qux\n"
	pairs := parseCheckEnvFile(content)
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0][0] != "FOO" || pairs[0][1] != "bar" {
		t.Errorf("unexpected pair: %v", pairs[0])
	}
	if pairs[1][0] != "BAZ" || pairs[1][1] != "qux" {
		t.Errorf("unexpected pair: %v", pairs[1])
	}
}

func TestParseCheckEnvFile_SkipsComments(t *testing.T) {
	content := "# this is a comment\nFOO=bar\n"
	pairs := parseCheckEnvFile(content)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0][0] != "FOO" {
		t.Errorf("unexpected key: %s", pairs[0][0])
	}
}

func TestParseCheckEnvFile_SkipsBlankLines(t *testing.T) {
	content := "\nFOO=bar\n\nBAZ=qux\n\n"
	pairs := parseCheckEnvFile(content)
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
}

func TestParseCheckEnvFile_ValueWithEquals(t *testing.T) {
	content := "TOKEN=abc=def=ghi\n"
	pairs := parseCheckEnvFile(content)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0][1] != "abc=def=ghi" {
		t.Errorf("expected value 'abc=def=ghi', got '%s'", pairs[0][1])
	}
}

func TestParseCheckEnvFile_Empty(t *testing.T) {
	pairs := parseCheckEnvFile("")
	if len(pairs) != 0 {
		t.Fatalf("expected 0 pairs, got %d", len(pairs))
	}
}

func TestParseCheckEnvFile_MalformedLineSkipped(t *testing.T) {
	content := "NOTAVALIDLINE\nFOO=bar\n"
	pairs := parseCheckEnvFile(content)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0][0] != "FOO" {
		t.Errorf("unexpected key: %s", pairs[0][0])
	}
}
