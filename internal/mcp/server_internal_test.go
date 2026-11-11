package mcp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestScrubbingLoggerCoversErrorValues(t *testing.T) {
	var buf bytes.Buffer
	secret := "sk-proj-LOGGERSECRET1234567890abcdefghij"
	newScrubbingLogger(&buf).Error("session ended "+secret, "error", errors.New("boom "+secret), "detail", secret)
	if strings.Contains(buf.String(), "LOGGERSECRET") {
		t.Fatalf("secret reached stderr: %s", buf.String())
	}
}
