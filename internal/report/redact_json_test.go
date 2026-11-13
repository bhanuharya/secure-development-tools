package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFinalJSONRedactionCoversEveryFieldAndEcho(t *testing.T) {
	const secret = "synthetic signing secret 7!"
	doc := map[string]any{
		"findings": []any{map[string]any{
			"message":  secret,
			"metadata": map[string]any{"new_field": `SIGNING_KEY = "` + secret + `"`},
		}},
		"unresolved": []string{`basicauth.Config{Users: map[string]string{"operator": "synthetic_Map7Demo!"`},
		"echo":       "synthetic_Map7Demo!",
		"count":      int64(9007199254740993),
	}
	raw, err := MarshalRedacted(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) || !strings.Contains(string(raw), "9007199254740993") {
		t.Fatalf("JSON structure or number changed: %s", raw)
	}
	for _, value := range []string{secret, "synthetic_Map7Demo!"} {
		if strings.Contains(string(raw), value) {
			t.Fatalf("credential survived the final pass: %s", raw)
		}
	}
	if doc["echo"] != "synthetic_Map7Demo!" {
		t.Fatal("redaction mutated the input")
	}
}
