package report

import (
	"bytes"
	"encoding/json"
	"sort"
)

// MarshalRedacted is the last guard on JSON artifacts. Redact decoded text, so JSON escapes
// cannot hide a credential, and collect values before scrubbing echoes in other fields.
func MarshalRedacted(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var doc any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	withheld := map[string]struct{}{}
	walkText(doc, func(text string) string {
		redactSource(text, withheld)
		return text
	})
	secrets := make([]string, 0, len(withheld))
	for secret := range withheld {
		secrets = append(secrets, secret)
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	doc = walkText(doc, func(text string) string { return Redact(text, secrets...) })
	return json.MarshalIndent(doc, "", "  ")
}

func walkText(value any, clean func(string) string) any {
	switch v := value.(type) {
	case string:
		return clean(v)
	case []any:
		for i := range v {
			v[i] = walkText(v[i], clean)
		}
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[clean(key)] = walkText(item, clean)
		}
		return out
	}
	return value
}
