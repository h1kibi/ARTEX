package agent

import (
	"encoding/json"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// unwrapStringifiedArray recovers an array that a model sent as a JSON string
// ("[{\"summary\":\"x\"}]") instead of an array. Only a valid JSON array wrapped
// in a string is unwrapped; anything else is returned byte-for-byte.
func unwrapStringifiedArray(raw json.RawMessage) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) < 2 || trimmed[0] != '"' {
		return raw
	}
	var inner string
	if json.Unmarshal(raw, &inner) != nil {
		return raw
	}
	inner = strings.TrimSpace(inner)
	if len(inner) < 2 || inner[0] != '[' || inner[len(inner)-1] != ']' || !json.Valid([]byte(inner)) {
		return raw
	}
	var arr []json.RawMessage
	if json.Unmarshal([]byte(inner), &arr) != nil {
		return raw
	}
	return json.RawMessage(inner)
}

// normalizeToolInputArrays applies unwrapStringifiedArray to the named top-level
// fields and to the same fields inside intents/facts/assets array elements. It is
// the single entry normalization for write tools: handlers then unmarshal a shape
// they already understand.
func normalizeToolInputArrays(in json.RawMessage, arrayKeys ...string) json.RawMessage {
	if len(in) == 0 {
		return in
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(in, &obj) != nil {
		return in
	}
	changed := false
	for _, key := range arrayKeys {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		if next := unwrapStringifiedArray(raw); string(next) != string(raw) {
			obj[key] = next
			changed = true
		}
	}
	for _, container := range []string{"intents", "facts", "assets"} {
		raw, ok := obj[container]
		if !ok {
			continue
		}
		if next, ok := normalizeArrayElements(raw, arrayKeys); ok {
			obj[container] = next
			changed = true
		}
	}
	if !changed {
		return in
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return in
	}
	return out
}

// normalizeArrayElements unwraps the named fields inside every object element of a
// top-level array. ok reports whether anything changed.
func normalizeArrayElements(raw json.RawMessage, keys []string) (json.RawMessage, bool) {
	var elements []json.RawMessage
	if json.Unmarshal(raw, &elements) != nil {
		return raw, false
	}
	changed := false
	for i, elem := range elements {
		var obj map[string]json.RawMessage
		if json.Unmarshal(elem, &obj) != nil {
			continue
		}
		elemChanged := false
		for _, key := range keys {
			v, ok := obj[key]
			if !ok {
				continue
			}
			if next := unwrapStringifiedArray(v); string(next) != string(v) {
				obj[key] = next
				elemChanged = true
			}
		}
		if !elemChanged {
			continue
		}
		encoded, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		elements[i] = encoded
		changed = true
	}
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(elements)
	if err != nil {
		return raw, false
	}
	return out, true
}

// looseID parses an id that may arrive as a JSON number or as a string carrying a
// common display prefix ("#14825", "intent:14825", "fact:14825"). Only a positive
// integer after the prefix is accepted; anything else is 0.
func looseID(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		if n > 0 {
			return n
		}
		return 0
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return 0
	}
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '#'); i >= 0 {
		s = s[i+1:]
	} else if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

// artifactCompareKey folds the two spellings of one absolute artifact path (drive
// form and /mnt/<drive> form) into a single comparison key. actool.ToWSLPath does
// the drive conversion; only the drive letter is lower-cased, the rest of the
// path keeps its case.
func artifactCompareKey(p string) string {
	key := actool.ToWSLPath(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
	if strings.HasPrefix(key, "/mnt/") && len(key) >= 6 {
		return key[:5] + strings.ToLower(key[5:6]) + key[6:]
	}
	return key
}
