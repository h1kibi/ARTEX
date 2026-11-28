package agent

import (
	"encoding/json"
	"testing"
)

func TestInputNormUnwrapStringifiedArray(t *testing.T) {
	unwrapped := map[string]string{
		`"[{\"summary\":\"one\"}]"`: `[{"summary":"one"}]`,
		`" [1,2,3] "`:               `[1,2,3]`,
	}
	for in, want := range unwrapped {
		if got := string(unwrapStringifiedArray(json.RawMessage(in))); got != want {
			t.Fatalf("unwrap(%s)=%s want %s", in, got, want)
		}
	}
	unchanged := []string{
		`"[not json"`,
		`[{"summary":"one"}]`,
		`"plain"`,
		`"{}"`,
	}
	for _, in := range unchanged {
		if got := string(unwrapStringifiedArray(json.RawMessage(in))); got != in {
			t.Fatalf("unwrap(%s) changed to %s", in, got)
		}
	}
}

func TestInputNormToolArrays(t *testing.T) {
	in := json.RawMessage(`{
		"intents": "[{\"summary\":\"s\",\"parent_ids\":\"[\\\"#12\\\",\\\"node:13\\\"]\"}]",
		"facts": "[{\"summary\":\"f\",\"claim_ids\":\"[1,2]\"}]",
		"assets": "[{\"type\":\"ip\",\"ip\":\"10.0.0.1\"}]",
		"asset_ids": "[7,8]"
	}`)
	out := normalizeToolInputArrays(in, "intents", "facts", "assets", "asset_ids", "parent_ids", "claim_ids")
	var obj struct {
		Intents []struct {
			ParentIDs []string `json:"parent_ids"`
		} `json:"intents"`
		Facts []struct {
			ClaimIDs []int64 `json:"claim_ids"`
		} `json:"facts"`
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("normalized output does not decode: %v (%s)", err, out)
	}
	if len(obj.Intents) != 1 || len(obj.Intents[0].ParentIDs) != 2 || obj.Intents[0].ParentIDs[1] != "node:13" {
		t.Fatalf("intents=%+v", obj.Intents)
	}
	if len(obj.Facts) != 1 || len(obj.Facts[0].ClaimIDs) != 2 {
		t.Fatalf("facts=%+v", obj.Facts)
	}
	if len(obj.AssetIDs) != 2 || obj.AssetIDs[0] != 7 {
		t.Fatalf("asset_ids=%v", obj.AssetIDs)
	}
	// Input without stringified arrays is returned untouched.
	plain := json.RawMessage(`{"summary":"x","asset_ids":[1]}`)
	if got := string(normalizeToolInputArrays(plain, "asset_ids")); got != string(plain) {
		t.Fatalf("plain input changed: %s", got)
	}
}

func TestInputNormLooseID(t *testing.T) {
	cases := map[string]int64{
		`14825`:           14825,
		`"14825"`:         14825,
		`"#14825"`:        14825,
		`"node:14825"`:    14825,
		`"intent:14825"`:  14825,
		`"fact:14825"`:    14825,
		`"finding:14825"`: 14825,
		`"asset:42"`:      42,
		`"goal:9"`:        9,
		`" # 12 "`:        12,
		`"abc"`:           0,
		`"node:abc"`:      0,
		`"node:"`:         0,
		`"-3"`:            0,
		`0`:               0,
		`null`:            0,
	}
	for in, want := range cases {
		if got := pid(json.RawMessage(in)); got != want {
			t.Fatalf("pid(%s)=%d want %d", in, got, want)
		}
	}
}

func TestArtifactCompareKey(t *testing.T) {
	cases := map[string]string{
		`C:\workspace\dir with space`: "/mnt/c/workspace/dir with space",
		`C:/workspace/dir with space`: "/mnt/c/workspace/dir with space",
		`D:\var\artex\tasks`:          "/mnt/d/var/artex/tasks",
		`c:\`:                         "/mnt/c",
		`/mnt/C/workspace/project`:    "/mnt/c/workspace/project",
		`/etc/passwd`:                 "/etc/passwd",
	}
	for in, want := range cases {
		if got := artifactCompareKey(in); got != want {
			t.Fatalf("artifactCompareKey(%q)=%q want %q", in, got, want)
		}
	}
}
