package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/oast"
	actool "github.com/Autumn-27/norma/tool"
)

func oastTool(t *testing.T, tools []actool.CoreTool, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range tools {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("missing tool %s", name)
	return nil
}

// The full blind-vulnerability loop: generate a callback bound to the run, deliver
// a target-style request to it, poll the hits, then use an `oast:<id>` reference as
// a finding's evidence — which the host's EvidenceRefValidator must accept.
func TestOASTEvidenceLoop(t *testing.T) {
	srv := oast.New(oast.Options{Addr: "127.0.0.1:0"})
	if err := srv.Start(); err != nil {
		t.Fatalf("start oast: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	var gotTask, gotIntent int64
	tools := srv.Tools(func(ctx context.Context) (int64, int64) {
		ri := agent.RunInfoFrom(ctx)
		gotTask, gotIntent = ri.TaskID, ri.IntentID
		return ri.TaskID, ri.IntentID
	})
	gen, poll := oastTool(t, tools, "oast_generate"), oastTool(t, tools, "oast_poll")

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 11, IntentID: 22})
	raw, _ := json.Marshal(map[string]any{"memo": "blind SSRF in the PDF renderer"})
	res, err := gen.Call(ctx, raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("generate: %v %s", err, res.Flatten())
	}
	var out struct {
		Token       string `json:"token"`
		CallbackURL string `json:"callback_url"`
		CurlExample string `json:"curl_example"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("decode generate: %v (%s)", err, res.Flatten())
	}
	if out.Token == "" || out.CallbackURL == "" || out.CurlExample == "" {
		t.Fatalf("incomplete generate result: %+v", out)
	}
	if gotTask != 11 || gotIntent != 22 {
		t.Fatalf("token not bound to the run: task=%d intent=%d", gotTask, gotIntent)
	}

	// The target "fetches" the callback URL.
	resp, err := http.Get(out.CallbackURL + "/ssrf?url=http://169.254.169.254/latest/meta-data")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	raw, _ = json.Marshal(map[string]any{"token": out.Token})
	res, err = poll.Call(context.Background(), raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("poll: %v %s", err, res.Flatten())
	}
	var polled struct {
		Count        int `json:"count"`
		Interactions []struct {
			EvidenceRef string `json:"evidence_ref"`
			RemoteIP    string `json:"remote_ip"`
			Method      string `json:"method"`
			Path        string `json:"path"`
			Query       string `json:"query"`
		} `json:"interactions"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &polled); err != nil {
		t.Fatalf("decode poll: %v (%s)", err, res.Flatten())
	}
	if polled.Count != 1 || len(polled.Interactions) != 1 {
		t.Fatalf("poll count=%d want 1 (%s)", polled.Count, res.Flatten())
	}
	hit := polled.Interactions[0]
	if !strings.HasPrefix(hit.EvidenceRef, "oast:") || !strings.Contains(hit.Query, "169.254.169.254") {
		t.Fatalf("unexpected interaction: %+v", hit)
	}

	// Evidence validation: a retained interaction resolves; a fabricated one does not.
	if err := validateOASTEvidence(srv, hit.EvidenceRef); err != nil {
		t.Fatalf("valid oast ref rejected: %v", err)
	}
	if err := validateOASTEvidence(srv, "oast:999999999"); err == nil {
		t.Fatal("fabricated oast ref accepted")
	}
}

// validateOASTEvidence mirrors the host wiring in New(): the ref's id must still
// be in the ring buffer.
func validateOASTEvidence(srv *oast.Server, ref string) error {
	parsed, err := db.ParseEvidenceRef(ref)
	if err != nil {
		return err
	}
	if parsed.Kind != "oast" {
		return nil
	}
	if srv != nil && srv.Has(parsed.ID) {
		return nil
	}
	return errOastRefMissing
}

var errOastRefMissing = errors.New("带外回调证据不存在")
