package oast

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	ishclient "github.com/projectdiscovery/interactsh/pkg/client"
	ishserver "github.com/projectdiscovery/interactsh/pkg/server"
)

// generateInteractsh registers one identity with the external interactsh server.
func (s *Server) generateInteractsh(ish *ishclient.Client, memo string, taskID, intentID int64) Token {
	domain := strings.ToLower(ish.URL())
	if domain == "" {
		return Token{}
	}
	uniqueID := domain
	if i := strings.IndexByte(domain, '.'); i > 0 {
		uniqueID = domain[:i]
	}
	s.mu.Lock()
	s.addTokenLocked(Token{
		Value: uniqueID, Memo: strings.TrimSpace(memo), TaskID: taskID, IntentID: intentID,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		CallbackURL: "http://" + domain,
		CurlExample: "curl -sS -i 'http://" + domain + "/probe'",
		DNSDomain:   domain,
		DNSExample:  "nslookup " + domain,
	})
	out := s.tokens[uniqueID].token
	s.mu.Unlock()
	return out
}

// interactshServerHost returns the host the client actually registered with.
// A standard interactsh setting names a bare domain or a comma-separated list
// without a scheme; the registered URL carries the final host, so it is the
// authoritative source and the configured value is only a fallback.
func interactshServerHost(c *ishclient.Client, raw string) string {
	sample := strings.ToLower(c.URL())
	if _, host, ok := strings.Cut(sample, "."); ok && host != "" {
		return host
	}
	first := strings.TrimSpace(strings.Split(raw, ",")[0])
	if first == "" {
		return ""
	}
	if !strings.Contains(first, "://") {
		first = "https://" + first
	}
	u, err := url.Parse(first)
	if err != nil {
		return ""
	}
	return u.Host
}

// startInteractsh connects to an external callback service and begins polling it.
func (s *Server) startInteractsh(raw string) error {
	c, err := ishclient.New(&ishclient.Options{ServerURL: raw, Token: strings.TrimSpace(s.opts.InteractshToken)})
	if err != nil {
		return fmt.Errorf("interactsh 客户端初始化失败: %w", err)
	}
	serverHost := interactshServerHost(c, raw)
	if serverHost == "" {
		_ = c.Close()
		return fmt.Errorf("interactsh 服务地址无效: %q", raw)
	}
	s.mu.Lock()
	s.ish = c
	s.public = "http://" + serverHost
	s.mu.Unlock()
	if err := c.StartPolling(s.opts.PollInterval, s.handleInteractsh); err != nil {
		_ = c.Close()
		s.mu.Lock()
		s.ish = nil
		s.public = ""
		s.mu.Unlock()
		return fmt.Errorf("interactsh 轮询启动失败: %w", err)
	}
	log.Printf("[oast] 已接入外部 interactsh 服务 %s，轮询间隔 %s", serverHost, s.opts.PollInterval)
	return nil
}

// handleInteractsh turns one polled interactsh interaction into the same evidence
// record the embedded listeners produce.
func (s *Server) handleInteractsh(in *ishserver.Interaction) {
	if in == nil {
		return
	}
	at := in.Timestamp.UTC().Format(time.RFC3339)
	if in.Timestamp.IsZero() {
		at = time.Now().UTC().Format(time.RFC3339)
	}
	method := strings.ToUpper(in.Protocol)
	if in.QType != "" {
		method = "DNS:" + strings.ToUpper(in.QType)
	}
	s.publishInteraction(&Interaction{
		Token:       strings.ToLower(in.UniqueID),
		Protocol:    strings.ToLower(in.Protocol),
		At:          at,
		RemoteIP:    remoteHost(in.RemoteAddress),
		Method:      method,
		Path:        in.FullId,
		BodyPreview: truncate(in.RawRequest, maxBodyPreview),
		TaskID:      -1,
	})
}
