package server

import (
	"io"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// maxImpactScan bounds how much of a stored response is read to decide whether it
// actually shows impact. A login page announces itself in the first few KB.
const maxImpactScan = 256 << 10

// impactVerdict is the outcome of reading a finding's bound response for real
// evidence. It answers the question the previous triager never asked: does this
// response prove the claimed impact, or is it the target refusing?
type impactVerdict struct {
	// Proven is true only when the response shows content the claim says should
	// not be reachable (a 2xx that is not a login/auth bounce).
	Proven bool
	// Refuted is true when the response positively shows the claim is false —
	// a login page, an auth challenge, a permission denial.
	Refuted bool
	Reason  string
}

// loginMarkers are the shapes of an auth bounce. A 200 that carries them proves
// only that the request was served the login form; that is the single most common
// AI false positive for access-control claims.
var loginMarkers = []string{
	"type=\"password\"", "type='password'", "name=\"password\"", "name='password'",
	"请输入密码", "用户登录", "账号登录", "登录页",
	"redirect to login", "/login?next=", "/login?redirect",
}

// assessImpact reads one bound snapshot's response and classifies it. body may be
// nil (snapshot without stored bytes): then only the status line is judged.
func assessImpact(snap db.TrafficEvidenceSnapshot, body []byte) impactVerdict {
	status := snap.Status
	switch {
	case status >= 300 && status < 400:
		// A redirect is not impact by itself, and following it would only reach
		// the login page. It is neither proof nor refutation.
		return impactVerdict{Reason: "响应是重定向，未直接呈现受影响内容"}
	case status == 401 || status == 403 || status == 407:
		return impactVerdict{Refuted: true,
			Reason: "响应为 " + itoaStatus(status) + " 拒绝访问，说明权限校验生效，未证明越权"}
	case status == 0:
		return impactVerdict{Reason: "响应缺少状态码"}
	case status >= 500:
		return impactVerdict{Reason: "响应为服务端错误，不能证明受影响内容可达"}
	case status == 304:
		// Not modified: no body was served, so nothing about impact can be read.
		return impactVerdict{Reason: "响应为 304 未修改，未返回正文"}
	case status != 200 && status != 201 && status != 202 && status != 203 && status != 206:
		// Any other final status (404 not-found, 429 rate-limited, 410 gone, an odd
		// 1xx) means the request did not obtain the content the claim is about. A
		// body on a 404 is an error page, not leaked data.
		return impactVerdict{Refuted: true,
			Reason: "响应为 " + itoaStatus(status) + "，未取得所声明的内容（不是成功响应）"}
	}

	lower := strings.ToLower(string(body))
	for _, m := range loginMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return impactVerdict{Refuted: true,
				Reason: "响应正文是登录页（命中特征 " + m + "），200 只表示登录表单被返回，未证明越权访问"}
		}
	}
	if len(body) == 0 {
		return impactVerdict{Reason: "响应正文未留存，无法核对受影响内容"}
	}
	return impactVerdict{Proven: true,
		Reason: "响应 " + itoaStatus(status) + " 且未返回登录页/拒绝页，呈现了受影响内容"}
}

func itoaStatus(n int) string {
	switch {
	case n == 200:
		return "200"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 && i > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// readSnapshotBody reads at most maxImpactScan bytes of a snapshot side. A missing
// blob or an unreadable file yields nil: the caller then judges on the status line
// alone instead of failing the whole verification.
func (s *Server) readSnapshotBody(snap db.TrafficEvidenceSnapshot, side string) []byte {
	f, _, err := s.evidenceStore().OpenBody(snap, side)
	if err != nil || f == nil {
		return nil
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, maxImpactScan))
	if err != nil {
		return nil
	}
	return buf
}
