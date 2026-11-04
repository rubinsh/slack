// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

var (
	errSlackQRInvalid = errors.New("invalid Slack QR link")
	errSlackQRBrowser = errors.New("unsupported step required for Slack QR sign-in")
	errSlackQRExpired = errors.New("expired or already-used Slack QR link")
	errSlackQRDevice  = errors.New("device confirmation required for Slack QR sign-in")
	errSlackQRFailed  = errors.New("failed to complete Slack QR sign-in")
	qrPathPattern     = regexp.MustCompile(`^/t/([a-z0-9][a-z0-9-]*)/login/(z-app-[A-Za-z0-9_-]+)$`)
	qrWebTokenPattern = regexp.MustCompile(`"api_token"\s*:\s*"(xoxc-[a-zA-Z0-9-]+)"`)
)

const (
	slackQRMaxHops          = 10
	slackQRBrowserUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)

type slackQRAPI struct{ client *http.Client }
type slackQRLink struct {
	url               *url.URL
	workspace, secret string
}
type slackQRChallenge struct {
	link         *slackQRLink
	url          *url.URL
	magic, email string
}
type slackQRChallengeProperties struct {
	Magic string `json:"magicLogin"`
	Email string `json:"emailAddress"`
}
type slackQRResult struct {
	token, cookie string
	challenge     *slackQRChallenge
}

func newSlackQRAPI() *slackQRAPI {
	return &slackQRAPI{client: &http.Client{Timeout: slackLoginDefaultRequestTime, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func parseSlackQRLink(raw string) (*slackQRLink, error) {
	if len(raw) > 8192 {
		return nil, errSlackQRInvalid
	}
	u, err := url.Parse(raw)
	if err != nil || !safeSlackQRURL(u) || u.Hostname() != "app.slack.com" || u.Fragment != "" {
		return nil, errSlackQRInvalid
	}
	match := qrPathPattern.FindStringSubmatch(u.EscapedPath())
	if match == nil || len(match[1]) > 63 {
		return nil, errSlackQRInvalid
	}
	return &slackQRLink{url: u, workspace: match[1], secret: match[2]}, nil
}

// Both initial requests and every redirect are checked before sending anything.
func safeSlackQRURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := u.Hostname()
	return host == "slack.com" || strings.HasSuffix(host, ".slack.com")
}

func (s *slackQRAPI) begin(ctx context.Context, raw string) (*slackQRResult, error) {
	link, err := parseSlackQRLink(raw)
	if err != nil {
		logSlackQRDiagnostic(ctx, qrInvalidLink, qrPhaseBegin, 0, 0)
		return nil, err
	}
	// A retried link must not inherit a previous attempt's credentials.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		logSlackQRDiagnostic(ctx, qrCookieJarFailed, qrPhaseBegin, 0, 0)
		return nil, errSlackQRFailed
	}
	client := *s.client
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.client = &client
	return s.walk(ctx, link, http.MethodGet, link.url, nil)
}

func (s *slackQRAPI) confirm(ctx context.Context, c *slackQRChallenge, code string) (*slackQRResult, error) {
	if c == nil || !qrConfirmationURL(c.url, c.link) || !slackTwoFactorPattern.MatchString(code) {
		logSlackQRDiagnostic(ctx, qrInvalidConfirmation, qrPhaseConfirm, 0, 0)
		return nil, errSlackQRInvalid
	}
	target := *c.url
	target.RawQuery = url.Values{"domain": {c.link.workspace}, "domainLogin": {"1"}, "email": {c.email}}.Encode()
	values := url.Values{"2fa_magiclogin": {c.magic}, "remember": {"0"}, "has_remember": {"false"}, "2fa_code": {code}, "2fa_action": {"submit_primary"}}
	return s.walk(ctx, c.link, http.MethodPost, &target, values)
}

func (s *slackQRAPI) walk(ctx context.Context, link *slackQRLink, method string, target *url.URL, form url.Values) (*slackQRResult, error) {
	phase := qrPhaseBegin
	if method == http.MethodPost {
		phase = qrPhaseConfirm
	}
	for hop := 0; hop < slackQRMaxHops; hop++ {
		body, location, status, err := s.request(ctx, method, target, form, phase, hop+1)
		if err != nil {
			return nil, err
		}
		if s.cookie(link) != "" {
			return s.session(ctx, link)
		}
		if status >= 300 && status < 400 {
			if location == "" {
				logSlackQRDiagnostic(ctx, qrMissingRedirect, phase, status, hop+1)
				return nil, errSlackQRFailed
			}
			next, err := target.Parse(location)
			if err != nil || !safeSlackQRURL(next) {
				logSlackQRDiagnostic(ctx, qrUnsafeRedirect, phase, status, hop+1)
				return nil, errSlackQRBrowser
			}
			// Never replay a confirmation POST/code to a redirect target.
			if method != http.MethodGet && status != http.StatusSeeOther && status != http.StatusFound && status != http.StatusMovedPermanently {
				logSlackQRDiagnostic(ctx, qrPostReplayBlocked, phase, status, hop+1)
				return nil, errSlackQRBrowser
			}
			target, method, form = next, http.MethodGet, nil
			continue
		}
		challenge, reason := parseQRChallenge(body, target, link)
		if challenge != nil {
			return &slackQRResult{challenge: challenge}, nil
		}
		detail := s.diagnosticDetail(target, link, body)
		if detail.route == qrRouteWorkspace {
			if denial := slackQRPageDenial(body); denial != qrReasonNone {
				logSlackQRDiagnostic(ctx, denial, phase, status, hop+1, detail)
				if denial == qrLinkExpired {
					return nil, errSlackQRExpired
				}
				return nil, errSlackQRDevice
			}
		}
		logSlackQRDiagnostic(ctx, reason, phase, status, hop+1, detail)
		return nil, errSlackQRBrowser
	}
	logSlackQRDiagnostic(ctx, qrRedirectLimit, phase, 0, slackQRMaxHops)
	return nil, errSlackQRFailed
}

func qrConfirmationURL(u *url.URL, link *slackQRLink) bool {
	if link == nil || link.secret == "" || !safeSlackQRURL(u) || u.Hostname() != link.workspace+".slack.com" {
		return false
	}
	// Allow the legacy path and the observed original-secret root path.
	// Never accept arbitrary prefixes, suffixes, or a different QR credential.
	path := u.EscapedPath()
	return path == "/login/"+link.secret || path == "/"+link.secret
}

func parseQRChallenge(body []byte, target *url.URL, link *slackQRLink) (*slackQRChallenge, slackQRReason) {
	if !qrConfirmationURL(target, link) {
		return nil, qrUnexpectedChallengeRoute
	}
	parsed, reason := parseQRChallengeProperties(body)
	if parsed == nil {
		return nil, reason
	}
	copyURL := *target
	return &slackQRChallenge{link: link, url: &copyURL, magic: parsed.Magic, email: parsed.Email}, qrReasonNone
}

// Parsing shape alone does not authorize a confirmation URL or request.
func parseQRChallengeProperties(body []byte) (*slackQRChallengeProperties, slackQRReason) {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			return nil, qrMissingChallengeProps
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		tag := tokenizer.Token()
		var id, props string
		for _, attr := range tag.Attr {
			if attr.Key == "id" {
				id = attr.Val
			}
			if attr.Key == "data-props" {
				props = attr.Val
			}
		}
		if id != "props_node" {
			continue
		}
		var parsed slackQRChallengeProperties
		if json.Unmarshal([]byte(props), &parsed) != nil {
			return nil, qrInvalidChallengeProps
		}
		if parsed.Magic == "" || parsed.Email == "" {
			return nil, qrMissingChallengeFields
		}
		return &parsed, qrReasonNone
	}
}

func (s *slackQRAPI) cookie(link *slackQRLink) string {
	if s.client.Jar == nil {
		return ""
	}
	target := &url.URL{Scheme: "https", Host: link.workspace + ".slack.com", Path: "/ssb/redirect"}
	for _, cookie := range s.client.Jar.Cookies(target) {
		if cookie.Name == "d" && cookie.Value != "" {
			// PathUnescape preserves literal '+' in cookie values.
			decoded, err := url.PathUnescape(cookie.Value)
			if err == nil {
				return decoded
			}
			return cookie.Value
		}
	}
	return ""
}

func (s *slackQRAPI) session(ctx context.Context, link *slackQRLink) (*slackQRResult, error) {
	target := &url.URL{Scheme: "https", Host: link.workspace + ".slack.com", Path: "/ssb/redirect"}
	for hop := 0; hop < slackQRMaxHops; hop++ {
		body, location, status, err := s.request(ctx, http.MethodGet, target, nil, qrPhaseSession, hop+1)
		if err != nil {
			return nil, err
		}
		if status >= 300 && status < 400 {
			next, err := target.Parse(location)
			if location == "" || err != nil || !safeSlackQRURL(next) {
				reason := qrUnsafeRedirect
				if location == "" {
					reason = qrMissingRedirect
				}
				logSlackQRDiagnostic(ctx, reason, qrPhaseSession, status, hop+1)
				return nil, errSlackQRBrowser
			}
			target = next
			continue
		}
		match := qrWebTokenPattern.FindSubmatch(body)
		if match == nil {
			logSlackQRDiagnostic(ctx, qrMissingSessionToken, qrPhaseSession, status, hop+1, s.diagnosticDetail(target, link, body))
			return nil, errSlackQRBrowser
		}
		cookie := s.cookie(link)
		if cookie == "" {
			logSlackQRDiagnostic(ctx, qrMissingSessionCookie, qrPhaseSession, status, hop+1)
			return nil, errSlackQRFailed
		}
		return &slackQRResult{token: string(match[1]), cookie: cookie}, nil
	}
	logSlackQRDiagnostic(ctx, qrRedirectLimit, qrPhaseSession, 0, slackQRMaxHops)
	return nil, errSlackQRFailed
}

// Deliberately suppress net/url errors: their Error() embeds secret-bearing URLs.
func (s *slackQRAPI) request(ctx context.Context, method string, target *url.URL, form url.Values, phase slackQRPhase, hop int) ([]byte, string, int, error) {
	if !safeSlackQRURL(target) {
		logSlackQRDiagnostic(ctx, qrUnsafeRequest, phase, 0, hop)
		return nil, "", 0, errSlackQRInvalid
	}
	var reader io.Reader
	if form != nil {
		reader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		logSlackQRDiagnostic(ctx, qrRequestBuildFailed, phase, 0, hop)
		return nil, "", 0, errSlackQRFailed
	}
	req.Header.Set("User-Agent", slackQRBrowserUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		logSlackQRDiagnostic(ctx, qrTransportFailed, phase, 0, hop)
		return nil, "", 0, errSlackQRFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		logSlackQRDiagnostic(ctx, qrHTTPStatusFailed, phase, resp.StatusCode, hop)
		return nil, "", 0, errSlackQRFailed
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, slackLoginMaxResponseSize+1))
	if err != nil {
		logSlackQRDiagnostic(ctx, qrResponseReadFailed, phase, resp.StatusCode, hop)
		return nil, "", 0, errSlackQRFailed
	}
	if len(body) > slackLoginMaxResponseSize {
		logSlackQRDiagnostic(ctx, qrResponseTooLarge, phase, resp.StatusCode, hop)
		return nil, "", 0, errSlackQRFailed
	}
	return body, resp.Header.Get("Location"), resp.StatusCode, nil
}
