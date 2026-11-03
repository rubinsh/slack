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

	"github.com/slack-go/slack"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

var (
	errSlackQRInvalid = errors.New("invalid Slack QR link")
	errSlackQRBrowser = errors.New("Slack requires browser verification")
	errSlackQRFailed  = errors.New("Slack QR sign-in did not complete")
	qrPathPattern     = regexp.MustCompile(`^/t/([a-z0-9][a-z0-9-]*)/login/(z-app-[A-Za-z0-9_-]+)$`)
	qrWebTokenPattern = regexp.MustCompile(`"api_token"\s*:\s*"(xoxc-[a-zA-Z0-9-]+)"`)
)

const slackQRMaxHops = 10

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
		return nil, err
	}
	// A retried link must not inherit a previous attempt's credentials.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
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
		return nil, errSlackQRInvalid
	}
	target := *c.url
	target.RawQuery = url.Values{"domain": {c.link.workspace}, "domainLogin": {"1"}, "email": {c.email}}.Encode()
	values := url.Values{"2fa_magiclogin": {c.magic}, "remember": {"0"}, "has_remember": {"false"}, "2fa_code": {code}, "2fa_action": {"submit_primary"}}
	return s.walk(ctx, c.link, http.MethodPost, &target, values)
}

func (s *slackQRAPI) walk(ctx context.Context, link *slackQRLink, method string, target *url.URL, form url.Values) (*slackQRResult, error) {
	for hop := 0; hop < slackQRMaxHops; hop++ {
		body, location, status, err := s.request(ctx, method, target, form)
		if err != nil {
			return nil, err
		}
		if s.cookie(link) != "" {
			return s.session(ctx, link)
		}
		if status >= 300 && status < 400 {
			if location == "" {
				return nil, errSlackQRFailed
			}
			next, err := target.Parse(location)
			if err != nil || !safeSlackQRURL(next) {
				return nil, errSlackQRBrowser
			}
			// Never replay a confirmation POST/code to a redirect target.
			if method != http.MethodGet && status != http.StatusSeeOther && status != http.StatusFound && status != http.StatusMovedPermanently {
				return nil, errSlackQRBrowser
			}
			target, method, form = next, http.MethodGet, nil
			continue
		}
		challenge := parseQRChallenge(body, target, link)
		if challenge != nil {
			return &slackQRResult{challenge: challenge}, nil
		}
		return nil, errSlackQRBrowser
	}
	return nil, errSlackQRFailed
}

func qrConfirmationURL(u *url.URL, link *slackQRLink) bool {
	return link != nil && safeSlackQRURL(u) && u.Hostname() == link.workspace+".slack.com" && u.EscapedPath() == "/login/"+link.secret
}

func parseQRChallenge(body []byte, target *url.URL, link *slackQRLink) *slackQRChallenge {
	if !qrConfirmationURL(target, link) {
		return nil
	}
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			return nil
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
		var parsed struct {
			Magic string `json:"magicLogin"`
			Email string `json:"emailAddress"`
		}
		if json.Unmarshal([]byte(props), &parsed) != nil || parsed.Magic == "" || parsed.Email == "" {
			return nil
		}
		copyURL := *target
		return &slackQRChallenge{link: link, url: &copyURL, magic: parsed.Magic, email: parsed.Email}
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
		body, location, status, err := s.request(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		if status >= 300 && status < 400 {
			next, err := target.Parse(location)
			if location == "" || err != nil || !safeSlackQRURL(next) {
				return nil, errSlackQRBrowser
			}
			target = next
			continue
		}
		match := qrWebTokenPattern.FindSubmatch(body)
		if match == nil {
			return nil, errSlackQRBrowser
		}
		cookie := s.cookie(link)
		if cookie == "" {
			return nil, errSlackQRFailed
		}
		return &slackQRResult{token: string(match[1]), cookie: cookie}, nil
	}
	return nil, errSlackQRFailed
}

// Deliberately suppress net/url errors: their Error() embeds secret-bearing URLs.
func (s *slackQRAPI) request(ctx context.Context, method string, target *url.URL, form url.Values) ([]byte, string, int, error) {
	if !safeSlackQRURL(target) {
		return nil, "", 0, errSlackQRInvalid
	}
	var reader io.Reader
	if form != nil {
		reader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, "", 0, errSlackQRFailed
	}
	req.Header.Set("User-Agent", slack.DefaultUserAgent)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", 0, errSlackQRFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, "", 0, errSlackQRFailed
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, slackLoginMaxResponseSize+1))
	if err != nil || len(body) > slackLoginMaxResponseSize {
		return nil, "", 0, errSlackQRFailed
	}
	return body, resp.Header.Get("Location"), resp.StatusCode, nil
}
