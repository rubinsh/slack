// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"context"
	"errors"
	"fmt"
	stdhtml "html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"maunium.net/go/mautrix/bridgev2"
)

const qrSyntheticURL = "https://app.slack.com/t/acme/login/z-app-123-synthetic-secret?team_id=TTEST&user_id=UTEST"
const qrSyntheticPath = "/login/z-app-123-synthetic-secret"

type qrTestTransport func(*http.Request) (*http.Response, error)

func (f qrTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func qrResponse(r *http.Request, status int, body string, headers ...string) *http.Response {
	h := make(http.Header)
	for i := 0; i < len(headers); i += 2 {
		h.Add(headers[i], headers[i+1])
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func qrTestAPI(f qrTestTransport) *slackQRAPI { a := newSlackQRAPI(); a.client.Transport = f; return a }
func qrProps(magic string) string {
	return `<div data-props="` + stdhtml.EscapeString(fmt.Sprintf(`{"magicLogin":%q,"emailAddress":"test@example.invalid","twoFactorType":"sms"}`, magic)) + `" id="props_node"></div>`
}

func TestSlackQRFactoryContract(t *testing.T) {
	process, err := (&SlackConnector{}).CreateLogin(context.Background(), nil, LoginFlowIDQR)
	require.NoError(t, err)
	step, err := process.Start(context.Background())
	require.NoError(t, err)
	assert.Equal(t, LoginStepIDQR, step.StepID)
	require.Len(t, step.UserInputParams.Fields, 1)
	assert.Equal(t, "login_url", step.UserInputParams.Fields[0].ID)
	assert.Equal(t, bridgev2.LoginInputFieldTypePassword, step.UserInputParams.Fields[0].Type)
}

func TestSlackQRRejectsInvalidLinksBeforeNetwork(t *testing.T) {
	bad := []string{"", "https://evil.invalid/t/acme/login/z-app-secret", "http://app.slack.com/t/acme/login/z-app-secret", "https://app.slack.com.evil.invalid/t/acme/login/z-app-secret", "https://app.slack.com:444/t/acme/login/z-app-secret", "https://user:pass@app.slack.com/t/acme/login/z-app-secret", "https://app.slack.com/t/acme/login/z-app-secret#fragment", "https://app.slack.com/t/../login/z-app-secret", "https://app.slack.com/t/acme/login/z-app-secret/extra", "https://app.slack.com/t/acme%2eevil/login/z-app-secret", "https://app.slack.com/client/TTEST", strings.Repeat("x", 8193)}
	for i, raw := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			a := qrTestAPI(func(*http.Request) (*http.Response, error) { t.Fatal("invalid URL reached transport"); return nil, nil })
			_, err := a.begin(context.Background(), raw)
			require.ErrorIs(t, err, errSlackQRInvalid)
		})
	}
	_, err := parseSlackQRLink(qrSyntheticURL)
	require.NoError(t, err)
}

func TestSlackQRRedirectCookieAndToken(t *testing.T) {
	var paths []string
	a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Hostname()+r.URL.Path)
		require.Equal(t, "https", r.URL.Scheme)
		switch r.URL.Path {
		case "/t/acme" + qrSyntheticPath:
			return qrResponse(r, 302, "", "Location", "https://acme.slack.com"+qrSyntheticPath), nil
		case qrSyntheticPath:
			return qrResponse(r, 302, "", "Set-Cookie", "d=xoxd-synthetic%2B%2F%3D; Domain=.slack.com; Path=/; Secure; HttpOnly", "Location", "/client"), nil
		case "/ssb/redirect":
			cookie, err := r.Cookie("d")
			require.NoError(t, err)
			assert.Equal(t, "xoxd-synthetic%2B%2F%3D", cookie.Value)
			return qrResponse(r, 200, `<script>var boot={"api_token": "xoxc-synthetic"}</script>`), nil
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
			return nil, nil
		}
	})
	result, err := a.begin(context.Background(), qrSyntheticURL)
	require.NoError(t, err)
	assert.Nil(t, result.challenge)
	assert.Equal(t, "xoxc-synthetic", result.token)
	assert.Equal(t, "xoxd-synthetic+/=", result.cookie)
	require.Len(t, paths, 3)
}

func TestSlackQRRequiredTwoFactorAndRetry(t *testing.T) {
	for _, challengePath := range []string{qrSyntheticPath, strings.TrimPrefix(qrSyntheticPath, "/login")} {
		t.Run(challengePath, func(t *testing.T) {
			calls, posts, completed := 0, 0, 0
			a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
				assertSlackQRRequestProfile(t, r)
				calls++
				if r.URL.Hostname() == "app.slack.com" {
					if r.URL.Path != "/app-redir" {
						return qrResponse(r, 302, "", "Location", "https://app.slack.com/app-redir"), nil
					}
					return qrResponse(r, 302, "", "Location", "https://acme.slack.com"+challengePath), nil
				}
				if r.URL.Path == "/ssb/redirect" {
					return qrResponse(r, 200, `{"api_token":"xoxc-synthetic"}`), nil
				}
				require.Equal(t, challengePath, r.URL.Path)
				if r.Method == http.MethodPost {
					posts++
					require.NoError(t, r.ParseForm())
					assert.Equal(t, "123456", r.PostForm.Get("2fa_code"))
					assert.Equal(t, "submit_primary", r.PostForm.Get("2fa_action"))
					assert.Equal(t, "test@example.invalid", r.URL.Query().Get("email"))
					assert.Equal(t, "acme", r.URL.Query().Get("domain"))
					if posts == 1 {
						assert.Equal(t, "synthetic-magic", r.PostForm.Get("2fa_magiclogin"))
						return qrResponse(r, 200, qrProps("synthetic-retry")), nil
					}
					assert.Equal(t, "synthetic-retry", r.PostForm.Get("2fa_magiclogin"))
					return qrResponse(r, 303, "", "Set-Cookie", "d=xoxd-synthetic; Domain=.slack.com; Path=/; Secure", "Location", "/client"), nil
				}
				return qrResponse(r, 200, qrProps("synthetic-magic")), nil
			})
			p := &SlackQRLogin{api: a, complete: func(ctx context.Context, u *bridgev2.User, token, cookie string) (*bridgev2.LoginStep, error) {
				completed++
				assert.Equal(t, "xoxc-synthetic", token)
				assert.Equal(t, "xoxd-synthetic", cookie)
				return &bridgev2.LoginStep{Type: bridgev2.LoginStepTypeComplete}, nil
			}}
			step, err := p.SubmitUserInput(context.Background(), map[string]string{loginFieldQR: qrSyntheticURL})
			require.NoError(t, err)
			assert.Equal(t, LoginStepIDTwoFactor, step.StepID)
			assert.Zero(t, completed)
			before := calls
			step, err = p.SubmitUserInput(context.Background(), map[string]string{loginFieldTwoFactorCode: "not-a-code"})
			require.NoError(t, err)
			assert.Equal(t, LoginStepIDTwoFactor, step.StepID)
			assert.Equal(t, before, calls)
			step, err = p.SubmitUserInput(context.Background(), map[string]string{loginFieldTwoFactorCode: "123456"})
			require.NoError(t, err)
			assert.Equal(t, LoginStepIDTwoFactor, step.StepID)
			assert.Zero(t, completed)
			step, err = p.SubmitUserInput(context.Background(), map[string]string{loginFieldTwoFactorCode: "123456"})
			require.NoError(t, err)
			assert.Equal(t, bridgev2.LoginStepTypeComplete, step.Type)
			assert.Equal(t, 1, completed)
			_, err = p.SubmitUserInput(context.Background(), map[string]string{loginFieldQR: qrSyntheticURL})
			assert.ErrorIs(t, err, context.Canceled)
		})
	}
}

func TestSlackQRDoesNotFollowUnsafeRedirects(t *testing.T) {
	targets := []string{"https://idp.example.invalid/login", "http://acme.slack.com/login", "https://acme.slack.com:8080/login", "https://user:password@acme.slack.com/login", "slack://signin", "https://acme.slack.com.evil.invalid/login"}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			calls := 0
			a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
				calls++
				return qrResponse(r, 302, "", "Location", target), nil
			})
			_, err := a.begin(context.Background(), qrSyntheticURL)
			require.Error(t, err)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestSlackQRConfirmationOriginAndPathPinned(t *testing.T) {
	for _, target := range []string{"https://other.slack.com" + qrSyntheticPath, "https://acme.slack.com/prefix" + qrSyntheticPath, "https://acme.slack.com/login/z-app-other"} {
		t.Run(target, func(t *testing.T) {
			a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
				if r.URL.Hostname() == "app.slack.com" {
					return qrResponse(r, 302, "", "Location", target), nil
				}
				assert.Equal(t, http.MethodGet, r.Method)
				return qrResponse(r, 200, qrProps("synthetic")), nil
			})
			_, err := a.begin(context.Background(), qrSyntheticURL)
			require.ErrorIs(t, err, errSlackQRBrowser)
		})
	}
}

func TestSlackQRDoesNotReplayConfirmationPost(t *testing.T) {
	a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return qrResponse(r, 307, "", "Location", "https://other.slack.com/steal"), nil
		}
		if r.URL.Hostname() == "app.slack.com" {
			return qrResponse(r, 302, "", "Location", "https://acme.slack.com"+qrSyntheticPath), nil
		}
		require.Equal(t, "acme.slack.com", r.URL.Hostname())
		return qrResponse(r, 200, qrProps("synthetic")), nil
	})
	result, err := a.begin(context.Background(), qrSyntheticURL)
	require.NoError(t, err)
	_, err = a.confirm(context.Background(), result.challenge, "123456")
	require.ErrorIs(t, err, errSlackQRBrowser)
}

func TestSlackQRFailuresDoNotExposeSecrets(t *testing.T) {
	a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("synthetic-secret in " + r.URL.String())
	})
	_, err := a.begin(context.Background(), qrSyntheticURL)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "synthetic-secret")
	assert.NotContains(t, err.Error(), "https://")
	p := &SlackQRLogin{api: a}
	step, err := p.SubmitUserInput(context.Background(), map[string]string{loginFieldQR: qrSyntheticURL})
	require.NoError(t, err)
	assert.NotContains(t, step.Instructions, "synthetic-secret")
}

func TestSlackQRCancelStopsRequestAndCompletion(t *testing.T) {
	entered := make(chan struct{})
	a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	p := &SlackQRLogin{api: a, complete: func(context.Context, *bridgev2.User, string, string) (*bridgev2.LoginStep, error) {
		t.Error("cancelled process completed")
		return nil, nil
	}}
	done := make(chan error, 1)
	go func() {
		_, err := p.SubmitUserInput(context.Background(), map[string]string{loginFieldQR: qrSyntheticURL})
		done <- err
	}()
	<-entered
	p.Cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt request")
	}
	_, err := p.SubmitUserInput(context.Background(), map[string]string{loginFieldQR: qrSyntheticURL})
	require.ErrorIs(t, err, context.Canceled)
}

func TestSlackQRRedirectLimit(t *testing.T) {
	calls := 0
	a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		calls++
		return qrResponse(r, 302, "", "Location", qrSyntheticURL), nil
	})
	_, err := a.begin(context.Background(), qrSyntheticURL)
	require.Error(t, err)
	assert.Equal(t, slackQRMaxHops, calls)
}

func TestSlackQRRetryClearsOldCookie(t *testing.T) {
	second := false
	a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		if second {
			assert.Empty(t, r.Header.Get("Cookie"))
			return qrResponse(r, 200, "Link Expired"), nil
		}
		if r.URL.Path == "/ssb/redirect" {
			return qrResponse(r, 200, `{"api_token":"xoxc-synthetic"}`), nil
		}
		return qrResponse(r, 302, "", "Set-Cookie", "d=xoxd-synthetic; Domain=.slack.com; Path=/; Secure", "Location", "https://acme.slack.com/client"), nil
	})
	_, err := a.begin(context.Background(), qrSyntheticURL)
	require.NoError(t, err)
	second = true
	_, err = a.begin(context.Background(), qrSyntheticURL)
	require.Error(t, err)
}

func TestSlackQRConfirmationRejectsForgedState(t *testing.T) {
	link, err := parseSlackQRLink(qrSyntheticURL)
	require.NoError(t, err)
	wrong, _ := url.Parse("https://evil.invalid" + qrSyntheticPath)
	a := qrTestAPI(func(*http.Request) (*http.Response, error) { t.Fatal("forged state reached network"); return nil, nil })
	_, err = a.confirm(context.Background(), &slackQRChallenge{url: wrong, link: link}, "123456")
	require.ErrorIs(t, err, errSlackQRInvalid)
}
