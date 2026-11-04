// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"maunium.net/go/mautrix/bridgev2"
)

func assertSlackQRRequestProfile(t *testing.T, r *http.Request) {
	t.Helper()
	assert.Equal(t, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36", r.Header.Get("User-Agent"))
	assert.Equal(t, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", r.Header.Get("Accept"))
	assert.Equal(t, "en-US,en;q=0.9", r.Header.Get("Accept-Language"))
}

func TestSlackQRProfileDoesNotChangeGlobalClient(t *testing.T) {
	before := slack.DefaultUserAgent
	api := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		assertSlackQRRequestProfile(t, r)
		return qrResponse(r, 200, ""), nil
	})
	_, err := api.begin(context.Background(), qrSyntheticURL)
	require.ErrorIs(t, err, errSlackQRBrowser)
	assert.Equal(t, before, slack.DefaultUserAgent)
}

func TestSlackQRRecognizedDenialPages(t *testing.T) {
	cases := []struct {
		name, body string
		reason     slackQRReason
	}{
		{"expired title", "<title>Link Expired</title>", qrLinkExpired},
		{"expired branded title", "<TITLE>  Link&#32;Expired | Slack </TITLE>", qrLinkExpired},
		{"expired heading", "<h1>Link <strong>Expired</strong></h1>", qrLinkExpired},
		{"expired alternate", "<h2>This link has expired</h2>", qrLinkExpired},
		{"other device heading", "<h1>Sign in on your other device</h1>", qrDeviceConfirmationRequired},
		{"other device title", "<title>Confirm this sign-in on your other device | Slack</title>", qrDeviceConfirmationRequired},
		{"generic confirm is not evidence", "<h1>Confirm your email</h1><p>Open Slack to continue.</p>", qrReasonNone},
		{"trouble signing in is not expiry proof", "<h1>We had trouble signing you in</h1>", qrReasonNone},
		{"ordinary link label", "<a>Link Expired</a>", qrReasonNone},
		{"script text", `<script>const html="<h1>Link Expired</h1>";</script>`, qrReasonNone},
		{"script in heading", `<h1><script>Link Expired</script>Sign in</h1>`, qrReasonNone},
		{"comment", "<!-- <h1>Link Expired</h1> -->", qrReasonNone},
		{"template", "<template><h1>Link Expired</h1></template>", qrReasonNone},
		{"nested template", "<template><template></template><h1>Link Expired</h1></template>", qrReasonNone},
		{"hidden heading", "<h1 hidden>Link Expired</h1>", qrReasonNone},
		{"hidden ancestor", "<div hidden><div></div><h1>Link Expired</h1></div>", qrReasonNone},
		{"aria hidden", `<h1 aria-hidden="TRUE">Link Expired</h1>`, qrReasonNone},
		{"inline hidden", `<h1 style="display: none">Link Expired</h1>`, qrReasonNone},
		{"additional title text", "<title>Link Expired documentation</title>", qrReasonNone},
		{"large heading", "<h1>" + strings.Repeat(" ", 513) + "Link Expired</h1>", qrReasonNone},
		{"incomplete heading", "<h1>Link Expired", qrReasonNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.reason, slackQRPageDenial([]byte(tc.body))) })
	}
}

func TestSlackQRDenialsKeepSecretsAndCompletionClosed(t *testing.T) {
	cases := []struct {
		name, body, reason, message string
		err                         error
	}{
		{"expired", "<title>Link Expired</title>", "link_expired", "expired", errSlackQRExpired},
		{"device", "<h1>Sign in on your other device</h1>", "device_confirmation_required", "confirm this sign-in", errSlackQRDevice},
		{"unknown", "<h1>Confirm</h1>", "unexpected_challenge_route", "could not complete here", errSlackQRBrowser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := func() *slackQRAPI {
				return qrTestAPI(func(r *http.Request) (*http.Response, error) {
					assertSlackQRRequestProfile(t, r)
					if r.URL.Hostname() == "app.slack.com" {
						return qrResponse(r, 302, "", "Location", "https://acme.slack.com/app-redir/synthetic"), nil
					}
					if r.URL.Path == "/app-redir/synthetic" {
						return qrResponse(r, 302, "", "Location", "/signin"), nil
					}
					require.Equal(t, "/signin", r.URL.Path)
					return qrResponse(r, 200, tc.body+"<p>"+qrDiagnosticCanary+" test@example.invalid xoxd-synthetic 123456</p>"), nil
				})
			}
			ctx, logs := qrDiagnosticContext()
			_, err := api().begin(ctx, qrSyntheticURL)
			require.ErrorIs(t, err, tc.err)
			assertQRDiagnostic(t, logs, tc.reason, "begin", 200, 3)
			completed := false
			process := &SlackQRLogin{api: api(), complete: func(context.Context, *bridgev2.User, string, string) (*bridgev2.LoginStep, error) {
				completed = true
				return nil, errors.New(qrDiagnosticCanary)
			}}
			ctx, logs = qrDiagnosticContext()
			step, err := process.SubmitUserInput(ctx, map[string]string{loginFieldQR: qrSyntheticURL})
			require.NoError(t, err)
			require.NotNil(t, step)
			assert.False(t, completed)
			assert.Nil(t, process.challenge)
			assert.Equal(t, LoginStepIDQR, step.StepID)
			assert.Equal(t, loginFieldQR, step.UserInputParams.Fields[0].ID)
			assert.Contains(t, step.Instructions, tc.message)
			assert.NotContains(t, step.Instructions, "requires an additional browser")
			for _, secret := range []string{qrDiagnosticCanary, qrSyntheticURL, "test@example.invalid", "xoxd-synthetic", "123456"} {
				assert.NotContains(t, step.Instructions, secret)
			}
			assertQRDiagnostic(t, logs, tc.reason, "begin", 200, 3)
		})
	}
}

func TestSlackQRDenialDoesNotBroadenConfirmationOrigin(t *testing.T) {
	ctx, logs := qrDiagnosticContext()
	api := qrTestAPI(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "app.slack.com" {
			return qrResponse(r, 302, "", "Location", "https://other.slack.com/signin"), nil
		}
		return qrResponse(r, 200, "<title>Link Expired</title>"+qrProps("synthetic-magic")), nil
	})
	_, err := api.begin(ctx, qrSyntheticURL)
	require.ErrorIs(t, err, errSlackQRBrowser)
	assertQRDiagnostic(t, logs, "unexpected_challenge_route", "begin", 200, 2)
}
