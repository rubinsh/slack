// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"maunium.net/go/mautrix/bridgev2"
)

const qrDiagnosticCanary = "PRIVATE-provider-body-and-error"

func qrDiagnosticContext() (context.Context, *bytes.Buffer) {
	buffer := new(bytes.Buffer)
	logger := zerolog.New(buffer)
	return logger.WithContext(context.Background()), buffer
}

func assertQRDiagnostic(t *testing.T, buffer *bytes.Buffer, reason, phase string, status, hop int) {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &got), "expected exactly one JSON diagnostic")
	assert.Equal(t, map[string]any{
		"level": "warn", "message": "Slack QR sign-in could not advance",
		"qr_reason": reason, "qr_phase": phase, "http_status": float64(status), "hop": float64(hop),
	}, got)
	for _, secret := range []string{
		qrDiagnosticCanary, "z-app-123", "https://", "acme.slack.com", "app.slack.com",
		"test@example.invalid", "synthetic-magic", "xoxc-synthetic", "xoxd-synthetic", "123456", "UTEST", "TTEST",
	} {
		assert.NotContains(t, buffer.String(), secret)
	}
}

func qrDiagnosticLanding(body string) qrTestTransport {
	return func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "app.slack.com" {
			return qrResponse(r, 302, "", "Location", "https://acme.slack.com"+qrSyntheticPath), nil
		}
		return qrResponse(r, 200, body), nil
	}
}

func qrDiagnosticSession(t *testing.T, reply qrTestTransport) qrTestTransport {
	return func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "app.slack.com" {
			return qrResponse(r, 200, qrDiagnosticCanary, "Set-Cookie", "d=xoxd-synthetic; Domain=.slack.com; Path=/; Secure"), nil
		}
		require.Equal(t, "/ssb/redirect", r.URL.Path)
		return reply(r)
	}
}

func TestSlackQRDiagnosticsDistinguishBrowserFallbacks(t *testing.T) {
	cases := []struct {
		name, reason, phase string
		status, hop         int
		transport           qrTestTransport
	}{
		{"unexpected landing", "unexpected_challenge_route", "begin", 200, 1, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 200, qrDiagnosticCanary), nil
		}},
		{"missing props", "missing_challenge_props", "begin", 200, 2, qrDiagnosticLanding(qrDiagnosticCanary)},
		{"invalid props", "invalid_challenge_props", "begin", 200, 2, qrDiagnosticLanding(`<div id="props_node" data-props="` + qrDiagnosticCanary + `"></div>`)},
		{"missing fields", "missing_challenge_fields", "begin", 200, 2, qrDiagnosticLanding(`<div id="props_node" data-props="{&quot;emailAddress&quot;:&quot;test@example.invalid&quot;}"></div>`)},
		{"unsafe redirect", "unsafe_redirect", "begin", 302, 1, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 302, qrDiagnosticCanary, "Location", "https://idp.example.invalid/"+qrDiagnosticCanary+"?code=123456"), nil
		}},
		{"session token", "missing_session_token", "session", 200, 1, qrDiagnosticSession(t, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 200, qrDiagnosticCanary), nil
		})},
		{"session redirect", "unsafe_redirect", "session", 302, 1, qrDiagnosticSession(t, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 302, qrDiagnosticCanary, "Location", "https://idp.example.invalid/"+qrDiagnosticCanary), nil
		})},
		{"session missing location", "missing_redirect", "session", 302, 1, qrDiagnosticSession(t, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 302, qrDiagnosticCanary), nil
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, buffer := qrDiagnosticContext()
			_, err := qrTestAPI(tc.transport).begin(ctx, qrSyntheticURL)
			require.ErrorIs(t, err, errSlackQRBrowser)
			assertQRDiagnostic(t, buffer, tc.reason, tc.phase, tc.status, tc.hop)
		})
	}
}

type qrBrokenBody struct{}

func (qrBrokenBody) Read([]byte) (int, error) { return 0, errors.New(qrDiagnosticCanary) }
func (qrBrokenBody) Close() error             { return nil }

func TestSlackQRDiagnosticsDistinguishRequestAndLimitFailures(t *testing.T) {
	cases := []struct {
		name, reason string
		status, hop  int
		transport    qrTestTransport
	}{
		{"transport", "transport_failed", 0, 1, func(r *http.Request) (*http.Response, error) {
			return nil, errors.New(qrDiagnosticCanary + r.URL.String())
		}},
		{"http status", "http_status_failed", 429, 1, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 429, qrDiagnosticCanary), nil
		}},
		{"body read", "response_read_failed", 200, 1, func(r *http.Request) (*http.Response, error) {
			response := qrResponse(r, 200, "")
			response.Body = qrBrokenBody{}
			return response, nil
		}},
		{"body limit", "response_too_large", 200, 1, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 200, strings.Repeat("x", slackLoginMaxResponseSize+1)), nil
		}},
		{"missing redirect", "missing_redirect", 302, 1, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 302, qrDiagnosticCanary), nil
		}},
		{"redirect limit", "redirect_limit", 0, slackQRMaxHops, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 302, qrDiagnosticCanary, "Location", qrSyntheticURL), nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, buffer := qrDiagnosticContext()
			_, err := qrTestAPI(tc.transport).begin(ctx, qrSyntheticURL)
			require.ErrorIs(t, err, errSlackQRFailed)
			assert.NotContains(t, err.Error(), qrDiagnosticCanary)
			assertQRDiagnostic(t, buffer, tc.reason, "begin", tc.status, tc.hop)
		})
	}
}

func TestSlackQRDiagnosticsConfirmationAndCompletion(t *testing.T) {
	t.Run("blocked confirmation replay", func(t *testing.T) {
		ctx, buffer := qrDiagnosticContext()
		a := qrTestAPI(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPost {
				return qrResponse(r, 307, qrDiagnosticCanary, "Location", "https://acme.slack.com/"+qrDiagnosticCanary), nil
			}
			return qrDiagnosticLanding(qrProps("synthetic-magic"))(r)
		})
		result, err := a.begin(ctx, qrSyntheticURL)
		require.NoError(t, err)
		require.Empty(t, buffer.String())
		_, err = a.confirm(ctx, result.challenge, "123456")
		require.ErrorIs(t, err, errSlackQRBrowser)
		assertQRDiagnostic(t, buffer, "post_replay_blocked", "confirm", 307, 1)
	})
	t.Run("cookie disappeared", func(t *testing.T) {
		ctx, buffer := qrDiagnosticContext()
		a := qrTestAPI(qrDiagnosticSession(t, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 200, `{"api_token":"xoxc-synthetic"}`, "Set-Cookie", "d=; Max-Age=-1; Domain=.slack.com; Path=/; Secure"), nil
		}))
		_, err := a.begin(ctx, qrSyntheticURL)
		require.ErrorIs(t, err, errSlackQRFailed)
		assertQRDiagnostic(t, buffer, "missing_session_cookie", "session", 200, 1)
	})
	t.Run("completion validation", func(t *testing.T) {
		ctx, buffer := qrDiagnosticContext()
		a := qrTestAPI(qrDiagnosticSession(t, func(r *http.Request) (*http.Response, error) {
			return qrResponse(r, 200, `{"api_token":"xoxc-synthetic"}`), nil
		}))
		process := &SlackQRLogin{api: a, complete: func(context.Context, *bridgev2.User, string, string) (*bridgev2.LoginStep, error) {
			return nil, errors.New(qrDiagnosticCanary + " xoxc-synthetic xoxd-synthetic")
		}}
		step, err := process.SubmitUserInput(ctx, map[string]string{loginFieldQR: qrSyntheticURL})
		require.NoError(t, err)
		assert.Equal(t, LoginStepIDQR, step.StepID)
		assert.NotContains(t, step.Instructions, qrDiagnosticCanary)
		assertQRDiagnostic(t, buffer, "session_validation_failed", "complete", 0, 0)
	})
}

func TestSlackQRDiagnosticsInvalidInputAndRequest(t *testing.T) {
	t.Run("invalid initial link", func(t *testing.T) {
		ctx, buffer := qrDiagnosticContext()
		_, err := newSlackQRAPI().begin(ctx, "https://evil.invalid/"+qrDiagnosticCanary)
		require.ErrorIs(t, err, errSlackQRInvalid)
		assertQRDiagnostic(t, buffer, "invalid_link", "begin", 0, 0)
	})
	t.Run("forged confirmation", func(t *testing.T) {
		ctx, buffer := qrDiagnosticContext()
		_, err := newSlackQRAPI().confirm(ctx, nil, "123456")
		require.ErrorIs(t, err, errSlackQRInvalid)
		assertQRDiagnostic(t, buffer, "invalid_confirmation", "confirm", 0, 0)
	})
	for _, tc := range []struct{ name, target, method, reason string }{
		{"unsafe request", "http://app.slack.com/" + qrDiagnosticCanary, http.MethodGet, "unsafe_request"},
		{"request construction", qrSyntheticURL, "\n", "request_build_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, buffer := qrDiagnosticContext()
			target, err := url.Parse(tc.target)
			require.NoError(t, err)
			_, _, _, err = newSlackQRAPI().request(ctx, tc.method, target, nil, qrPhaseBegin, 1)
			expected := errSlackQRFailed
			if tc.reason == "unsafe_request" {
				expected = errSlackQRInvalid
			}
			require.ErrorIs(t, err, expected)
			assertQRDiagnostic(t, buffer, tc.reason, "begin", 0, 1)
		})
	}
}

func TestSlackQRDiagnosticsBoundMetadataAndIgnoreCancellation(t *testing.T) {
	ctx, buffer := qrDiagnosticContext()
	logSlackQRDiagnostic(ctx, slackQRReason(255), slackQRPhase(255), 999999, -999)
	assertQRDiagnostic(t, buffer, "unknown", "unknown", 0, 0)
	buffer.Reset()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	a := qrTestAPI(func(*http.Request) (*http.Response, error) { return nil, errors.New(qrDiagnosticCanary) })
	_, err := a.begin(cancelled, qrSyntheticURL)
	require.Error(t, err)
	assert.Empty(t, buffer.String())
}

func TestSlackQRDiagnosticsSuccessfulFlowIsSilent(t *testing.T) {
	ctx, buffer := qrDiagnosticContext()
	a := qrTestAPI(qrDiagnosticSession(t, func(r *http.Request) (*http.Response, error) {
		return qrResponse(r, 200, `{"api_token":"xoxc-synthetic"}`), nil
	}))
	process := &SlackQRLogin{api: a, complete: func(context.Context, *bridgev2.User, string, string) (*bridgev2.LoginStep, error) {
		return &bridgev2.LoginStep{Type: bridgev2.LoginStepTypeComplete}, nil
	}}
	step, err := process.SubmitUserInput(ctx, map[string]string{loginFieldQR: qrSyntheticURL})
	require.NoError(t, err)
	assert.Equal(t, bridgev2.LoginStepTypeComplete, step.Type)
	assert.Empty(t, buffer.String())
}
