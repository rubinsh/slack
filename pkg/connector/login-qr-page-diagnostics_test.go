// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlackQRDiagnosticPathClasses(t *testing.T) {
	link, err := parseSlackQRLink(qrSyntheticURL)
	require.NoError(t, err)
	for _, tc := range []struct{ path, class string }{
		{"/login/" + link.secret, "login_secret"}, {"/" + link.secret, "secret"},
		{"/", "root"}, {"", "root"}, {"/signin", "signin"}, {"/signin/" + link.secret, "signin"},
		{"/ssb/redirect", "ssb"}, {"/checkcookie", "checkcookie"}, {"/app-redir/" + link.secret, "app_redirect"},
		{"/client/TTEST", "client"}, {"/messages/UTEST", "messages"}, {"/login/another-" + link.secret, "login_other"},
		{"/signin-" + link.secret, "other"}, {"/" + link.secret + "/extra", "other"}, {"/login/%7A-app-123", "login_other"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			target, err := url.Parse("https://acme.slack.com" + tc.path + "?code=123456#" + qrDiagnosticCanary)
			require.NoError(t, err)
			assert.Equal(t, tc.class, slackQRPathClass(target, link).String())
		})
	}
	assert.Equal(t, "unknown", slackQRPathClass(nil, link).String())
	unsafe, _ := url.Parse("https://evil.invalid/" + link.secret)
	assert.Equal(t, "unknown", slackQRPathClass(unsafe, link).String())
}

func TestSlackQRDiagnosticPropsClassesArePersistedWithoutValues(t *testing.T) {
	for _, tc := range []struct{ class, body string }{
		{"not_found", qrDiagnosticCanary},
		{"invalid", `<div id="props_node" data-props="` + qrDiagnosticCanary + `"></div>`},
		{"invalid", `<div id="props_node" data-props='{"magicLogin":123456,"emailAddress":"test@example.invalid"}'></div>`},
		{"incomplete", `<div id="props_node" data-props='{"magicLogin":"synthetic-magic"}'></div>`},
		{"present", qrProps("synthetic-magic")},
	} {
		t.Run(tc.class, func(t *testing.T) {
			ctx, buffer := qrDiagnosticContext()
			api := qrTestAPI(func(r *http.Request) (*http.Response, error) {
				if r.URL.Hostname() == "app.slack.com" {
					return qrResponse(r, 302, "", "Location", "https://acme.slack.com/signin/"+qrDiagnosticCanary+"?code=123456"), nil
				}
				return qrResponse(r, 200, tc.body), nil
			})
			result, err := api.begin(ctx, qrSyntheticURL)
			require.ErrorIs(t, err, errSlackQRBrowser)
			require.Nil(t, result) // Even complete properties do not authorize this path.
			var got map[string]any
			require.NoError(t, json.Unmarshal(buffer.Bytes(), &got))
			assert.Equal(t, "signin", got["path_class"])
			assert.Equal(t, tc.class, got["props_class"])
			assertQRDiagnostic(t, buffer, "unexpected_challenge_route", "begin", 200, 2)
		})
	}
}

func TestSlackQRDiagnosticCompletePropsDoNotRelaxRouteOrOrigin(t *testing.T) {
	link, err := parseSlackQRLink(qrSyntheticURL)
	require.NoError(t, err)
	for _, tc := range []struct{ landing, route, path string }{
		{"https://acme.slack.com/" + link.secret, "workspace", "secret"},
		{"https://other.slack.com/login/" + link.secret, "other_slack", "login_secret"},
	} {
		t.Run(tc.route, func(t *testing.T) {
			ctx, buffer := qrDiagnosticContext()
			requests := 0
			api := qrTestAPI(func(r *http.Request) (*http.Response, error) {
				requests++
				require.Equal(t, http.MethodGet, r.Method)
				switch requests {
				case 1:
					return qrResponse(r, 302, "", "Location", "https://app.slack.com/app-redir/"+link.secret), nil
				case 2:
					return qrResponse(r, 302, "", "Location", tc.landing), nil
				default:
					return qrResponse(r, 200, qrProps("synthetic-magic")), nil
				}
			})
			result, err := api.begin(ctx, qrSyntheticURL)
			require.ErrorIs(t, err, errSlackQRBrowser)
			require.Nil(t, result)
			require.Equal(t, 3, requests)
			var got map[string]any
			require.NoError(t, json.Unmarshal(buffer.Bytes(), &got))
			assert.Equal(t, tc.route, got["route_class"])
			assert.Equal(t, tc.path, got["path_class"])
			assert.Equal(t, "present", got["props_class"])
			assert.Equal(t, false, got["has_d_cookie"])
			assertQRDiagnostic(t, buffer, "unexpected_challenge_route", "begin", 200, 3)
		})
	}
}
