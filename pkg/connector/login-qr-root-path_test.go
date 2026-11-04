// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlackQRRootAndLegacyConfirmationPathsAreExact(t *testing.T) {
	link, err := parseSlackQRLink(qrSyntheticURL)
	require.NoError(t, err)
	root := "/" + link.secret
	for _, path := range []string{root, qrSyntheticPath} {
		target, err := url.Parse("https://acme.slack.com" + path + "?ignored=synthetic")
		require.NoError(t, err)
		assert.True(t, qrConfirmationURL(target, link))
	}
	for _, tc := range []struct{ name, target string }{
		{"foreign workspace root", "https://other.slack.com" + root},
		{"foreign workspace legacy", "https://other.slack.com" + qrSyntheticPath},
		{"host suffix attack", "https://acme.slack.com.evil.invalid" + root},
		{"insecure", "http://acme.slack.com" + root},
		{"foreign port", "https://acme.slack.com:444" + root},
		{"userinfo", "https://user:password@acme.slack.com" + root},
		{"root prefix", "https://acme.slack.com/attacker" + root},
		{"legacy prefix", "https://acme.slack.com/attacker" + qrSyntheticPath},
		{"trailing slash", "https://acme.slack.com" + root + "/"},
		{"trailing component", "https://acme.slack.com" + root + "/extra"},
		{"different root secret", "https://acme.slack.com/z-app-other"},
		{"different legacy secret", "https://acme.slack.com/login/z-app-other"},
		{"encoded root secret", "https://acme.slack.com/%7A" + strings.TrimPrefix(link.secret, "z")},
		{"encoded legacy secret", "https://acme.slack.com/login/%7A" + strings.TrimPrefix(link.secret, "z")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := url.Parse(tc.target)
			require.NoError(t, err)
			assert.False(t, qrConfirmationURL(target, link))
			api := qrTestAPI(func(*http.Request) (*http.Response, error) {
				t.Fatal("forged confirmation sent credentials to transport")
				return nil, nil
			})
			_, err = api.confirm(context.Background(), &slackQRChallenge{link: link, url: target, magic: "synthetic-magic", email: "test@example.invalid"}, "123456")
			require.ErrorIs(t, err, errSlackQRInvalid)
			challenge, reason := parseQRChallenge([]byte(qrProps("synthetic-magic")), target, link)
			assert.Nil(t, challenge)
			assert.Equal(t, qrUnexpectedChallengeRoute, reason)
		})
	}
	target, _ := url.Parse("https://acme.slack.com/")
	assert.False(t, qrConfirmationURL(target, &slackQRLink{workspace: "acme"}))
	assert.False(t, qrConfirmationURL(nil, link))
	assert.False(t, qrConfirmationURL(target, nil))
}
