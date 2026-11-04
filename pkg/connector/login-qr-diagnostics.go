// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"context"

	"github.com/rs/zerolog"
)

type slackQRPhase uint8

const (
	qrPhaseBegin slackQRPhase = iota
	qrPhaseConfirm
	qrPhaseSession
	qrPhaseComplete
)

func (p slackQRPhase) String() string {
	names := [...]string{"begin", "confirm", "session", "complete"}
	if int(p) >= len(names) {
		return "unknown"
	}
	return names[p]
}

type slackQRReason uint8

const (
	qrReasonNone slackQRReason = iota
	qrInvalidLink
	qrCookieJarFailed
	qrInvalidConfirmation
	qrUnsafeRedirect
	qrMissingRedirect
	qrPostReplayBlocked
	qrUnexpectedChallengeRoute
	qrMissingChallengeProps
	qrInvalidChallengeProps
	qrMissingChallengeFields
	qrMissingSessionToken
	qrMissingSessionCookie
	qrRedirectLimit
	qrUnsafeRequest
	qrRequestBuildFailed
	qrTransportFailed
	qrHTTPStatusFailed
	qrResponseReadFailed
	qrResponseTooLarge
	qrSessionValidationFailed
)

func (r slackQRReason) String() string {
	names := [...]string{
		"none", "invalid_link", "cookie_jar_failed", "invalid_confirmation",
		"unsafe_redirect", "missing_redirect", "post_replay_blocked",
		"unexpected_challenge_route", "missing_challenge_props", "invalid_challenge_props",
		"missing_challenge_fields", "missing_session_token", "missing_session_cookie",
		"redirect_limit", "unsafe_request", "request_build_failed", "transport_failed",
		"http_status_failed", "response_read_failed", "response_too_large", "session_validation_failed",
	}
	if int(r) >= len(names) {
		return "unknown"
	}
	return names[r]
}

// URL paths, response bodies and even transport errors may contain credentials.
// This boundary accepts only fixed enums and bounded numeric metadata.
func logSlackQRDiagnostic(ctx context.Context, reason slackQRReason, phase slackQRPhase, status, hop int) {
	if ctx.Err() != nil {
		return
	}
	if status < 100 || status > 599 {
		status = 0
	}
	if hop < 0 || hop > slackQRMaxHops {
		hop = 0
	}
	zerolog.Ctx(ctx).Warn().
		Str("qr_reason", reason.String()).
		Str("qr_phase", phase.String()).
		Int("http_status", status).
		Int("hop", hop).
		Msg("Slack QR sign-in could not advance")
}
