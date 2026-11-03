// SPDX-License-Identifier: AGPL-3.0-or-later
package connector

import (
	"context"
	"errors"
	"strings"
	"sync"

	"maunium.net/go/mautrix/bridgev2"
)

const (
	LoginFlowIDQR = "qr"
	LoginStepIDQR = "fi.mau.slack.login.enter_qr_link"
	loginFieldQR  = "login_url"
)

// Each process owns a fresh cookie jar; no browser or existing bridge session is read.
type SlackQRLogin struct {
	User      *bridgev2.User
	api       *slackQRAPI
	complete  slackLoginCompleter
	challenge *slackQRChallenge
	submitMu  sync.Mutex
	mu        sync.Mutex
	cancel    context.CancelFunc
	ended     bool
}

var _ bridgev2.LoginProcessUserInput = (*SlackQRLogin)(nil)

func (s *SlackQRLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	return slackQRStep("Scan Slack's Sign in on mobile QR code, or paste its one-time sign-in link."), nil
}

func (s *SlackQRLogin) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = true
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *SlackQRLogin) SubmitUserInput(parent context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return nil, context.Canceled
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); s.cancel = nil; s.mu.Unlock() }()
	if s.api == nil {
		s.api = newSlackQRAPI()
	}
	var result *slackQRResult
	var err error
	if s.challenge != nil {
		code := strings.TrimSpace(input[loginFieldTwoFactorCode])
		if !slackTwoFactorPattern.MatchString(code) {
			return slackTwoFactorStep("Enter the six-digit code Slack requires for this sign-in."), nil
		}
		result, err = s.api.confirm(ctx, s.challenge, code)
	} else {
		result, err = s.api.begin(ctx, strings.TrimSpace(input[loginFieldQR]))
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		s.challenge = nil
		instructions := "Slack could not complete that sign-in. Generate a fresh QR code, or cancel and choose another sign-in method."
		if errors.Is(err, errSlackQRInvalid) {
			instructions = "Enter an HTTPS Slack Sign in on mobile link, not an image address or another QR code."
		}
		if errors.Is(err, errSlackQRBrowser) {
			instructions = "Slack requires an additional browser or device approval. Complete the required verification in Slack, then try a fresh QR or another sign-in method."
		}
		return slackQRStep(instructions), nil
	}
	if result.challenge != nil {
		s.challenge = result.challenge
		return slackTwoFactorStep("Enter the six-digit authentication code Slack requires for this sign-in."), nil
	}
	complete := s.complete
	if complete == nil {
		complete = completeSlackEmailLogin
	}
	step, err := complete(ctx, s.User, result.token, result.cookie)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.challenge = nil
	if err != nil {
		// Never return a transport error containing a one-time URL, token or cookie.
		return slackQRStep("The bridge could not validate the Slack session. Try a fresh QR or another sign-in method."), nil
	}
	s.mu.Lock()
	s.ended = true
	s.mu.Unlock()
	return step, nil
}

func slackQRStep(instructions string) *bridgev2.LoginStep {
	return &bridgev2.LoginStep{
		Type: bridgev2.LoginStepTypeUserInput, StepID: LoginStepIDQR, Instructions: instructions,
		UserInputParams: &bridgev2.LoginUserInputParams{Fields: []bridgev2.LoginInputDataField{{
			Type: bridgev2.LoginInputFieldTypePassword, ID: loginFieldQR, Name: "Slack sign-in link",
		}}},
	}
}
