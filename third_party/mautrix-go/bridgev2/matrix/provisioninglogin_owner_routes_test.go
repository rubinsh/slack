package matrix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/id"
)

type ownerRouteProcess struct{ calls atomic.Int32 }

func ownerRouteStep(stepID string) *bridgev2.LoginStep {
	return &bridgev2.LoginStep{
		Type: bridgev2.LoginStepTypeUserInput, StepID: stepID,
		UserInputParams: &bridgev2.LoginUserInputParams{CanCancel: true},
	}
}

func (p *ownerRouteProcess) Start(context.Context) (*bridgev2.LoginStep, error) {
	return ownerRouteStep("input"), nil
}
func (p *ownerRouteProcess) Cancel() { p.calls.Add(1) }
func (p *ownerRouteProcess) SubmitUserInput(context.Context, map[string]string) (*bridgev2.LoginStep, error) {
	p.calls.Add(1)
	return ownerRouteStep("next"), nil
}
func (p *ownerRouteProcess) CancelStep(context.Context) (*bridgev2.LoginStep, error) {
	p.calls.Add(1)
	return ownerRouteStep("next"), nil
}

// Both requesters have login permission; only ownership differs.
func TestOwnedProcessRoutes(t *testing.T) {
	owner := id.UserID("@alice:example.org")
	other := id.UserID("@bob:example.org")
	for _, route := range []string{"step", "step_cancel", "cancel", "client_http"} {
		for _, requester := range []id.UserID{owner, other} {
			t.Run(route+"/"+string(requester), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				process := &ownerRouteProcess{}
				login := &ProvLogin{
					ID: "owned", Owner: owner, Process: process, Ctx: ctx, CancelCtx: cancel,
					step: &stepManager{next: ownerRouteStep("input")},
				}
				prov := &ProvisioningAPI{logins: map[string]*ProvLogin{"owned": login}}
				path := map[string]string{"loginProcessID": "owned", "stepID": "input", "stepType": "user_input"}
				body := `{"code":"synthetic"}`
				var handler http.HandlerFunc
				switch route {
				case "step":
					handler = prov.PostLoginStep
				case "step_cancel":
					handler = prov.PostLoginStepCancel
				case "cancel":
					handler = prov.PostLoginCancel
				case "client_http":
					handler = prov.PostLoginClientHTTP
					path["txnID"], path["reqID"] = "transaction", "request"
					login.step.next = &bridgev2.LoginStep{
						Type: bridgev2.LoginStepTypeClientHTTP, StepID: "request", TxnID: "transaction",
						ClientHTTPParams: &bridgev2.LoginClientHTTPParams{RequestID: "request"},
					}
					pending := make(chan *bridgev2.LoginClientHTTPResponse, 1)
					login.step.pendingHTTP = pending
					payload, err := json.Marshal(&bridgev2.LoginClientHTTPResponse{StatusCode: http.StatusOK, Body: []byte("synthetic")})
					if err != nil {
						t.Fatal(err)
					}
					body = string(payload)
					go func() {
						select {
						case <-pending:
							process.calls.Add(1)
							login.step.WithNonErroringLock(func(sm *stepManager) {
								finishStep(sm, ownerRouteStep("next"), login)
							})
						case <-ctx.Done():
						}
					}()
				}
				req := provRequest(http.MethodPost, "/", requester, path, body)
				requestCtx, requestCancel := context.WithTimeout(req.Context(), 5*time.Second)
				defer requestCancel()
				w := httptest.NewRecorder()
				handler(w, req.WithContext(requestCtx))
				if requester != owner {
					if w.Code != http.StatusNotFound || process.calls.Load() != 0 || ctx.Err() != nil {
						t.Fatalf("foreign request: status=%d calls=%d context=%v", w.Code, process.calls.Load(), ctx.Err())
					}
					if prov.logins["owned"] != login || login.step.next.StepID == "next" {
						t.Fatal("foreign request changed process or step")
					}
				} else {
					if w.Code != http.StatusOK || process.calls.Load() != 1 {
						t.Fatalf("owner request: status=%d calls=%d body=%s", w.Code, process.calls.Load(), w.Body.String())
					}
					if route == "cancel" {
						if prov.logins["owned"] != nil || ctx.Err() == nil {
							t.Fatal("owner cancellation did not remove and cancel process")
						}
					} else if login.step.next.StepID != "next" {
						t.Fatal("owner request did not advance step")
					}
				}
			})
		}
	}
}

type ownerStartConnector struct {
	bridgev2.NetworkConnector
	process bridgev2.LoginProcess
}

func (n *ownerStartConnector) CreateLogin(context.Context, *bridgev2.User, string) (bridgev2.LoginProcess, error) {
	return n.process, nil
}

func TestLoginStartRecordsAuthenticatedOwner(t *testing.T) {
	owner := id.UserID("@alice:example.org")
	prov := &ProvisioningAPI{
		br:     &Connector{Bridge: &bridgev2.Bridge{BackgroundCtx: context.Background()}},
		net:    &ownerStartConnector{process: &ownerRouteProcess{}},
		logins: make(map[string]*ProvLogin),
	}
	w := httptest.NewRecorder()
	prov.PostLoginStart(w, provRequest(http.MethodPost, "/", owner, map[string]string{"flowID": "synthetic"}, "{}"))
	if w.Code != http.StatusOK {
		t.Fatalf("start: status=%d body=%s", w.Code, w.Body.String())
	}
	var response RespSubmitLogin
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	login := prov.logins[response.LoginID]
	if login == nil {
		t.Fatal("start did not register process")
	}
	t.Cleanup(func() { prov.deleteLogin(login, true, ErrLoginCancelled) })
	if login.Owner != owner {
		t.Fatalf("owner=%q, want authenticated user %q", login.Owner, owner)
	}
}
