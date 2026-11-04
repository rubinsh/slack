package matrix

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/id"
)

func TestLookupOwnedLogin(t *testing.T) {
	alice := id.UserID("@alice:example.org")
	bob := id.UserID("@bob:example.org")
	prov := &ProvisioningAPI{logins: map[string]*ProvLogin{
		"a1": {ID: "a1", Owner: alice},
	}}

	if login, ok := prov.lookupOwnedLogin("a1", alice); !ok || login.ID != "a1" {
		t.Fatalf("owner should get their own login, got %v %v", login, ok)
	}
	if login, ok := prov.lookupOwnedLogin("a1", bob); ok || login != nil {
		t.Fatalf("another user must not get the login, got %v %v", login, ok)
	}
	if _, ok := prov.lookupOwnedLogin("a1", ""); ok {
		t.Fatal("an empty user ID must not match")
	}
	if _, ok := prov.lookupOwnedLogin("missing", alice); ok {
		t.Fatal("an unknown ID must not be found")
	}
}

func TestLookupOwnedLoginRejectsUnownedProcess(t *testing.T) {
	// A process created without an owner (e.g. by code that predates the
	// field) must not be reachable by anyone.
	prov := &ProvisioningAPI{logins: map[string]*ProvLogin{"x": {ID: "x"}}}
	if _, ok := prov.lookupOwnedLogin("x", ""); ok {
		t.Fatal("ownerless process matched an empty user ID")
	}
	if _, ok := prov.lookupOwnedLogin("x", "@alice:example.org"); ok {
		t.Fatal("ownerless process matched a real user")
	}
}

type fakeLoginProcess struct{ cancelled bool }

func (f *fakeLoginProcess) Start(context.Context) (*bridgev2.LoginStep, error) { return nil, nil }
func (f *fakeLoginProcess) Cancel()                                            { f.cancelled = true }

func newOwnedTestLogin(prov *ProvisioningAPI, loginID string, owner id.UserID) *fakeLoginProcess {
	proc := &fakeLoginProcess{}
	ctx, cancel := context.WithCancel(context.Background())
	prov.logins[loginID] = &ProvLogin{
		ID: loginID, Process: proc, Owner: owner,
		step: &stepManager{started: true, wait: make(chan struct{})},
		Ctx:  ctx, CancelCtx: cancel,
	}
	return proc
}

func provRequest(method, target string, as id.UserID, pathValues map[string]string, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(body)), nil
	}
	for k, v := range pathValues {
		r.SetPathValue(k, v)
	}
	user := &bridgev2.User{User: &database.User{MXID: as}, Permissions: bridgeconfig.PermissionLevelUser}
	return r.WithContext(context.WithValue(r.Context(), provisioningUserKey, user))
}

// Every process-scoped handler must refuse another user's login process with
// 404 and leave it untouched.
func TestProcessScopedHandlersRejectOtherUsers(t *testing.T) {
	alice := id.UserID("@alice:example.org")
	bob := id.UserID("@bob:example.org")
	prov := &ProvisioningAPI{logins: map[string]*ProvLogin{}}
	proc := newOwnedTestLogin(prov, "a1", alice)

	cases := []struct {
		name    string
		handler http.HandlerFunc
		path    map[string]string
		body    string
	}{
		{"step", prov.PostLoginStep, map[string]string{"loginProcessID": "a1", "stepID": "s", "stepType": "user_input"}, `{"code":"123"}`},
		{"step cancel", prov.PostLoginStepCancel, map[string]string{"loginProcessID": "a1", "stepID": "s"}, ""},
		{"cancel", prov.PostLoginCancel, map[string]string{"loginProcessID": "a1"}, ""},
		{"client http", prov.PostLoginClientHTTP, map[string]string{"loginProcessID": "a1", "txnID": "t", "reqID": "r"}, "{}"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		c.handler(w, provRequest(http.MethodPost, "/", bob, c.path, c.body))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: other user got status %d, want 404", c.name, w.Code)
		}
	}
	if _, ok := prov.logins["a1"]; !ok || proc.cancelled {
		t.Fatal("another user's requests changed the owner's login process")
	}

	// Positive control: the owner can still cancel their own login.
	w := httptest.NewRecorder()
	prov.PostLoginCancel(w, provRequest(http.MethodPost, "/", alice, map[string]string{"loginProcessID": "a1"}, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("owner cancel got status %d, want 200", w.Code)
	}
	if _, ok := prov.logins["a1"]; ok || !proc.cancelled {
		t.Fatal("owner cancel did not cancel and remove the login process")
	}
}
