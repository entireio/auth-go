package tokenmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/entireio/auth-go/refresh"
	"github.com/entireio/auth-go/tokens"
)

func TestRunRefresh_NoRefreshPath(t *testing.T) {
	t.Parallel()
	m, err := New(Config{Issuer: testIssuer, ClientID: testClientID, Store: newMemStore()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No RefreshPath, no override → ErrNoRefreshPath.
	if _, err := m.runRefresh(context.Background(), "rt"); !errors.Is(err, ErrNoRefreshPath) {
		t.Fatalf("err = %v, want ErrNoRefreshPath", err)
	}
}

func TestRunRefresh_OverrideReceivesClientIDOnBothSurfaces(t *testing.T) {
	t.Parallel()
	m, err := New(Config{Issuer: testIssuer, ClientID: testClientID, RefreshPath: "/oauth/token", Store: newMemStore()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var got refresh.Request
	SetRefreshForTest(t, m, func(_ context.Context, req refresh.Request) (*tokens.TokenSet, error) {
		got = req
		return &tokens.TokenSet{AccessToken: "x"}, nil
	})
	if _, err := m.runRefresh(context.Background(), "rt-1"); err != nil {
		t.Fatalf("runRefresh: %v", err)
	}
	if got.RefreshToken != "rt-1" {
		t.Errorf("RefreshToken = %q, want rt-1", got.RefreshToken)
	}
	if got.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q (Basic-auth surface)", got.ClientID, testClientID)
	}
	if got.Extra.Get("client_id") != testClientID {
		t.Errorf("Extra client_id = %q, want %q (form surface)", got.Extra.Get("client_id"), testClientID)
	}
}

func TestProcessLock_DefaultDerivesPerIdentityPath(t *testing.T) {
	t.Parallel()
	m1, _ := New(Config{Issuer: testIssuer, ClientID: "cli-a", Store: newMemStore()})
	m2, _ := New(Config{Issuer: testIssuer, ClientID: "cli-b", Store: newMemStore()})
	m3, _ := New(Config{Issuer: testIssuer, ClientID: "cli-a", Store: newMemStore()})

	p1 := m1.processLock().(*fileLockPath).path
	p2 := m2.processLock().(*fileLockPath).path
	p3 := m3.processLock().(*fileLockPath).path
	if p1 == p2 {
		t.Fatal("different ClientIDs must derive different lock paths")
	}
	if p1 != p3 {
		t.Fatal("same (ClientID, Issuer) must derive the same lock path")
	}
}
