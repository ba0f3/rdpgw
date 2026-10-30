package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testRecord(subject string) Record {
	now := time.Now().UTC().Truncate(time.Second)
	return Record{Subject: subject, UserName: "alice", Host: "desktop:3389", AuthTime: now, ExpiresAt: now.Add(MaxLifetime)}
}

func TestCredentialPersistenceAndRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := testRecord("subject-alice")
	token, err := s.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(token)
	if err != nil || got.ExpiresAt.Sub(got.AuthTime) != 30*24*time.Hour {
		t.Fatalf("record=%+v error=%v", got, err)
	}
	if strings.Contains(token, got.ID) {
		t.Fatal("public ID must not expose bearer")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) {
		t.Fatal("database stores plaintext bearer")
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Lookup(token); err != nil {
		t.Fatal("restart invalidated credential", err)
	}
	if err := s.Revoke(got.ID, "someone-else"); err == nil {
		t.Fatal("cross-user revocation allowed")
	}
	if err := s.Revoke(got.ID, r.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(token); err == nil {
		t.Fatal("revoked credential accepted")
	}
	if _, err := s.Lookup(other); err != nil {
		t.Fatal("individual revoke affected another credential", err)
	}
	if err := s.RevokeUser(r.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(other); err == nil {
		t.Fatal("user revocation ignored")
	}
	if _, err := s.Issue(r); err == nil {
		t.Fatal("old web session issued replacement after user revocation")
	}
	r.Generation, err = s.Generation(r.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue(r); err != nil {
		t.Fatal("fresh login cannot issue", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Lookup(token); err == nil {
		t.Fatal("individual revocation lost after reopen")
	}
	if _, err := s.Lookup(other); err == nil {
		t.Fatal("user revocation lost after reopen")
	}
	if _, err := s.Lookup("c1_invalid"); err == nil {
		t.Fatal("unknown credential accepted")
	}
}

func TestExpiryAndAuthenticationBound(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "credentials.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := testRecord("alice")
	r.ExpiresAt = r.AuthTime.Add(MaxLifetime + time.Second)
	if _, err := s.Issue(r); err == nil {
		t.Fatal("credential exceeded authentication bound")
	}
	r = testRecord("alice")
	r.AuthTime = time.Now().Add(-MaxLifetime - time.Hour)
	r.ExpiresAt = time.Now().Add(-time.Hour)
	if _, err := s.Issue(r); err == nil {
		t.Fatal("expired authentication issued credential")
	}
	r = testRecord("alice")
	token, err := s.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return r.ExpiresAt }
	if _, err := s.Lookup(token); err == nil {
		t.Fatal("accepted at exact expiry")
	}
}

func TestConcurrentIssuanceCannotEscapeUserRevocation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "credentials.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := testRecord("alice")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Issue(r) }()
	}
	if err := s.RevokeUser(r.Subject); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	listed, err := s.List(r.Subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range listed {
		if !record.Revoked {
			t.Fatal("concurrent issuance escaped revocation")
		}
	}
}
