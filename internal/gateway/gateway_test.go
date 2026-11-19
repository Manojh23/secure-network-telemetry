package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*API, *Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reports.jsonl")
	s, e := Open(path, 10000)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	keys := map[string]Credential{"a-key": {"alpha", strings.Repeat("a", 32)}, "b-key": {"beta", strings.Repeat("b", 32)}}
	a, e := New(s, keys, 32, nil)
	if e != nil {
		t.Fatal(e)
	}
	return a, s, path
}
func sample() Report {
	return Report{ID: "report-1", Site: "boston", Target: "gateway.example.test:443", Protocol: "tls", ObservedAt: time.Now().Unix(), Success: true, LatencyMS: 12}
}
func encode(r Report) []byte { b, _ := json.Marshal(r); return b }
func signed(a *API, method, uri, key, nonce string, b []byte) *http.Request {
	r := httptest.NewRequest(method, uri, bytes.NewReader(b))
	stamp := strconv.FormatInt(a.now().Unix(), 10)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Key-ID", key)
	r.Header.Set("X-Timestamp", stamp)
	r.Header.Set("X-Nonce", nonce)
	r.Header.Set("X-Signature", Signature(a.keys[key].Secret, key, method, uri, stamp, nonce, b))
	return r
}
func call(a *API, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestIdempotencyAndPayloadConflict(t *testing.T) {
	a, s, _ := fixture(t)
	r := sample()
	for i, want := range []int{201, 200} {
		w := call(a, signed(a, "POST", "/v1/reports", "a-key", fmt.Sprint(i), encode(r)))
		if w.Code != want {
			t.Fatalf("%d: %s", w.Code, w.Body)
		}
	}
	r.LatencyMS++
	if w := call(a, signed(a, "POST", "/v1/reports", "a-key", "conflict", encode(r))); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if len(s.List("alpha", 0)) != 1 {
		t.Fatal("duplicate report persisted")
	}
}
func TestTenantIsolation(t *testing.T) {
	a, _, _ := fixture(t)
	b := encode(sample())
	call(a, signed(a, "POST", "/v1/reports", "a-key", "write", b))
	w := call(a, signed(a, "GET", "/v1/summary", "b-key", "read", nil))
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal(w.Code, w.Body)
	}
	w = call(a, signed(a, "POST", "/v1/reports", "b-key", "write", b))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestSignatureBindsPayloadAndQuery(t *testing.T) {
	a, _, _ := fixture(t)
	r := signed(a, "POST", "/v1/reports", "a-key", "body", encode(sample()))
	r.Body = io.NopCloser(strings.NewReader(`{}`))
	if w := call(a, r); w.Code != 401 {
		t.Fatal(w.Code)
	}
	r = signed(a, "GET", "/v1/summary?since=0", "a-key", "query", nil)
	r.URL.RawQuery = "since=1"
	if w := call(a, r); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestReplayAndExpiredSignature(t *testing.T) {
	a, _, _ := fixture(t)
	for i, want := range []int{200, 409} {
		w := call(a, signed(a, "GET", "/v1/summary", "a-key", "same", nil))
		if w.Code != want {
			t.Fatal(i, w.Code)
		}
	}
	r := signed(a, "GET", "/v1/summary", "a-key", "old", nil)
	stamp := strconv.FormatInt(a.now().Unix()-121, 10)
	r.Header.Set("X-Timestamp", stamp)
	r.Header.Set("X-Signature", Signature(a.keys["a-key"].Secret, "a-key", "GET", "/v1/summary", stamp, "old", nil))
	if w := call(a, r); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestConcurrentDuplicateWrites(t *testing.T) {
	a, s, _ := fixture(t)
	r := encode(sample())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := call(a, signed(a, "POST", "/v1/reports", "a-key", fmt.Sprint(i), r))
			if w.Code != 201 && w.Code != 200 {
				t.Errorf("unexpected %d", w.Code)
			}
		}(i)
	}
	wg.Wait()
	if len(s.List("alpha", 0)) != 1 {
		t.Fatal("concurrent duplicates")
	}
}
func TestJournalRestartAndLock(t *testing.T) {
	_, s, p := fixture(t)
	r := sample()
	s.Put("alpha", r)
	if another, e := Open(p, 10000); e == nil {
		another.Close()
		t.Fatal("second writer obtained journal lock")
	}
	s.Close()
	again, e := Open(p, 10000)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	if rows := again.List("alpha", 0); len(rows) != 1 || rows[0] != r {
		t.Fatal(rows)
	}
	if created, e := again.Put("alpha", r); created || e != nil {
		t.Fatal(created, e)
	}
}
func TestCorruptJournalFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "broken.jsonl")
	os.WriteFile(p, []byte(`{"tenant":"alpha"`), 0600)
	if s, e := Open(p, 10000); e == nil {
		s.Close()
		t.Fatal("corruption accepted")
	}
}
func TestBackpressureAndBodyLimit(t *testing.T) {
	a, _, _ := fixture(t)
	for i := 0; i < cap(a.slots); i++ {
		a.slots <- struct{}{}
	}
	if w := call(a, signed(a, "GET", "/v1/summary", "a-key", "busy", nil)); w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal(w.Code)
	}
	for len(a.slots) > 0 {
		<-a.slots
	}
	if w := call(a, signed(a, "POST", "/v1/reports", "a-key", "large", bytes.Repeat([]byte("x"), 8193))); w.Code != 413 {
		t.Fatal(w.Code)
	}
}
func TestStrictValidation(t *testing.T) {
	a, _, _ := fixture(t)
	bad := []string{`{}`, string(encode(sample())) + ` {}`, strings.Replace(string(encode(sample())), `"tls"`, `"udp"`, 1), strings.Replace(string(encode(sample())), `"id":`, `"extra":1,"id":`, 1)}
	for i, b := range bad {
		if w := call(a, signed(a, "POST", "/v1/reports", "a-key", fmt.Sprint(i), []byte(b))); w.Code != 400 {
			t.Fatal(i, w.Code, w.Body)
		}
	}
}
func TestSummary(t *testing.T) {
	rows := []Report{}
	for i := 0; i < 20; i++ {
		r := sample()
		r.LatencyMS = float64(i + 1)
		r.Success = i != 0
		rows = append(rows, r)
	}
	s := Summarize(rows)[0]
	if s.Samples != 20 || s.Failures != 1 || s.Availability != .95 || s.P95MS != 20 || s.Degraded {
		t.Fatal(s)
	}
	rows[1].Success = false
	if !Summarize(rows)[0].Degraded {
		t.Fatal("failed to flag degraded route")
	}
}
func TestJournalCapacity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "full")
	s, e := Open(p, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r := sample()
	s.Put("alpha", r)
	r.ID = "second"
	if _, e := s.Put("alpha", r); e != ErrFull {
		t.Fatal(e)
	}
}
func TestTLS13AndTLS12Rejection(t *testing.T) {
	a, _, _ := fixture(t)
	server := httptest.NewUnstartedServer(a)
	server.TLS = TLSConfig()
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}, Timeout: time.Second}
	r, e := client.Get(server.URL + "/healthz")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.TLS.Version != tls.VersionTLS13 {
		t.Fatal("not TLS1.3")
	}
	legacy := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}}, Timeout: time.Second}
	if r, e = legacy.Get(server.URL + "/healthz"); e == nil {
		r.Body.Close()
		t.Fatal("TLS1.2 accepted")
	}
}
