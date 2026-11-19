// Package gateway accepts signed network measurements. It never initiates probes.
package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Credential struct {
	Tenant string `json:"tenant"`
	Secret string `json:"secret"`
}
type Report struct {
	ID         string  `json:"id"`
	Site       string  `json:"site"`
	Target     string  `json:"target"`
	Protocol   string  `json:"protocol"`
	ObservedAt int64   `json:"observed_at"`
	Success    bool    `json:"success"`
	LatencyMS  float64 `json:"latency_ms"`
	Error      string  `json:"error,omitempty"`
}
type record struct {
	Tenant string `json:"tenant"`
	Report Report `json:"report"`
}

var ErrConflict = errors.New("report ID already has a different payload")
var ErrFull = errors.New("journal capacity reached")

// Store is a single-process, append-only journal. Acknowledgements follow fsync.
type Store struct {
	mu     sync.Mutex
	file   *os.File
	rows   map[string]record
	order  []string
	max    int
	broken bool
}

func Open(path string, max int) (*Store, error) {
	if max < 1 {
		return nil, errors.New("invalid store capacity")
	}
	f, e := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Store, error) { f.Close(); return nil, e }
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail(fmt.Errorf("journal already locked: %w", e))
	}
	// Read only one bounded line at a time, and reject truncated/corrupt records.
	s := &Store{file: f, rows: map[string]record{}, max: max}
	dec := json.NewDecoder(io.LimitReader(f, int64(max)*8192+1))
	for {
		var r record
		e = dec.Decode(&r)
		if e == io.EOF {
			break
		}
		if e != nil {
			return fail(fmt.Errorf("invalid journal: %w", e))
		}
		if r.Tenant == "" || validate(r.Report) != nil {
			return fail(errors.New("invalid journal record"))
		}
		k := r.Tenant + "/" + r.Report.ID
		if _, ok := s.rows[k]; ok {
			return fail(errors.New("duplicate journal record"))
		}
		if len(s.order) >= max {
			return fail(ErrFull)
		}
		s.rows[k] = r
		s.order = append(s.order, k)
	}
	if _, e = f.Seek(0, io.SeekEnd); e != nil {
		return fail(e)
	}
	return s, nil
}
func (s *Store) Close() error { return s.file.Close() }
func (s *Store) Put(tenant string, r Report) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken {
		return false, errors.New("journal requires restart and recovery")
	}
	k := tenant + "/" + r.ID
	if old, ok := s.rows[k]; ok {
		if old.Report != r {
			return false, ErrConflict
		}
		return false, nil
	}
	if len(s.order) >= s.max {
		return false, ErrFull
	}
	row := record{tenant, r}
	b, e := json.Marshal(row)
	if e != nil {
		return false, e
	}
	b = append(b, '\n')
	n, e := s.file.Write(b)
	if e != nil || n != len(b) {
		s.broken = true
		return false, errors.New("journal write failed")
	}
	if e = s.file.Sync(); e != nil {
		s.broken = true
		return false, e
	}
	s.rows[k] = row
	s.order = append(s.order, k)
	return true, nil
}
func (s *Store) List(tenant string, after int64) []Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Report{}
	for _, k := range s.order {
		r := s.rows[k]
		if r.Tenant == tenant && r.Report.ObservedAt >= after {
			out = append(out, r.Report)
		}
	}
	return out
}
func validID(s string) bool {
	if len(s) < 1 || len(s) > 100 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func validate(r Report) error {
	if !validID(r.ID) || !validID(r.Site) || len(r.Target) < 1 || len(r.Target) > 250 || len(r.Error) > 200 || r.ObservedAt <= 0 {
		return errors.New("invalid fields")
	}
	if r.Protocol != "tcp" && r.Protocol != "tls" {
		return errors.New("protocol must be tcp or tls")
	}
	if math.IsNaN(r.LatencyMS) || math.IsInf(r.LatencyMS, 0) || r.LatencyMS < 0 || r.LatencyMS > 60000 {
		return errors.New("invalid latency")
	}
	if r.Success && r.Error != "" {
		return errors.New("successful reports cannot have an error")
	}
	return nil
}

// Signature binds identity, method, exact URI (including query), freshness and body.
func Signature(secret, keyID, method, uri, timestamp, nonce string, body []byte) string {
	digest := sha256.Sum256(body)
	msg := strings.Join([]string{keyID, method, uri, timestamp, nonce, hex.EncodeToString(digest[:])}, "\n")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

type API struct {
	store  *Store
	keys   map[string]Credential
	slots  chan struct{}
	mu     sync.Mutex
	nonces map[string]int64
	now    func() time.Time
	log    *slog.Logger
}

func New(s *Store, keys map[string]Credential, parallel int, log *slog.Logger) (*API, error) {
	if len(keys) == 0 || parallel < 1 {
		return nil, errors.New("keys and concurrency are required")
	}
	copyKeys := map[string]Credential{}
	for id, k := range keys {
		if !validID(id) || !validID(k.Tenant) || len(k.Secret) < 32 {
			return nil, errors.New("invalid key configuration (minimum 32-byte secret)")
		}
		copyKeys[id] = k
	}
	return &API{store: s, keys: copyKeys, slots: make(chan struct{}, parallel), nonces: map[string]int64{}, now: time.Now, log: log}, nil
}
func (a *API) authenticate(r *http.Request, body []byte) (string, int) {
	id, ts, nonce := r.Header.Get("X-Key-ID"), r.Header.Get("X-Timestamp"), r.Header.Get("X-Nonce")
	k, ok := a.keys[id]
	stamp, e := strconv.ParseInt(ts, 10, 64)
	now := a.now().Unix()
	if !ok || e != nil || stamp < now-120 || stamp > now+30 || !validID(nonce) {
		return "", 401
	}
	supplied, e := hex.DecodeString(r.Header.Get("X-Signature"))
	if e != nil {
		return "", 401
	}
	want, _ := hex.DecodeString(Signature(k.Secret, id, r.Method, r.URL.RequestURI(), ts, nonce, body))
	if !hmac.Equal(supplied, want) {
		return "", 401
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for n, expiry := range a.nonces {
		if expiry < now {
			delete(a.nonces, n)
		}
	}
	key := id + "/" + nonce
	if _, ok := a.nonces[key]; ok {
		return "", 409
	}
	// Bound replay-cache memory independently of the journal/request semaphore.
	if len(a.nonces) >= 10000 {
		return "", 429
	}
	a.nonces[key] = stamp + 121
	return k.Tenant, 0
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rid := strconv.FormatInt(start.UnixNano(), 36)
	w.Header().Set("X-Request-ID", rid)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if a.log != nil {
			a.log.Info("request", "id", rid, "method", r.Method, "path", r.URL.Path, "elapsed_ms", time.Since(start).Milliseconds())
		}
	}()
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		reply(w, 200, map[string]string{"status": "up"})
		return
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		reply(w, 503, map[string]string{"error": "busy"})
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if e != nil {
		reply(w, 413, map[string]string{"error": "body too large"})
		return
	}
	tenant, status := a.authenticate(r, body)
	if status != 0 {
		reply(w, status, map[string]string{"error": "signature, freshness or replay check failed"})
		return
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/reports" && r.URL.RawQuery == "":
		if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
			reply(w, 415, map[string]string{"error": "JSON required"})
			return
		}
		var report Report
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if d.Decode(&report) != nil || d.Decode(new(any)) != io.EOF || validate(report) != nil || report.ObservedAt < a.now().Unix()-86400 || report.ObservedAt > a.now().Unix()+30 {
			reply(w, 400, map[string]string{"error": "invalid report"})
			return
		}
		created, e := a.store.Put(tenant, report)
		if e != nil {
			code := 503
			if errors.Is(e, ErrConflict) {
				code = 409
			}
			reply(w, code, map[string]string{"error": e.Error()})
			return
		}
		code := 200
		if created {
			code = 201
		}
		reply(w, code, map[string]any{"id": report.ID, "created": created})
	case r.Method == "GET" && r.URL.Path == "/v1/summary" && len(body) == 0:
		since := a.now().Unix() - 3600
		if raw := r.URL.Query().Get("since"); raw != "" {
			since, e = strconv.ParseInt(raw, 10, 64)
			if e != nil || since < 0 {
				reply(w, 400, map[string]string{"error": "invalid since"})
				return
			}
		}
		reply(w, 200, Summarize(a.store.List(tenant, since)))
	default:
		reply(w, 404, map[string]string{"error": "not found"})
	}
}

type Summary struct {
	Site         string  `json:"site"`
	Target       string  `json:"target"`
	Protocol     string  `json:"protocol"`
	Samples      int     `json:"samples"`
	Failures     int     `json:"failures"`
	Availability float64 `json:"availability"`
	P95MS        float64 `json:"p95_ms"`
	Degraded     bool    `json:"degraded"`
}

func Summarize(rows []Report) []Summary {
	groups := map[string][]Report{}
	for _, r := range rows {
		k := r.Site + "\x00" + r.Target + "\x00" + r.Protocol
		groups[k] = append(groups[k], r)
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []Summary{}
	for _, k := range keys {
		rs := groups[k]
		s := Summary{Site: rs[0].Site, Target: rs[0].Target, Protocol: rs[0].Protocol, Samples: len(rs)}
		lat := []float64{}
		for _, r := range rs {
			if !r.Success {
				s.Failures++
			} else {
				lat = append(lat, r.LatencyMS)
			}
		}
		s.Availability = float64(s.Samples-s.Failures) / float64(s.Samples)
		if len(lat) > 0 {
			sort.Float64s(lat)
			s.P95MS = lat[int(math.Ceil(.95*float64(len(lat))))-1]
		}
		s.Degraded = s.Availability < .95 || s.P95MS > 250
		out = append(out, s)
	}
	return out
}
func TLSConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13} }
