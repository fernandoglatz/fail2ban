package fail2ban

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedis is a minimal in-process RESP server that implements only the
// commands the plugin uses, so the Redis code path can be tested without a
// real Redis instance.
type fakeRedis struct {
	t        *testing.T
	ln       net.Listener
	mu       sync.Mutex
	strings  map[string]int64
	zsets    map[string]map[string]float64
	ttls     map[string]int64
	failCmds map[string]bool
}

func newFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &fakeRedis{
		t:        t,
		ln:       ln,
		strings:  map[string]int64{},
		zsets:    map[string]map[string]float64{},
		ttls:     map[string]int64{},
		failCmds: map[string]bool{},
	}
	go r.serve()
	t.Cleanup(func() { ln.Close() })
	return r
}

func (r *fakeRedis) addr() string { return r.ln.Addr().String() }

func (r *fakeRedis) failCommand(cmd string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failCmds[cmd] = true
}

func (r *fakeRedis) ttl(key string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ttls[key]
}

func (r *fakeRedis) zcard(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.zsets[key])
}

func (r *fakeRedis) del(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.strings, key)
	delete(r.ttls, key)
}

func (r *fakeRedis) zadd(key string, score float64, member string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.zsets[key] == nil {
		r.zsets[key] = map[string]float64{}
	}
	r.zsets[key][member] = score
}

func (r *fakeRedis) serve() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

func (r *fakeRedis) handle(conn net.Conn) {
	defer conn.Close()
	rd := bufio.NewReader(conn)
	for {
		args, err := readRESPArray(rd)
		if err != nil {
			return
		}
		if _, err := io.WriteString(conn, r.exec(args)); err != nil {
			return
		}
	}
}

func readRESPArray(rd *bufio.Reader) ([]string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line)[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := rd.ReadString('\n'); err != nil { // $<len>
			return nil, err
		}
		arg, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args = append(args, strings.TrimRight(arg, "\r\n"))
	}
	return args, nil
}

func parseScore(s string) float64 {
	switch s {
	case "-inf":
		return -1e300
	case "+inf", "inf":
		return 1e300
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func (r *fakeRedis) exec(args []string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	cmd := strings.ToUpper(args[0])
	if r.failCmds[cmd] {
		return "-ERR injected failure\r\n"
	}
	switch cmd {
	case "AUTH", "SELECT":
		return "+OK\r\n"
	case "GET":
		v, ok := r.strings[args[1]]
		if !ok {
			return "$-1\r\n"
		}
		s := strconv.FormatInt(v, 10)
		return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s)
	case "INCR":
		r.strings[args[1]]++
		return fmt.Sprintf(":%d\r\n", r.strings[args[1]])
	case "EXPIRE":
		secs, _ := strconv.ParseInt(args[2], 10, 64)
		r.ttls[args[1]] = secs
		return ":1\r\n"
	case "DEL":
		_, ok := r.strings[args[1]]
		delete(r.strings, args[1])
		delete(r.zsets, args[1])
		delete(r.ttls, args[1])
		if ok {
			return ":1\r\n"
		}
		return ":0\r\n"
	case "ZADD":
		if r.zsets[args[1]] == nil {
			r.zsets[args[1]] = map[string]float64{}
		}
		r.zsets[args[1]][args[3]] = parseScore(args[2])
		return ":1\r\n"
	case "ZREMRANGEBYSCORE":
		lo, hi := parseScore(args[2]), parseScore(args[3])
		removed := 0
		for m, s := range r.zsets[args[1]] {
			if s >= lo && s <= hi {
				delete(r.zsets[args[1]], m)
				removed++
			}
		}
		return fmt.Sprintf(":%d\r\n", removed)
	case "ZCARD":
		return fmt.Sprintf(":%d\r\n", len(r.zsets[args[1]]))
	}
	r.t.Errorf("fakeRedis: unexpected command %q", cmd)
	return "-ERR unknown command\r\n"
}

// notifySink collects ban notifications sent by the plugin.
type notifySink struct {
	srv      *httptest.Server
	payloads chan NotificationPayload
}

func newNotifySink(t *testing.T) *notifySink {
	t.Helper()
	s := &notifySink{payloads: make(chan NotificationPayload, 16)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p NotificationPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("bad notification body: %v", err)
		}
		s.payloads <- p
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { s.srv.Close() })
	return s
}

func (s *notifySink) next(t *testing.T) NotificationPayload {
	t.Helper()
	select {
	case p := <-s.payloads:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ban notification")
		return NotificationPayload{}
	}
}

func (s *notifySink) expectNone(t *testing.T) {
	t.Helper()
	select {
	case p := <-s.payloads:
		t.Fatalf("unexpected extra notification: %+v", p)
	case <-time.After(200 * time.Millisecond):
	}
}

func newTestFail2Ban(t *testing.T, cfg *Config) *fail2Ban {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if cfg.FailWindow == "" {
		cfg.FailWindow = "10m"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "ERROR"
	}
	h, err := New(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h.(*fail2Ban)
}

func failTimes(f *fail2Ban, ip string, n int) {
	req := httptest.NewRequest("GET", "http://test.com/login", nil)
	for i := 0; i < n; i++ {
		f.incrementViewCounter(ip, req)
	}
}

const testIP = "203.0.113.10"

func TestConfigDefaultsKeepFixedBanTime(t *testing.T) {
	cfg := CreateConfig()
	if cfg.BanTimeIncrement {
		t.Error("BanTimeIncrement must default to false (backwards compatible)")
	}
	if cfg.BanHistoryWindow != "168h" {
		t.Errorf("BanHistoryWindow default = %q, want 168h", cfg.BanHistoryWindow)
	}
}

func TestNewRejectsInvalidBanHistoryWindow(t *testing.T) {
	_, err := New(context.Background(), nil, &Config{
		BanTime: "1h", FailWindow: "10m", BanTimeIncrement: true, BanHistoryWindow: "one week",
	}, "test")
	if err == nil {
		t.Fatal("expected error for invalid BanHistoryWindow")
	}
}

func TestNewRejectsNonPositiveBanHistoryWindowWhenIncrementing(t *testing.T) {
	_, err := New(context.Background(), nil, &Config{
		BanTime: "1h", FailWindow: "10m", BanTimeIncrement: true, BanHistoryWindow: "0s",
	}, "test")
	if err == nil {
		t.Fatal("expected error for zero BanHistoryWindow with BanTimeIncrement")
	}
}

func TestEscalatedBanTime(t *testing.T) {
	f := &fail2Ban{banTime: time.Hour, banTimeIncrement: true}
	cases := map[int64]time.Duration{0: time.Hour, 1: time.Hour, 2: 2 * time.Hour, 20: 20 * time.Hour}
	for n, want := range cases {
		if got := f.escalatedBanTime(n); got != want {
			t.Errorf("escalatedBanTime(%d) = %v, want %v", n, got, want)
		}
	}
	f.banTimeIncrement = false
	if got := f.escalatedBanTime(5); got != time.Hour {
		t.Errorf("without increment escalatedBanTime(5) = %v, want 1h", got)
	}
}

func TestRedisFixedBanTimeWhenIncrementDisabled(t *testing.T) {
	r := newFakeRedis(t)
	sink := newNotifySink(t)
	f := newTestFail2Ban(t, &Config{BanTime: "1h", NumberFails: 3, RedisAddress: r.addr(), NotifyURL: sink.srv.URL})

	failTimes(f, testIP, 3)

	if got := r.ttl("fail2ban:" + testIP); got != 3600 {
		t.Errorf("ban TTL = %d, want 3600", got)
	}
	p := sink.next(t)
	if p.BanTime != "1h0m0s" || p.BanCount != 1 {
		t.Errorf("notification banTime=%q banCount=%d, want 1h0m0s/1", p.BanTime, p.BanCount)
	}
	if n := r.zcard("fail2ban:bans:" + testIP); n != 0 {
		t.Errorf("ban history must not be recorded when increment is disabled, got %d", n)
	}
}

func TestRedisBanTimeIncrementEscalates(t *testing.T) {
	r := newFakeRedis(t)
	sink := newNotifySink(t)
	f := newTestFail2Ban(t, &Config{
		BanTime: "1h", NumberFails: 3, RedisAddress: r.addr(), NotifyURL: sink.srv.URL,
		BanTimeIncrement: true, BanHistoryWindow: "168h",
	})
	key := "fail2ban:" + testIP

	for ban := int64(1); ban <= 3; ban++ {
		failTimes(f, testIP, 3)
		if got, want := r.ttl(key), 3600*ban; got != want {
			t.Errorf("ban #%d TTL = %d, want %d", ban, got, want)
		}
		p := sink.next(t)
		if p.BanCount != ban || p.BanTime != (time.Duration(ban)*time.Hour).String() {
			t.Errorf("ban #%d notification banCount=%d banTime=%q", ban, p.BanCount, p.BanTime)
		}
		r.del(key) // ban expires (or is lifted by the unban routine)
	}
	if n := r.zcard("fail2ban:bans:" + testIP); n != 3 {
		t.Errorf("ban history size = %d, want 3", n)
	}
	if got, want := r.ttl("fail2ban:bans:"+testIP), int64((168 * time.Hour).Seconds()); got != want {
		t.Errorf("history TTL = %d, want %d", got, want)
	}
}

func TestRedisBanHistoryWindowForgetsOldBans(t *testing.T) {
	r := newFakeRedis(t)
	sink := newNotifySink(t)
	f := newTestFail2Ban(t, &Config{
		BanTime: "1h", NumberFails: 3, RedisAddress: r.addr(), NotifyURL: sink.srv.URL,
		BanTimeIncrement: true, BanHistoryWindow: "168h",
	})
	old := time.Now().Add(-8 * 24 * time.Hour)
	r.zadd("fail2ban:bans:"+testIP, float64(old.Unix()), strconv.FormatInt(old.UnixNano(), 10))

	failTimes(f, testIP, 3)

	if got := r.ttl("fail2ban:" + testIP); got != 3600 {
		t.Errorf("ban TTL = %d, want 3600 (8-day-old ban is outside the window)", got)
	}
	if p := sink.next(t); p.BanCount != 1 {
		t.Errorf("banCount = %d, want 1", p.BanCount)
	}
}

func TestRedisBannedRequestKeepsEscalatedBanTime(t *testing.T) {
	r := newFakeRedis(t)
	f := newTestFail2Ban(t, &Config{
		BanTime: "1h", NumberFails: 3, RedisAddress: r.addr(),
		BanTimeIncrement: true, BanHistoryWindow: "168h",
	})
	key := "fail2ban:" + testIP
	failTimes(f, testIP, 3)
	r.del(key)
	failTimes(f, testIP, 3) // second ban: 2h

	if !f.isClientBanned(testIP) {
		t.Fatal("client should be banned")
	}
	if got := r.ttl(key); got != 7200 {
		t.Errorf("TTL after banned request = %d, want 7200 (must not drop back to 1h)", got)
	}
}

func TestRedisBanStartsOnceWhenFailuresOvershoot(t *testing.T) {
	r := newFakeRedis(t)
	sink := newNotifySink(t)
	f := newTestFail2Ban(t, &Config{
		BanTime: "1h", NumberFails: 3, RedisAddress: r.addr(), NotifyURL: sink.srv.URL,
		BanTimeIncrement: true, BanHistoryWindow: "168h",
	})

	// In-flight requests can push the counter past NumberFails.
	failTimes(f, testIP, 6)

	sink.next(t)
	sink.expectNone(t)
	if n := r.zcard("fail2ban:bans:" + testIP); n != 1 {
		t.Errorf("ban history size = %d, want 1", n)
	}
	if got := r.ttl("fail2ban:" + testIP); got != 3600 {
		t.Errorf("ban TTL = %d, want 3600", got)
	}
}

func TestRedisSingleFailureBanWhenNumberFailsIsOne(t *testing.T) {
	r := newFakeRedis(t)
	f := newTestFail2Ban(t, &Config{BanTime: "1h", NumberFails: 1, RedisAddress: r.addr()})

	failTimes(f, testIP, 1)

	if got := r.ttl("fail2ban:" + testIP); got != 3600 {
		t.Errorf("ban TTL = %d, want 3600", got)
	}
	if !f.isClientBanned(testIP) {
		t.Error("client should be banned after one failure when NumberFails=1")
	}
}

func TestRedisHistoryErrorFallsBackToBaseBanTime(t *testing.T) {
	r := newFakeRedis(t)
	sink := newNotifySink(t)
	f := newTestFail2Ban(t, &Config{
		BanTime: "1h", NumberFails: 3, RedisAddress: r.addr(), NotifyURL: sink.srv.URL,
		BanTimeIncrement: true, BanHistoryWindow: "168h",
	})
	r.failCommand("ZADD")

	failTimes(f, testIP, 3)

	if got := r.ttl("fail2ban:" + testIP); got != 3600 {
		t.Errorf("ban TTL = %d, want 3600 (still banned with base time)", got)
	}
	if p := sink.next(t); p.BanCount != 1 || p.BanTime != "1h0m0s" {
		t.Errorf("notification banCount=%d banTime=%q, want 1/1h0m0s", p.BanCount, p.BanTime)
	}
}

func TestInMemoryBanTimeIncrementEscalates(t *testing.T) {
	sink := newNotifySink(t)
	f := newTestFail2Ban(t, &Config{
		BanTime: "1h", NumberFails: 2, NotifyURL: sink.srv.URL,
		BanTimeIncrement: true, BanHistoryWindow: "168h",
	})

	for ban := 1; ban <= 3; ban++ {
		failTimes(f, testIP, 2)
		f.mu.Lock()
		got := f.bannedClients[testIP].banDuration
		f.mu.Unlock()
		if want := time.Duration(ban) * time.Hour; got != want {
			t.Errorf("ban #%d duration = %v, want %v", ban, got, want)
		}
		if p := sink.next(t); p.BanCount != int64(ban) {
			t.Errorf("ban #%d notification banCount = %d", ban, p.BanCount)
		}
		f.mu.Lock()
		delete(f.bannedClients, testIP) // ban expired
		f.mu.Unlock()
	}
}

func TestInMemoryEscalatedBanDoesNotExpireEarly(t *testing.T) {
	f := newTestFail2Ban(t, &Config{BanTime: "1h", NumberFails: 2, BanTimeIncrement: true, BanHistoryWindow: "168h"})
	f.mu.Lock()
	f.bannedClients[testIP] = &client{
		firstFailure: time.Now().Add(-2 * time.Hour),
		lastViewed:   time.Now().Add(-90 * time.Minute),
		failCounter:  2,
		banDuration:  2 * time.Hour,
	}
	f.mu.Unlock()

	if !f.isClientBanned(testIP) {
		t.Error("2h ban viewed 90 minutes ago must still be active")
	}
}

func TestInMemoryBanHistoryWindowForgetsOldBans(t *testing.T) {
	f := newTestFail2Ban(t, &Config{BanTime: "1h", NumberFails: 2, BanTimeIncrement: true, BanHistoryWindow: "168h"})
	f.mu.Lock()
	f.banHistory[testIP] = []time.Time{time.Now().Add(-8 * 24 * time.Hour)}
	f.mu.Unlock()

	failTimes(f, testIP, 2)

	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.bannedClients[testIP].banDuration; got != time.Hour {
		t.Errorf("ban duration = %v, want 1h", got)
	}
	if n := len(f.banHistory[testIP]); n != 1 {
		t.Errorf("history size = %d, want 1 (old entry pruned)", n)
	}
}

func TestPruneBanHistoryDropsExpiredEntries(t *testing.T) {
	f := &fail2Ban{banHistoryWindow: time.Hour, banHistory: map[string][]time.Time{
		"old":   {time.Now().Add(-2 * time.Hour)},
		"mixed": {time.Now().Add(-2 * time.Hour), time.Now()},
	}}
	f.pruneBanHistory(time.Now())
	if _, ok := f.banHistory["old"]; ok {
		t.Error("IP with only expired bans should be removed")
	}
	if n := len(f.banHistory["mixed"]); n != 1 {
		t.Errorf("mixed history size = %d, want 1", n)
	}
}
