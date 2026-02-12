package fail2ban

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSeverNotBanned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	h, err := New(
		ctx,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		&Config{
			BanTime:     "1s",
			FailWindow:  "1s",
			LogLevel:    "ERROR",
			NumberFails: 3,
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	// Simulate 100 requests
	f := h.(*fail2Ban)
	for idx := 0; idx < 100; idx++ {
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "http://garabge", nil)
		request.RemoteAddr = "1.2.3.4:5678"
		h.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("Expected response to be %d but got %d", http.StatusOK, response.Code)
		}
		// Should not get banned with 100 StatusOK responses
		if len(f.bannedClients) != 0 && f.bannedClients["1.2.3.4"] != nil {
			t.Error("Client should not get banned")
		}
	}
}

func TestSeverBanned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	h, err := New(
		ctx,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
		&Config{
			BanTime:     "100ms",
			FailWindow:  "100ms",
			LogLevel:    "ERROR",
			NumberFails: 3,
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	// Simulate 100 requests
	f := h.(*fail2Ban)
	for idx := uint(0); idx < 100; idx++ {
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "http://garabge", nil)
		request.RemoteAddr = "1.2.3.4:5678"
		h.ServeHTTP(response, request)
		// First few requests will be fine, will get banned after NumberFails is reached
		if idx < f.maxFails {
			if response.Code != http.StatusNotFound {
				t.Errorf("Expected response to be %d but got %d", http.StatusNotFound, response.Code)
			}
		} else {
			if response.Code != http.StatusForbidden {
				t.Errorf("Expected response to be %d but got %d", http.StatusForbidden, response.Code)
			}
		}
		// Client should get added to ban list
		if len(f.bannedClients) != 1 || f.bannedClients["1.2.3.4"].failCounter != idx+1 {
			t.Error("Client should get banned")
		}
	}

	// Wait to get unbanned and then try a new request
	time.Sleep(300 * time.Millisecond)
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://garabge", nil)
	request.RemoteAddr = "1.2.3.4:5678"
	h.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Errorf("Expected response to be %d but got %d", http.StatusNotFound, response.Code)
	}
	if len(f.bannedClients) != 1 && f.bannedClients["1.2.3.4"].failCounter != 1 {
		t.Error("Client should not get banned")
	}
}

func TestSeverMultipleClientsAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	cancel()
	var wg sync.WaitGroup
	numClients := 20
	numRequests := uint(20)
	wg.Add(numClients)

	h, err := New(
		ctx,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id, _ := strconv.Atoi(r.Header.Get("header")); id%2 == 0 {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		}),
		&Config{
			BanTime:      "1s",
			FailWindow:   "1s",
			LogLevel:     "ERROR",
			ClientHeader: "header",
			NumberFails:  3,
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	f := h.(*fail2Ban)

	for client := 0; client < numClients; client++ {
		go func(client int) {
			defer wg.Done()
			clientId := fmt.Sprintf("%d", client)
			// Simulate numRequests requests
			for idx := uint(0); idx < numRequests; idx++ {
				response := httptest.NewRecorder()
				request := httptest.NewRequest("GET", "http://garabge", nil)
				request.Header.Add("header", clientId)

				h.ServeHTTP(response, request)

				f.mu.Lock()
				if client%2 == 0 {
					// First few requests will be fine, will get banned after NumberFails is reached
					if idx < f.maxFails {
						if response.Code != http.StatusNotFound {
							t.Errorf("Expected response for client %d on request %d to be %d but got %d", client, idx, http.StatusNotFound, response.Code)
						}
					} else {
						if response.Code != http.StatusForbidden {
							t.Errorf("Expected response for client %d on request %d to be %d but got %d", client, idx, http.StatusForbidden, response.Code)
						}
					}
					// Client should get added to ban list
					if f.bannedClients[clientId].failCounter != idx+1 {
						t.Errorf("Client fail counter should get increased")
					}
				} else {
					if response.Code != http.StatusOK {
						t.Error("Client should not get banned")
					}
				}
				f.mu.Unlock()
			}

		}(client)
	}
	wg.Wait()

	if len(f.bannedClients) != (numClients/2 + numClients%2) {
		t.Errorf("Half of the clients should get banned but only %d out of %d did", len(f.bannedClients), numClients)
	}
}

func TestCheckViewCounter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	h, err := New(
		ctx,
		nil,
		&Config{
			BanTime:     "1s",
			FailWindow:  "1s",
			LogLevel:    "ERROR",
			NumberFails: 3,
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	f := h.(*fail2Ban)
	// Client 1 is banned
	f.bannedClients["1"] = &client{
		firstFailure: time.Now(),
		lastViewed:   time.Now(),
		failCounter:  10,
	}
	// Client 2 is no banned
	f.bannedClients["2"] = &client{
		firstFailure: time.Now(),
		lastViewed:   time.Now(),
		failCounter:  1,
	}

	if f.isClientBanned("0") {
		t.Error("Client 0 should not be banned")
	}
	if !f.isClientBanned("1") {
		t.Error("Client 1 should be banned")
	}
	if f.bannedClients["1"].failCounter != 11 {
		t.Error("Should have incremented failed views")
	}
	if f.isClientBanned("2") {
		t.Error("Client 2 should not be banned")
	}

	// Unban Client 1
	f.bannedClients["1"].lastViewed = f.bannedClients["1"].lastViewed.Add(-f.banTime).Add(-time.Microsecond)
	if f.isClientBanned("1") {
		t.Error("Client 1 should be unbanned")
	}
}

func TestIncrementingViewCounter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	h, err := New(
		ctx,
		nil,
		&Config{
			BanTime:     "1s",
			FailWindow:  "1s",
			NumberFails: 3,
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	f := h.(*fail2Ban)

	if len(f.bannedClients) != 0 {
		t.Error("Banned client map should be empty")
	}

	// need to subtract a bit so that timestamps aren't the same
	start := time.Now().Add(-time.Microsecond)

	// Create a mock request for testing
	req := httptest.NewRequest("GET", "http://test.com", nil)
	req.RemoteAddr = "1.2.3.4:5678"

	f.incrementViewCounter("1", req)
	f.incrementViewCounter("2", req)
	f.incrementViewCounter("3", req)
	f.incrementViewCounter("3", req)

	if len(f.bannedClients) != 3 {
		t.Error("Banned client map should have 3 clients")
	}

	if f.bannedClients["1"].failCounter != 1 {
		t.Error("Client 1 should have 1 view")
	}
	if !f.bannedClients["1"].lastViewed.After(start) {
		t.Error("Client 1 view time should be set to after test start time")
	}

	if f.bannedClients["2"].failCounter != 1 {
		t.Error("Client 2 should have 1 view")
	}
	if !f.bannedClients["2"].lastViewed.After(start) {
		t.Error("Client 2 view time should be set to after test start time")
	}

	if f.bannedClients["3"].failCounter != 2 {
		t.Error("Client 3 should have 1 view")
	}
	if !f.bannedClients["3"].lastViewed.After(start) {
		t.Error("Client 1 view time should be set to after test start time")
	}
}

func TestCleaner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	h, err := New(
		ctx,
		nil,
		&Config{
			BanTime:    "1us",
			FailWindow: "1us",
			LogLevel:   "ERROR",
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	f := h.(*fail2Ban)

	// Do this to make sure cleaner has enough time to start running
	waitForCleanerToRun := func(f *fail2Ban) {
		// Wait for cleaner to loop through twice
		f.mu.Lock()
		f._cleaning_test_var = false
		f.mu.Unlock()
		for {
			time.Sleep(time.Millisecond)
			f.mu.Lock()
			if f._cleaning_test_var {
				f._cleaning_test_var = false
				f.mu.Unlock()
				for {
					time.Sleep(time.Millisecond)
					f.mu.Lock()
					if f._cleaning_test_var {
						f.mu.Unlock()
						return
					}
					f.mu.Unlock()
				}
			}
			f.mu.Unlock()
		}
	}
	waitForCleanerToRun(f)

	// Change cleaner config and add clients
	f.mu.Lock()
	f.banTime = time.Microsecond
	f.bannedClients = make(map[string]*client)
	f.bannedClients["1"] = &client{firstFailure: time.Time{}}
	f.bannedClients["2"] = &client{firstFailure: time.Time{}}
	f.bannedClients["3"] = &client{firstFailure: time.Time{}}
	f.bannedClients["4"] = &client{firstFailure: time.Time{}}
	f.mu.Unlock()

	// wait for cleaner to clean
	waitForCleanerToRun(f)

	// pause cleaner
	f.mu.Lock()
	if len(f.bannedClients) != 0 {
		t.Errorf("Failed to clear out banned clients, %d left", len(f.bannedClients))
	}

	// Change cleaner config and add clients
	f.banTime = time.Microsecond
	f.bannedClients = make(map[string]*client)
	f.bannedClients["1"] = &client{
		firstFailure: time.Now(),
		lastViewed:   time.Now().Add(time.Minute),
	}
	f.bannedClients["2"] = &client{firstFailure: time.Time{}}
	f.bannedClients["3"] = &client{firstFailure: time.Time{}}
	f.bannedClients["4"] = &client{firstFailure: time.Time{}}
	f.mu.Unlock()

	// wait for cleaner to clean
	waitForCleanerToRun(f)

	// pause cleaner
	f.mu.Lock()

	if len(f.bannedClients) != 1 {
		t.Errorf("Should have cleaned all but one client, %d left", len(f.bannedClients))
	}
	if _, ok := f.bannedClients["1"]; !ok {
		t.Error("Client 1 should remain uncleaned")
	}

	f.mu.Unlock()
}

func TestCleanerShutsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	h, err := New(
		ctx,
		nil,
		&Config{
			BanTime:    "1s",
			FailWindow: "1s",
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	ctx, cancel = context.WithCancel(context.TODO())
	cancel()
	var mu sync.Mutex
	mu.Lock()
	f := h.(*fail2Ban)
	go func() {
		// should block here until ctx cancel
		f.cleaner(ctx)
		mu.Unlock()
	}()

	time.Sleep(10 * time.Millisecond)
	if !mu.TryLock() {
		t.Error("Cleaner should have exited")
	}
}

func TestExtractClient(t *testing.T) {
	tests := map[string]struct {
		input          *fail2Ban
		req            *http.Request
		expectedClient string
		expectedError  string
	}{
		"Should get from RemoteAddr": {
			&fail2Ban{},
			func() *http.Request {
				req := httptest.NewRequest("GET", "http://test.com", nil)
				req.RemoteAddr = "1.2.3.4:5678"
				return req
			}(),
			"1.2.3.4",
			"",
		},
		"Should get error from invaid RemoteAddr": {
			&fail2Ban{},
			func() *http.Request {
				req := httptest.NewRequest("GET", "http://test.com", nil)
				req.RemoteAddr = "1.2.3.4"
				return req
			}(),
			"",
			"failed to extract Client IP from RemoteAddr:",
		},
		"Should get from header": {
			&fail2Ban{
				clientHeader: "test-header",
			},
			func() *http.Request {
				req := httptest.NewRequest("GET", "http://test.com", nil)
				req.Header.Add("test-header", "ip")
				req.RemoteAddr = "1.2.3.4:5678"
				return req
			}(),
			"ip",
			"",
		},
		"Should throw error when header is missing": {
			&fail2Ban{
				clientHeader: "test-header",
			},
			func() *http.Request {
				req := httptest.NewRequest("GET", "http://test.com", nil)
				req.RemoteAddr = "1.2.3.4:5678"
				return req
			}(),
			"",
			"failed to extract Client Identifier from \"test-header\" Header",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := test.input.extractClient(test.req)
			if result != test.expectedClient {
				t.Errorf("Expected Client %q, got %q", test.expectedClient, result)
			}
			if err == nil {
				if len(test.expectedError) != 0 {
					t.Errorf("Expected error %q but got none", test.expectedError)
				}
			} else {
				if len(test.expectedError) == 0 {
					t.Errorf("Got error %q but expected none", err.Error())
				} else {
					if !strings.Contains(err.Error(), test.expectedError) {
						t.Errorf("Expected error %q but got %q", test.expectedError, err.Error())
					}
				}
			}
		})
	}
}

func TestIgnoreHostsSkipsTracking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	h, err := New(
		ctx,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
		&Config{
			BanTime:     "1s",
			FailWindow:  "1s",
			LogLevel:    "ERROR",
			NumberFails: 1,
			IgnoreHosts: []string{"ignored.test"},
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	f := h.(*fail2Ban)
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://ignored.test", nil)
	request.Host = "ignored.test"
	request.RemoteAddr = "1.2.3.4:5678"

	h.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Errorf("Expected response to be %d but got %d", http.StatusNotFound, response.Code)
	}
	if len(f.bannedClients) != 0 {
		t.Error("Ignored host should not be tracked")
	}
}

func TestIgnoreHostsUsesXForwardedHost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	h, err := New(
		ctx,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
		&Config{
			BanTime:     "1s",
			FailWindow:  "1s",
			LogLevel:    "ERROR",
			NumberFails: 1,
			IgnoreHosts: []string{"ignored.test"},
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	f := h.(*fail2Ban)
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://not-ignored.test", nil)
	request.Host = "not-ignored.test"
	request.Header.Set("X-Forwarded-Host", "ignored.test")
	request.RemoteAddr = "1.2.3.4:5678"

	h.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Errorf("Expected response to be %d but got %d", http.StatusNotFound, response.Code)
	}
	if len(f.bannedClients) != 0 {
		t.Error("Ignored X-Forwarded-Host should not be tracked")
	}
}

func TestIgnoreHostsDoesNotOverrideDenylist(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	h, err := New(
		ctx,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
		&Config{
			BanTime:       "1s",
			FailWindow:    "1s",
			LogLevel:      "ERROR",
			NumberFails:   1,
			IgnoreHosts:   []string{"ignored.test"},
			DenylistCIDRs: []string{"1.2.3.0/24"},
		},
		"test",
	)
	if err != nil {
		t.Errorf("Got error %s", err.Error())
		t.FailNow()
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://ignored.test", nil)
	request.Host = "ignored.test"
	request.RemoteAddr = "1.2.3.4:5678"

	h.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Errorf("Expected response to be %d but got %d", http.StatusForbidden, response.Code)
	}
}

func TestInterceptor(t *testing.T) {
	rec := httptest.NewRecorder()
	i := newIntercept(rec)
	i.WriteHeader(123)
	if rec.Code != 123 {
		t.Errorf("Failed to intercept, got %d", rec.Code)
	}
}

func TestCheckForInterceptedStatusCode(t *testing.T) {
	tests := map[string]struct {
		input    interceptor
		expected bool
	}{
		"200": {
			interceptor{
				nil,
				200,
			},
			false,
		},
		"300": {
			interceptor{
				nil,
				300,
			},
			false,
		},
		"500": {
			interceptor{
				nil,
				500,
			},
			false,
		},
		"400": {
			interceptor{
				nil,
				400,
			},
			true,
		},
		"499": {
			interceptor{
				nil,
				499,
			},
			true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.expected != test.input.checkBadUserRequestStatusCode() {
				t.Error("Unexpected Result")
			}
		})
	}
}

func TestHasBanExpired(t *testing.T) {
	d := 10 * time.Minute
	tests := map[string]struct {
		client     client
		hasExpired bool
	}{
		"has expired": {
			client: client{
				firstFailure: time.Time{},
				lastViewed:   time.Now().Add(-2 * d),
				failCounter:  0,
			},
			hasExpired: true,
		},
		"has not expired": {
			client: client{
				firstFailure: time.Time{},
				lastViewed:   time.Now(),
				failCounter:  0,
			},
			hasExpired: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.hasExpired != test.client.hasBanExpired(time.Now(), d) {
				t.Error("Unexpected result")
			}
		})
	}

}
