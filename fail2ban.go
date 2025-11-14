package fail2ban

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/charanpreetp/fail2ban/log"
	"github.com/redis/go-redis/v9"
)

// Config passed in from traefik configuration
type Config struct {
	NumberFails  uint
	BanTime      string
	FailWindow   string
	ClientHeader string
	LogLevel     log.LogLevel
	RedisAddr    string
	RedisPass    string
	RedisDB      int
}

// Create config with reasonable defaults
func CreateConfig() *Config {
	return &Config{
		NumberFails:  3,
		BanTime:      "3h",
		FailWindow:   "10m",
		ClientHeader: "Cf-Connecting-IP",
		LogLevel:     log.Info,
		RedisAddr:    "",
		RedisPass:    "",
		RedisDB:      0,
	}
}

type fail2Ban struct {
	// Boilerplate stuff
	next   http.Handler
	name   string
	logger *log.Logger

	// Stuff specific to this plugin
	maxFails      uint
	banTime       time.Duration
	failWindow    time.Duration
	clientHeader  string
	bannedClients map[string]*client
	// mutex is specifically access the bannedClients map
	mu sync.Mutex

	// Redis client (optional)
	redisClient *redis.Client

	// this is a test var to signal cleaner is running
	_cleaning_test_var bool
}

func New(ctx context.Context, next http.Handler, config *Config, middleWareName string) (http.Handler, error) {
	duration, err := time.ParseDuration(config.BanTime)
	if err != nil {
		return nil, err
	}
	failWindow, err := time.ParseDuration(config.FailWindow)
	if err != nil {
		return nil, err
	}
	f := fail2Ban{
		name:          middleWareName,
		logger:        log.New("Fail-2-Ban", config.LogLevel),
		next:          next,
		maxFails:      config.NumberFails,
		clientHeader:  config.ClientHeader,
		banTime:       duration,
		failWindow:    failWindow,
		bannedClients: make(map[string]*client),
	}

	// Connect to Redis if configured
	if config.RedisAddr != "" {
		f.redisClient = redis.NewClient(&redis.Options{
			Addr:     config.RedisAddr,
			Password: config.RedisPass,
			DB:       config.RedisDB,
		})

		// Test the connection
		if err := f.redisClient.Ping(ctx).Err(); err != nil {
			f.logger.Errorf("Failed to connect to Redis: %v", err)
			return nil, fmt.Errorf("redis connection failed: %w", err)
		}
		f.logger.Infof("Connected to Redis at %s", config.RedisAddr)
	}

	f.logger.Infof("Max Number Failures %d, Ban Time %q, Fail Window %q, Client-ID-header %q", f.maxFails, f.banTime, f.failWindow, f.clientHeader)
	go f.cleaner(ctx)

	return &f, err
}

func (f *fail2Ban) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	client, err := f.extractClient(req)
	if err != nil {
		f.logger.Errorf("Failed to get Client Identifier due to %q, blocking request to be safe", err)
		rw.WriteHeader(http.StatusForbidden)
		return

	}
	f.logger.Debugf("Request from %s", client)

	// block request if client has been banned
	if f.isClientBanned(client) {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	// intercept returned status code from downstream service(s)
	i := newIntercept(rw)
	f.next.ServeHTTP(i, req)

	// check for 4xx class status code
	if i.checkBadUserRequestStatusCode() {
		f.incrementViewCounter(client)
	}
}

func (f *fail2Ban) isClientBanned(ip string) bool {
	ctx := context.Background()

	// Use Redis if configured
	if f.redisClient != nil {
		return f.isClientBannedRedis(ctx, ip)
	}

	// Fall back to in-memory
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debugf("Checking for %s", ip)
	if c, ok := f.bannedClients[ip]; !ok {
		return false
	} else if c.failCounter >= f.maxFails {
		// Un-ban
		if c.hasBanExpired(time.Now(), f.banTime) {
			f.logger.Infof("Un-Banned %s", ip)
			delete(f.bannedClients, ip)
		} else {
			// extend Ban
			f.logger.Infof("Extend Ban for %s", ip)
			c.failCounter++
			c.lastViewed = time.Now()
			return true
		}
	}
	return false
}

func (f *fail2Ban) incrementViewCounter(ip string) {
	ctx := context.Background()

	// Use Redis if configured
	if f.redisClient != nil {
		f.incrementViewCounterRedis(ctx, ip)
		return
	}

	// Fall back to in-memory
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debugf("Increment %s", ip)
	now := time.Now()
	if f.bannedClients[ip] == nil {
		f.bannedClients[ip] = &client{
			firstFailure: now,
			lastViewed:   now,
			failCounter:  1,
		}
		return
	}

	// Check if we're outside the failure window - reset counter if so
	if now.Sub(f.bannedClients[ip].firstFailure) > f.failWindow {
		f.logger.Infof("Resetting counter for %s - outside failure window", ip)
		f.bannedClients[ip].firstFailure = now
		f.bannedClients[ip].failCounter = 1
	} else {
		f.bannedClients[ip].failCounter++
	}
	f.bannedClients[ip].lastViewed = now
}

// periodically clean up banned clients
func (f *fail2Ban) cleaner(ctx context.Context) {
	timer := time.NewTimer(f.banTime / 4)
	for {
		select {
		case <-ctx.Done():
			f.logger.Info("Shutting down client cleaner")
			f._cleaning_test_var = false
			return
		case <-timer.C:
			f.logger.Debugf("Cleaning up stale client states...")
			f.mu.Lock()
			f._cleaning_test_var = true
			{
				now := time.Now()
				for ip, c := range f.bannedClients {
					if c.hasBanExpired(now, f.banTime) {
						f.logger.Infof("Clearing out state for %s, it is no longer banned", ip)
						delete(f.bannedClients, ip)
					} else {
						f.logger.Debugf("%s still needs to be tracked", ip)
					}
				}
			}
			f.mu.Unlock()
		}
		timer.Reset(f.banTime / 4)
	}
}

func (f *fail2Ban) isClientBannedRedis(ctx context.Context, ip string) bool {
	key := fmt.Sprintf("fail2ban:%s", ip)

	// Get fail counter from Redis
	val, err := f.redisClient.Get(ctx, key).Uint64()
	if err == redis.Nil {
		// Key doesn't exist, client is not banned
		return false
	} else if err != nil {
		f.logger.Errorf("Redis error checking %s: %v", ip, err)
		return false
	}

	failCounter := uint(val)
	f.logger.Debugf("Checking for %s (count: %d)", ip, failCounter)

	if failCounter >= f.maxFails {
		// Client is banned, extend the TTL
		f.logger.Infof("Extend Ban for %s", ip)
		f.redisClient.Expire(ctx, key, f.banTime)
		return true
	}

	return false
}

func (f *fail2Ban) incrementViewCounterRedis(ctx context.Context, ip string) {
	key := fmt.Sprintf("fail2ban:%s", ip)

	// Increment counter in Redis
	count, err := f.redisClient.Incr(ctx, key).Result()
	if err != nil {
		f.logger.Errorf("Redis error incrementing %s: %v", ip, err)
		return
	}

	f.logger.Debugf("Increment %s (count: %d)", ip, count)

	// Set expiration on first increment to the failure window
	if count == 1 {
		f.redisClient.Expire(ctx, key, f.failWindow)
	} else if uint(count) >= f.maxFails {
		// Reset TTL to ban time when client gets banned
		f.redisClient.Expire(ctx, key, f.banTime)
		f.logger.Infof("Banned %s after %d failures", ip, count)
	}
}

func (f *fail2Ban) extractClient(req *http.Request) (string, error) {
	if len(f.clientHeader) > 0 {
		client := req.Header.Get(f.clientHeader)
		if len(client) == 0 {
			return "", fmt.Errorf("failed to extract Client Identifier from %q Header", f.clientHeader)
		}
		return client, nil
	}
	if client, _, err := net.SplitHostPort(req.RemoteAddr); err != nil {
		return "", fmt.Errorf("failed to extract Client IP from RemoteAddr: %w", err)
	} else {
		return client, nil
	}
}

// Intercept Return code from downstream
type interceptor struct {
	http.ResponseWriter
	code int
}

func newIntercept(w http.ResponseWriter) *interceptor {
	return &interceptor{w, http.StatusAccepted}
}

// Check for for 4xx status code (bad user requests)
func (i *interceptor) checkBadUserRequestStatusCode() bool {
	return i.code >= http.StatusBadRequest && i.code < http.StatusInternalServerError
}

func (i *interceptor) WriteHeader(code int) {
	i.code = code
	i.ResponseWriter.WriteHeader(code)
}

// client data tracking struct
type client struct {
	firstFailure time.Time
	lastViewed   time.Time
	failCounter  uint
}

func (c client) hasBanExpired(currentTime time.Time, d time.Duration) bool {
	return currentTime.After(c.lastViewed.Add(d))
}
