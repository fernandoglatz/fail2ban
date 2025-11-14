package fail2ban

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/charanpreetp/fail2ban/log"
)

// Config passed in from traefik configuration
type Config struct {
	NumberFails    uint
	BanTime        string
	FailWindow     string
	ClientHeader   string
	LogLevel       log.LogLevel
	RedisAddress   string
	RedisPassword  string
	RedisDB        int
	AllowlistCIDRs []string
	DenylistCIDRs  []string
}

// Create config with reasonable defaults
func CreateConfig() *Config {
	return &Config{
		NumberFails:    3,
		BanTime:        "3h",
		FailWindow:     "10m",
		ClientHeader:   "Cf-Connecting-IP",
		LogLevel:       log.Info,
		RedisAddress:   "",
		RedisPassword:  "",
		RedisDB:        0,
		AllowlistCIDRs: []string{},
		DenylistCIDRs:  []string{},
	}
}

type fail2Ban struct {
	// Boilerplate stuff
	next   http.Handler
	name   string
	logger *log.Logger

	// Stuff specific to this plugin
	maxFails       uint
	banTime        time.Duration
	failWindow     time.Duration
	clientHeader   string
	allowlistCIDRs []*net.IPNet
	denylistCIDRs  []*net.IPNet
	bannedClients  map[string]*client
	// mutex is specifically access the bannedClients map
	mu sync.Mutex

	// Redis connection via plain socket (optional)
	redisConn     net.Conn
	redisReader   *bufio.Reader
	redisMu       sync.Mutex
	redisAddress  string
	redisPassword string
	redisDB       int

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
	// Parse allowlist CIDRs
	allowlistCIDRs := make([]*net.IPNet, 0, len(config.AllowlistCIDRs))
	for _, cidr := range config.AllowlistCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in allowlist %q: %w", cidr, err)
		}
		allowlistCIDRs = append(allowlistCIDRs, ipNet)
	}

	// Parse denylist CIDRs
	denylistCIDRs := make([]*net.IPNet, 0, len(config.DenylistCIDRs))
	for _, cidr := range config.DenylistCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in denylist %q: %w", cidr, err)
		}
		denylistCIDRs = append(denylistCIDRs, ipNet)
	}

	f := fail2Ban{
		name:           middleWareName,
		logger:         log.New("Fail-2-Ban", config.LogLevel),
		next:           next,
		maxFails:       config.NumberFails,
		clientHeader:   config.ClientHeader,
		banTime:        duration,
		failWindow:     failWindow,
		allowlistCIDRs: allowlistCIDRs,
		denylistCIDRs:  denylistCIDRs,
		bannedClients:  make(map[string]*client),
	}

	// Connect to Redis using plain socket if configured
	if config.RedisAddress != "" {
		f.redisAddress = config.RedisAddress
		f.redisPassword = config.RedisPassword
		f.redisDB = config.RedisDB

		if err := f.connectRedis(); err != nil {
			return nil, err
		}
	}

	f.logger.Infof("Max Number Failures %d, Ban Time %q, Fail Window %q, Client-ID-header %q", f.maxFails, f.banTime, f.failWindow, f.clientHeader)
	if len(f.allowlistCIDRs) > 0 {
		f.logger.Infof("Allowlist CIDRs: %v", config.AllowlistCIDRs)
	}
	if len(f.denylistCIDRs) > 0 {
		f.logger.Infof("Denylist CIDRs: %v", config.DenylistCIDRs)
	}
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

	// Block denylisted IPs immediately
	if f.isIPDenylisted(client) {
		f.logger.Infof("%s is denylisted, blocking request", client)
		rw.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(rw, "You're banned: %s", client)
		return
	}

	// Skip ban logic for allowlisted IPs
	if f.isIPAllowlisted(client) {
		f.logger.Debugf("%s is allowlisted, skipping ban check", client)
		f.next.ServeHTTP(rw, req)
		return
	}

	// block request if client has been banned
	if f.isClientBanned(client) {
		rw.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(rw, "You're banned: %s", client)
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

func (f *fail2Ban) isIPDenylisted(ipStr string) bool {
	if len(f.denylistCIDRs) == 0 {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		f.logger.Debugf("Failed to parse IP %s for denylist check", ipStr)
		return false
	}

	for _, cidr := range f.denylistCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (f *fail2Ban) isIPAllowlisted(ipStr string) bool {
	if len(f.allowlistCIDRs) == 0 {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		f.logger.Debugf("Failed to parse IP %s for allowlist check", ipStr)
		return false
	}

	for _, cidr := range f.allowlistCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (f *fail2Ban) isClientBanned(ip string) bool {
	// Use Redis if configured
	f.redisMu.Lock()
	useRedis := f.redisConn != nil
	f.redisMu.Unlock()
	if useRedis {
		return f.isClientBannedRedis(ip)
	}

	// Fall back to in-memory
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debugf("[In-Memory] Checking for %s", ip)
	if c, ok := f.bannedClients[ip]; !ok {
		return false
	} else if c.failCounter >= f.maxFails {
		// Un-ban
		if c.hasBanExpired(time.Now(), f.banTime) {
			f.logger.Infof("[In-Memory] Un-Banned %s", ip)
			delete(f.bannedClients, ip)
		} else {
			// extend Ban
			f.logger.Infof("[In-Memory] Extend Ban for %s", ip)
			c.failCounter++
			c.lastViewed = time.Now()
			return true
		}
	}
	return false
}

func (f *fail2Ban) incrementViewCounter(ip string) {
	// Use Redis if configured
	f.redisMu.Lock()
	useRedis := f.redisConn != nil
	f.redisMu.Unlock()
	if useRedis {
		f.incrementViewCounterRedis(ip)
		return
	}

	// Fall back to in-memory
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger.Debugf("[In-Memory] Increment %s", ip)
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
		f.logger.Infof("[In-Memory] Resetting counter for %s - outside failure window", ip)
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
						f.logger.Infof("[In-Memory] Clearing out state for %s, it is no longer banned", ip)
						delete(f.bannedClients, ip)
					} else {
						f.logger.Debugf("[In-Memory] %s still needs to be tracked", ip)
					}
				}
			}
			f.mu.Unlock()
		}
		timer.Reset(f.banTime / 4)
	}
}

// connectRedis establishes and authenticates a Redis connection
func (f *fail2Ban) connectRedis() error {
	conn, err := net.Dial("tcp", f.redisAddress)
	if err != nil {
		f.logger.Errorf("Failed to connect to Redis: %v", err)
		return fmt.Errorf("redis connection failed: %w", err)
	}
	f.redisConn = conn
	f.redisReader = bufio.NewReader(conn)

	// Authenticate if password is set
	if f.redisPassword != "" {
		if err := f.redisCommand("AUTH", f.redisPassword); err != nil {
			f.logger.Errorf("Redis authentication failed: %v", err)
			f.redisConn.Close()
			f.redisConn = nil
			f.redisReader = nil
			return fmt.Errorf("redis auth failed: %w", err)
		}
	}

	// Select database
	if f.redisDB != 0 {
		if err := f.redisCommand("SELECT", fmt.Sprintf("%d", f.redisDB)); err != nil {
			f.logger.Errorf("Redis SELECT failed: %v", err)
			f.redisConn.Close()
			f.redisConn = nil
			f.redisReader = nil
			return fmt.Errorf("redis SELECT failed: %w", err)
		}
	}

	f.logger.Infof("Connected to Redis at %s", f.redisAddress)
	return nil
}

// reconnectRedis attempts to reconnect to Redis if the connection is broken
func (f *fail2Ban) reconnectRedis() error {
	// Close existing connection if any
	if f.redisConn != nil {
		f.redisConn.Close()
		f.redisConn = nil
		f.redisReader = nil
	}

	f.logger.Infof("Attempting to reconnect to Redis...")
	return f.connectRedis()
}

// ensureRedisConnection checks and restores Redis connection if needed
func (f *fail2Ban) ensureRedisConnection() error {
	if f.redisConn == nil {
		return f.reconnectRedis()
	}
	return nil
}

// Build RESP protocol command array
func (f *fail2Ban) buildRESPCommand(cmd string, args ...string) string {
	resp := fmt.Sprintf("*%d\r\n", len(args)+1)
	resp += fmt.Sprintf("$%d\r\n%s\r\n", len(cmd), cmd)
	for _, arg := range args {
		resp += fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)
	}
	return resp
}

// Send Redis command using RESP protocol
func (f *fail2Ban) redisCommand(cmd string, args ...string) error {
	f.redisMu.Lock()
	defer f.redisMu.Unlock()

	// Ensure connection is healthy
	if err := f.ensureRedisConnection(); err != nil {
		return err
	}

	// Build RESP array
	resp := f.buildRESPCommand(cmd, args...)

	// Send command
	_, err := f.redisConn.Write([]byte(resp))
	if err != nil {
		// Try to reconnect on write error
		if reconnErr := f.reconnectRedis(); reconnErr != nil {
			return fmt.Errorf("write error: %w, reconnect failed: %v", err, reconnErr)
		}
		return fmt.Errorf("write error: %w", err)
	}

	// Read response
	_, err = f.readRedisResponse()
	if err != nil {
		// Mark connection as broken on read error
		f.redisConn.Close()
		f.redisConn = nil
		f.redisReader = nil
	}
	return err
}

// Send Redis command and get integer response
func (f *fail2Ban) redisCommandInt(cmd string, args ...string) (int64, error) {
	f.redisMu.Lock()
	defer f.redisMu.Unlock()

	// Ensure connection is healthy
	if err := f.ensureRedisConnection(); err != nil {
		return 0, err
	}

	// Build RESP array
	resp := f.buildRESPCommand(cmd, args...)

	// Send command
	_, err := f.redisConn.Write([]byte(resp))
	if err != nil {
		// Try to reconnect on write error
		if reconnErr := f.reconnectRedis(); reconnErr != nil {
			return 0, fmt.Errorf("write error: %w, reconnect failed: %v", err, reconnErr)
		}
		return 0, fmt.Errorf("write error: %w", err)
	}

	// Read response
	val, err := f.readRedisResponse()
	if err != nil {
		// Mark connection as broken on read error
		f.redisConn.Close()
		f.redisConn = nil
		f.redisReader = nil
	}
	return val, err
}

// Read and parse Redis RESP protocol response
func (f *fail2Ban) readRedisResponse() (int64, error) {
	line, err := f.redisReader.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read error: %w", err)
	}

	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return 0, fmt.Errorf("empty response")
	}

	switch line[0] {
	case '+':
		// Simple string - OK response
		return 0, nil
	case '-':
		// Error
		return 0, fmt.Errorf("redis error: %s", line[1:])
	case ':':
		// Integer
		var num int64
		_, err := fmt.Sscanf(line[1:], "%d", &num)
		return num, err
	case '$':
		// Bulk string
		var size int
		_, err := fmt.Sscanf(line[1:], "%d", &size)
		if err != nil {
			return 0, err
		}
		if size == -1 {
			// Null response
			return 0, nil
		}
		// Read the actual string data
		data := make([]byte, size)
		_, err = io.ReadFull(f.redisReader, data)
		if err != nil {
			return 0, err
		}
		// Read and verify CRLF
		crlf := make([]byte, 2)
		_, err = io.ReadFull(f.redisReader, crlf)
		if err != nil || crlf[0] != '\r' || crlf[1] != '\n' {
			return 0, fmt.Errorf("invalid bulk string terminator")
		}
		// Try to parse as integer
		var num int64
		_, err = fmt.Sscanf(string(data), "%d", &num)
		if err != nil {
			return 0, nil
		}
		return num, nil
	default:
		return 0, fmt.Errorf("unknown response type: %c", line[0])
	}
}

func (f *fail2Ban) isClientBannedRedis(ip string) bool {
	key := fmt.Sprintf("fail2ban:%s", ip)

	// Get fail counter from Redis using plain socket
	val, err := f.redisCommandInt("GET", key)
	if err != nil {
		f.logger.Debugf("Redis GET for %s: %v (not banned)", ip, err)
		return false
	}

	failCounter := uint(val)
	f.logger.Debugf("[Redis] Checking for %s (count: %d)", ip, failCounter)

	if failCounter >= f.maxFails {
		// Client is banned, extend the TTL
		f.logger.Infof("[Redis] Extend Ban for %s", ip)
		if err := f.redisCommand("EXPIRE", key, fmt.Sprintf("%d", int(f.banTime.Seconds()))); err != nil {
			f.logger.Errorf("Failed to extend ban expiration for %s: %v", ip, err)
		}
		return true
	}

	return false
}

func (f *fail2Ban) incrementViewCounterRedis(ip string) {
	key := fmt.Sprintf("fail2ban:%s", ip)

	// Increment counter in Redis
	count, err := f.redisCommandInt("INCR", key)
	if err != nil {
		f.logger.Errorf("Redis error incrementing %s: %v", ip, err)
		return
	}

	f.logger.Debugf("[Redis] Increment %s (count: %d)", ip, count)

	// Set expiration on first increment to the failure window
	if count == 1 {
		if err := f.redisCommand("EXPIRE", key, fmt.Sprintf("%d", int(f.failWindow.Seconds()))); err != nil {
			f.logger.Errorf("Redis error setting TTL for %s: %v", ip, err)
			// Try to clean up the key to avoid indefinite persistence
			f.redisCommand("DEL", key)
		}
	} else if uint(count) >= f.maxFails {
		// Reset TTL to ban time when client gets banned
		if err := f.redisCommand("EXPIRE", key, fmt.Sprintf("%d", int(f.banTime.Seconds()))); err != nil {
			f.logger.Errorf("Redis error setting ban TTL for %s: %v", ip, err)
		} else {
			f.logger.Infof("[Redis] Banned %s after %d failures", ip, count)
		}
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
