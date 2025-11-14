# HTTP Fail 2 Ban Traefik Plugin

[![Build Status](https://github.com/charanpreetp/fail2ban/actions/workflows/go.yml/badge.svg)](https://github.com/charanpreetp/fail2ban/actions/workflows/go.yml)

## Usage

This plugin is an HTTP Traefik Middleware which will track wether a client is being naughty or not. This is tracked by checking if there are too many bad client requests (ie, server responds with status code `400` to `499`), the client will be banned from making further requests for a configured amount of time. The Middleware will respond immediately with a `403` response to a client if it is banned and not send the request further downstream.


> **NOTE:** Use this with Traefik 2.10+. Version below may still work but there seem to be errors in logs related to Yaegi value reflection panics and other random error messages for this plugin so best to just use Traefik 2.10+ where the Yaegi issue(s) are fixed.


## Configuration Options
Here are a list of settings you can optionally set for the Middleware
| Config | Default | Description |
| ------ | ------ | ------ |
| NumberFails | `5` | Number of times a client can make a request with a 4xx class HTTP response code before it gets banned |
| BanTime | `1h` | How long to Ban clients who make too many bad requests. Valid time units are `ns`, `us` (or `µs`), `ms`, `s`, `m`, `h`. Eg, `3h30m` would be for banning for 3 hours and 30 minutes |
| FailWindow | `10m` | Time window to track failures before resetting the counter. Valid time units are `ns`, `us` (or `µs`), `ms`, `s`, `m`, `h` |
| ClientHeader | `X-Real-Ip` | You want to use a specific header to track clients. Useful if the client's real IP is in a header when you're behind CloudFlare, a LoadBalancer or WAF, etc. If this is not set, it will just use the [RemoteAddr's](https://cs.opensource.google/go/go/+/refs/tags/go1.21.6:src/net/http/request.go;l=294) IP |
| LogLevel | `INFO` | Log verbosity level, can be `DEBUG`, `INFO`, `WARN`, or `ERROR` |
| RedisAddress | `""` | Redis server address in format `host:port` (e.g., `redis:6379`). If not set, uses in-memory storage |
| RedisPassword | `""` | Redis authentication password. Leave empty if Redis has no password |
| RedisDB | `0` | Redis database number to use (0-15) |
| AllowlistCIDRs | `[]` | List of CIDR ranges to allowlist (e.g., `["10.0.0.0/8", "192.168.1.0/24"]`). IPs matching these ranges will never be banned or tracked |
| DenylistCIDRs | `[]` | List of CIDR ranges to denylist (e.g., `["192.0.2.0/24", "198.51.100.5/32"]`). IPs matching these ranges will be immediately blocked with 403 Forbidden |
| NotifyURL | `""` | HTTP endpoint to send POST notifications when a user is banned (e.g., `"https://api.example.com/ban-webhook"`). Leave empty to disable notifications |
| NotifyHeaders | `{}` | Custom HTTP headers to include in ban notification requests (e.g., `{"API_KEY": "secret123", "Authorization": "Bearer token"}`). Useful for authentication |

## Ban Notifications

When a client is banned, the plugin can optionally send an HTTP POST notification to a configured endpoint. This is useful for logging, alerting, or triggering automated responses.

### Notification Payload

The notification is sent as JSON with the following structure:

```json
{
  "ip": "192.168.1.100",
  "fail_count": 5,
  "ban_time": "1h0m0s",
  "timestamp": "2025-11-14T12:30:45Z",
  "request": {
    "method": "POST",
    "path": "/api/login",
    "query": "redirect=/dashboard",
    "host": "example.com",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    "referer": "https://example.com/",
    "remote_addr": "192.168.1.100:54321",
    "headers": {
      "Accept": ["application/json"],
      "Content-Type": ["application/x-www-form-urlencoded"],
      "Cookie": ["session=abc123"],
      "X-Forwarded-For": ["10.0.0.1", "192.168.1.100"]
    }
  }
}
```

### Example Configuration

**YAML format:**

```yaml
http:
  middlewares:
    my-fail2ban:
      plugin:
        fail2ban:
          NumberFails: 5
          BanTime: "1h"
          FailWindow: "10m"
          ClientHeader: "X-Real-Ip"
          LogLevel: "INFO"
          # Redis configuration (optional - uses in-memory if not set)
          RedisAddress: "redis:6379"
          RedisPassword: "your-redis-password"
          RedisDB: 0
          # Allowlist trusted IPs/ranges (never banned)
          AllowlistCIDRs:
            - "10.0.0.0/8"        # Private network
            - "192.168.1.0/24"    # Local network
            - "203.0.113.5/32"    # Specific trusted IP
          # Denylist malicious IPs/ranges (always blocked)
          DenylistCIDRs:
            - "192.0.2.0/24"      # Known bad network
            - "198.51.100.50/32"  # Specific bad IP
          # Ban notification webhook (optional)
          NotifyURL: "https://api.example.com/ban-webhook"
          NotifyHeaders:
            API_KEY: "secret123"
            Authorization: "Bearer your-token"
```

**TOML format:**

```toml
[http.middlewares]
  [http.middlewares.my-fail2ban.plugin.fail2ban]
    NumberFails = 5
    BanTime = "1h"
    FailWindow = "10m"
    ClientHeader = "X-Real-Ip"
    LogLevel = "INFO"
    # Redis configuration (optional - uses in-memory if not set)
    RedisAddress = "redis:6379"
    RedisPassword = "your-redis-password"
    RedisDB = 0
    # Allowlist trusted IPs/ranges (never banned)
    AllowlistCIDRs = [
      "10.0.0.0/8",        # Private network
      "192.168.1.0/24",    # Local network
      "203.0.113.5/32"     # Specific trusted IP
    ]
    # Denylist malicious IPs/ranges (always blocked)
    DenylistCIDRs = [
      "192.0.2.0/24",      # Known bad network
      "198.51.100.50/32"   # Specific bad IP
    ]
    # Ban notification webhook (optional)
    NotifyURL = "https://api.example.com/ban-webhook"
    
    [http.middlewares.my-fail2ban.plugin.fail2ban.NotifyHeaders]
      API_KEY = "secret123"
      Authorization = "Bearer your-token"
```