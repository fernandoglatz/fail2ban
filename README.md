# HTTP Fail 2 Ban Traefik Plugin

[![Build Status](https://github.com/charanpreetp/fail2ban/actions/workflows/go.yml/badge.svg)](https://github.com/charanpreetp/fail2ban/actions/workflows/go.yml)

## Usage

This plugin is an HTTP Traefik Middleware which will track wether a client is being naughty or not. This is tracked by checking if there are too many bad client requests (ie, server responds with status code `400` to `499`), the client will be banned from making further requests for a configured amount of time. The Middleware will respond immediately with a `403` response to a client if it is banned and not send the request further downstream.


> **NOTE:** Use this with Traefik 2.10+. Version below may still work but there seem to be errors in logs related to Yaegi value reflection panics and other random error messages for this plugin so best to just use Traefik 2.10+ where the Yaegi issue(s) are fixed.


## Configuration Options
Here are a list of settings you can optionally set for the Middleware
| Config | Default | Description |
| ------ | ------ | ------ |
| NumberFails | `3` | Number of times a client can make a request with a 4xx class HTTP response code before it gets banned |
| BanTime | `3h` | How long to Ban clients who make too many bad requests. Valid time units are `ns`, `us` (or `µs`), `ms`, `s`, `m`, `h`. Eg, `3h30m` would be for banning for 3 hours and 30 minutes |
| FailWindow | `10m` | Time window to track failures before resetting the counter. Valid time units are `ns`, `us` (or `µs`), `ms`, `s`, `m`, `h` |
| ClientHeader | `Cf-Connecting-IP` | You want to use a specific header to track clients. Useful if the client's real IP is in a header when you're behind CloudFlare, a LoadBalancer or WAF, etc. If this is not set, it will just use the [RemoteAddr's](https://cs.opensource.google/go/go/+/refs/tags/go1.21.6:src/net/http/request.go;l=294) IP |
| LogLevel | `INFO` | Log verbosity level, can be `DEBUG`, `INFO`, `WARN`, or `ERROR` |
| RedisAddress | `""` | Redis server address in format `host:port` (e.g., `redis:6379`). If not set, uses in-memory storage |
| RedisPassword | `""` | Redis authentication password. Leave empty if Redis has no password |
| RedisDB | `0` | Redis database number to use (0-15) |