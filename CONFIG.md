# Coil Configuration Guide

This document describes how to configure Coil.

## Configuration Files

Coil uses two configuration files:

1. **config.yaml** - Server settings and behavior
2. **root.hints** - Root DNS server IP addresses

Both files must be present for the server to start successfully.

## config.yaml

The main configuration file uses YAML format. All settings are optional and have sensible defaults.

### Network Settings

- **listen_port** (default: 53)
  - Port number to listen on for DNS queries
  - Both UDP and TCP protocols use this port
  - Port 53 is the standard DNS port and requires root/administrator privileges
  - Valid range: 1-65535

- **listen_address** (default: "0.0.0.0")
  - IP address to bind to
  - "0.0.0.0" listens on all network interfaces
  - "127.0.0.1" only accepts queries from localhost
  - Useful for restricting access or testing

### Query Settings

- **timeout** (default: 5)
  - Timeout in seconds for upstream DNS queries
  - How long to wait for a response from nameservers
  - Valid range: 1 or greater
  - Lower values fail faster but may miss slow responses
  - Higher values are more patient but slower to fail

- **max_retries** (default: 3)
  - Maximum number of retry attempts for failed queries
  - Valid range: 0 or greater
  - 0 means no retries (fail immediately)
  - Higher values increase reliability but add latency on failures

### Cache Settings

- **cache_size** (default: 1000)
  - Maximum number of DNS records to cache
  - Valid range: 0 or greater
  - 0 disables caching entirely
  - Larger values use more memory but improve performance
  - Each cached entry stores a DNS record with its TTL

- **cache_ttl** (default: 3600)
  - Default time-to-live in seconds for cached entries
  - Valid range: 0 or greater
  - Individual DNS records may override this with their own TTL
  - Lower values keep cache fresher but increase upstream queries
  - Higher values reduce upstream queries but may serve stale data

### Logging Settings

- **log_level** (default: "INFO")
  - Controls verbosity of log output
  - Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL
  - **DEBUG**: Detailed information for troubleshooting
  - **INFO**: General operational messages
  - **WARNING**: Potential issues that don't prevent operation
  - **ERROR**: Errors that affect specific operations
  - **CRITICAL**: Severe errors that may cause shutdown

### Example Configuration

```yaml
# Minimal configuration (all defaults)
listen_port: 53
listen_address: 0.0.0.0
timeout: 5
max_retries: 3
cache_size: 1000
cache_ttl: 3600
log_level: INFO
```

```yaml
# High-performance configuration
listen_port: 53
listen_address: 0.0.0.0
timeout: 3
max_retries: 2
cache_size: 10000
cache_ttl: 7200
log_level: WARNING
```

```yaml
# Debug configuration
listen_port: 5353
listen_address: 127.0.0.1
timeout: 10
max_retries: 5
cache_size: 100
cache_ttl: 300
log_level: DEBUG
```

## root.hints

The root hints file contains IP addresses of the 13 root DNS servers. These servers are the starting point for all recursive DNS resolution.

### Format

- One IP address per line
- Lines starting with '#' or ';' are comments
- Empty lines are ignored
- IPv4 addresses only (currently)

### Example

```
# A.ROOT-SERVERS.NET
198.41.0.4

# B.ROOT-SERVERS.NET
199.9.14.201
```

### Updating Root Hints

Root server addresses rarely change, but when they do:

1. Visit https://www.iana.org/domains/root/servers
2. Download the latest root hints file
3. Replace the IP addresses in root.hints
4. Restart the DNS server

## Configuration Validation

The server validates all configuration on startup:

- **Missing files**: Server refuses to start
- **Invalid YAML**: Server refuses to start with error message
- **Invalid values**: Server refuses to start with specific error
- **Empty root.hints**: Server refuses to start (must have at least one root server)

All validation errors are logged with detailed messages to help diagnose issues.

## Configuration Errors

Common configuration errors and solutions:

### "Configuration file not found"
- Ensure config.yaml exists in the same directory as the server
- Check file permissions (must be readable)

### "Root hints file not found"
- Ensure root.hints exists in the same directory as the server
- Check file permissions (must be readable)

### "Invalid YAML in configuration file"
- Check YAML syntax (indentation, colons, quotes)
- Use a YAML validator to find syntax errors

### "Invalid IP address at line X"
- Ensure all IP addresses in root.hints are valid IPv4 addresses
- Format: XXX.XXX.XXX.XXX where each XXX is 0-255

### "Configuration validation failed"
- Check that all numeric values are in valid ranges
- Check that log_level is one of: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Ensure listen_port is between 1 and 65535

## Security Considerations

- **Port 53**: Requires root/administrator privileges on most systems
- **listen_address**: Use 127.0.0.1 to restrict to localhost only
- **File permissions**: Ensure configuration files are not world-writable
- **Root hints**: Only use trusted root server addresses

## Performance Tuning

For high-traffic environments:

1. Increase **cache_size** to reduce upstream queries
2. Increase **cache_ttl** for less frequently changing domains
3. Decrease **timeout** to fail faster on unreachable servers
4. Set **log_level** to WARNING or ERROR to reduce I/O

For low-latency requirements:

1. Decrease **timeout** to 2-3 seconds
2. Decrease **max_retries** to 1-2
3. Ensure adequate **cache_size** for working set

For debugging:

1. Set **log_level** to DEBUG
2. Use non-privileged port (e.g., 5353) for testing
3. Set **listen_address** to 127.0.0.1 for local testing
