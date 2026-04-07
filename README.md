# Coil - Recursive DNS Recursor

A fully-featured recursive DNS recursor implementation in Python that performs complete DNS resolution by querying internet root servers directly.

## Features

- **Full Recursive Resolution**: Starts with root servers and follows referrals down the DNS hierarchy
- **Dual Protocol Support**: Handles both UDP and TCP DNS queries
- **Intelligent Caching**: TTL-based caching with automatic expiration
- **Concurrent Handling**: Multi-threaded request processing for high performance
- **Comprehensive Error Handling**: Graceful error recovery and detailed logging
- **Configurable**: YAML-based configuration for all server settings
- **Property-Based Testing**: Extensive test coverage using Hypothesis

## Requirements

- Python 3.8+
- PyYAML
- Hypothesis (for testing)
- pytest (for testing)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

1. **Validate configuration** (recommended first step):
   ```bash
   python main.py --validate
   ```

2. **Configure the server** (optional - defaults provided):
   ```bash
   # Edit config.yaml to customize settings
   # Edit root.hints to specify root DNS servers
   # See CONFIG.md for detailed configuration documentation
   ```

3. **Run the server**:
   ```bash
   # Run on default port 53 (requires root/sudo)
   sudo python main.py
   
   # Or run on a non-privileged port
   python main.py --port 5353
   
   # Run with debug logging
   python main.py --log-level DEBUG
   
   # Use custom configuration files
   python main.py --config /path/to/config.yaml --hints /path/to/root.hints
   ```

4. **Test the server**:
   ```bash
   # Using dig (on port 5353)
   dig @localhost -p 5353 example.com
   
   # Using nslookup
   nslookup -port=5353 example.com localhost
   ```

## Command-Line Options

```
usage: main.py [-h] [--config CONFIG] [--hints HINTS] [--port PORT] 
               [--log-level LEVEL] [--validate] [--version]

Options:
  --config CONFIG       Path to configuration file (default: config.yaml)
  --hints HINTS         Path to root hints file (default: root.hints)
  --port PORT           Override listen port from config file (1-65535)
  --log-level LEVEL     Override log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  --validate            Validate configuration and exit without starting server
  --version             Show version and exit
  -h, --help            Show help message and exit
```

Examples:
```bash
# Validate configuration before starting
python main.py --validate

# Start with custom port
python main.py --port 5353

# Start with debug logging
python main.py --log-level DEBUG

# Use custom configuration files
python main.py --config custom.yaml --hints custom.hints
```

## Configuration

See [CONFIG.md](CONFIG.md) for detailed configuration documentation.

### config.yaml

```yaml
# Network settings
listen_port: 53          # Port to listen on
listen_address: 0.0.0.0  # Address to bind to

# Query settings
timeout: 5               # Query timeout in seconds
max_retries: 3          # Maximum retry attempts

# Cache settings
cache_size: 1000        # Maximum cache entries
cache_ttl: 3600         # Default TTL in seconds

# Logging
log_level: INFO         # DEBUG, INFO, WARNING, ERROR, CRITICAL
```

### root.hints

The root hints file contains IP addresses of root DNS servers, one per line. Comments start with `#` or `;`.

## Architecture

The server is built with a modular architecture:

- **DNSServer**: Main coordinator that integrates all components
- **DNSMessageParser**: Parses and serializes DNS messages
- **RecursiveResolver**: Implements recursive resolution logic
- **DNSCache**: Thread-safe cache with TTL support
- **UDPHandler/TCPHandler**: Network protocol handlers
- **ConfigManager**: Configuration and root hints management

## Testing

Run the complete test suite:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=dns_server

# Run specific test categories
pytest tests/test_integration.py      # Integration tests
pytest tests/test_parser_properties.py # Parser property tests
pytest tests/test_resolver_properties.py # Resolver property tests
```

## Project Structure

```
.
├── dns_server/           # Coil package
│   ├── __init__.py
│   ├── server.py        # Coil server coordinator
│   ├── parser.py        # DNS message parsing
│   ├── resolver.py      # Recursive resolution logic
│   ├── cache.py         # DNS cache implementation
│   ├── handlers.py      # UDP/TCP network handlers
│   ├── config.py        # Configuration management
│   ├── models.py        # DNS data models
│   └── network_client.py # Network client for upstream queries
├── tests/               # Test suite
│   ├── test_integration.py
│   ├── test_parser_properties.py
│   ├── test_resolver_properties.py
│   ├── test_cache.py
│   └── ...
├── config.yaml          # Server configuration
├── root.hints          # Root DNS servers
├── main.py             # Entry point
└── requirements.txt    # Python dependencies
```

## Implementation Details

### DNS Resolution Process

1. Client sends query to server (UDP or TCP)
2. Server checks cache for existing record
3. If not cached, starts recursive resolution:
   - Query root servers for TLD nameservers
   - Query TLD nameservers for authoritative nameservers
   - Query authoritative nameservers for final answer
4. Cache the result with TTL
5. Return response to client

### Error Handling

The server handles various error conditions:
- Network timeouts and connection failures
- Malformed DNS messages
- Invalid configuration
- Cache overflow
- Concurrent access conflicts

All errors are logged with appropriate severity levels, and the server continues operating whenever possible.

### Correctness Properties

The implementation is validated against formal correctness properties:
- DNS message serialization round-trip
- Query processing for all valid queries
- Error response generation for invalid queries
- Recursive resolution initiation from root servers
- DNS hierarchy traversal following referrals
- Configuration round-trip and error handling
- UDP size limit handling with truncation
- Concurrent request handling
- Error resilience and logging

## License

This project is provided as-is for educational purposes.

## Contributing

This is a specification-driven implementation. See `.kiro/specs/recursive-dns-server/` for:
- `requirements.md` - Formal requirements using EARS patterns
- `design.md` - Detailed design with correctness properties
- `tasks.md` - Implementation task breakdown
