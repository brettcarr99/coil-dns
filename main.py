#!/usr/bin/env python3
"""
Coil - Recursive DNS Recursor

Entry point for Coil. Loads configuration from config.yaml and root.hints,
then starts the recursive DNS server.
"""

import sys
import argparse
import logging
import signal
from pathlib import Path
from dns_server.server import DNSServer
from dns_server.config import ConfigurationError


def setup_logging(log_level: str = "INFO") -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def validate_files(config_path: Path, hints_path: Path) -> bool:
    """
    Validate that required configuration files exist and are readable.
    
    Args:
        config_path: Path to configuration file
        hints_path: Path to root hints file
        
    Returns:
        True if all files are valid, False otherwise
    """
    errors = []
    
    if not config_path.exists():
        errors.append(f"Configuration file not found: {config_path}")
    elif not config_path.is_file():
        errors.append(f"Configuration path is not a file: {config_path}")
    elif not config_path.stat().st_size > 0:
        errors.append(f"Configuration file is empty: {config_path}")
    
    if not hints_path.exists():
        errors.append(f"Root hints file not found: {hints_path}")
    elif not hints_path.is_file():
        errors.append(f"Root hints path is not a file: {hints_path}")
    elif not hints_path.stat().st_size > 0:
        errors.append(f"Root hints file is empty: {hints_path}")
    
    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        print("\nPlease ensure both config.yaml and root.hints files exist.", file=sys.stderr)
        print("See CONFIG.md for configuration documentation.", file=sys.stderr)
        return False
    
    return True


def main():
    """Main entry point for DNS server"""
    parser = argparse.ArgumentParser(
        description='Coil - Recursive DNS Recursor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server with default configuration
  python main.py
  
  # Start server with custom configuration files
  python main.py --config /path/to/config.yaml --hints /path/to/root.hints
  
  # Start server on custom port (overrides config file)
  python main.py --port 5353
  
  # Start server with debug logging
  python main.py --log-level DEBUG
  
  # Validate configuration without starting server
  python main.py --validate

Configuration Files:
  config.yaml  - Server configuration (port, timeouts, cache settings)
  root.hints   - Root DNS server IP addresses
  
  See CONFIG.md for detailed configuration documentation.

Requirements:
  - Port 53 requires root/administrator privileges
  - Both config.yaml and root.hints must exist
  - Configuration files must be valid YAML/text format
        """
    )
    
    parser.add_argument(
        '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--hints',
        default='root.hints',
        help='Path to root hints file (default: root.hints)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        metavar='PORT',
        help='Override listen port from config file (1-65535)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        metavar='LEVEL',
        help='Override log level from config file'
    )
    
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate configuration and exit without starting server'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Coil 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Convert paths to Path objects
    config_path = Path(args.config)
    hints_path = Path(args.hints)
    
    # Validate port if specified
    if args.port is not None:
        if args.port < 1 or args.port > 65535:
            print(f"Error: Port must be between 1 and 65535, got {args.port}", file=sys.stderr)
            return 1
        if args.port < 1024:
            print(f"Warning: Port {args.port} requires root/administrator privileges", file=sys.stderr)
    
    # Set up initial logging (may be overridden by config)
    setup_logging(args.log_level or 'INFO')
    logger = logging.getLogger(__name__)
    
    # Validate configuration files exist
    if not validate_files(config_path, hints_path):
        return 1
    
    try:
        # Create DNS server (loads and validates configuration)
        logger.info("Initializing Coil...")
        logger.info(f"  Configuration: {config_path.absolute()}")
        logger.info(f"  Root hints:    {hints_path.absolute()}")
        
        server = DNSServer(str(config_path), str(hints_path))
        
        # Override log level if specified
        if args.log_level:
            server.config.log_level = args.log_level
            logging.getLogger().setLevel(args.log_level)
            logger.info(f"  Log level:     {args.log_level} (overridden)")
        
        # Override port if specified
        if args.port:
            server.config.listen_port = args.port
            server.udp_handler.port = args.port
            server.tcp_handler.port = args.port
            logger.info(f"  Listen port:   {args.port} (overridden)")
        else:
            logger.info(f"  Listen port:   {server.config.listen_port}")
        
        logger.info(f"  Listen address: {server.config.listen_address}")
        logger.info(f"  Root servers:   {len(server.root_hints)} configured")
        logger.info(f"  Cache size:     {server.config.cache_size} entries")
        logger.info(f"  Query timeout:  {server.config.timeout}s")
        logger.info(f"  Max retries:    {server.config.max_retries}")
        
        # If validate-only mode, exit here
        if args.validate:
            logger.info("Configuration validation successful!")
            print("\n✓ Configuration is valid")
            print(f"✓ Found {len(server.root_hints)} root servers")
            print(f"✓ Server would listen on {server.config.listen_address}:{server.config.listen_port}")
            return 0
        
        # Start the server
        logger.info("Starting Coil...")
        print(f"\nCoil starting...")
        print(f"  Listening on {server.config.listen_address}:{server.config.listen_port}")
        print(f"  Press Ctrl+C to stop\n")
        
        # Run the server (blocks until interrupted)
        server.run()
        
        return 0
        
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        print(f"\nConfiguration Error: {e}", file=sys.stderr)
        print("See CONFIG.md for configuration documentation.", file=sys.stderr)
        return 1
    
    except PermissionError as e:
        logger.error(f"Permission denied: {e}")
        print(f"\nPermission Error: {e}", file=sys.stderr)
        print("Hint: Port 53 requires root/administrator privileges.", file=sys.stderr)
        print("Try running with sudo or use a different port (--port 5353).", file=sys.stderr)
        return 1
    
    except OSError as e:
        logger.error(f"Network error: {e}")
        print(f"\nNetwork Error: {e}", file=sys.stderr)
        if "Address already in use" in str(e):
            print("Hint: Another process is already using this port.", file=sys.stderr)
            print("Try stopping the other process or use a different port.", file=sys.stderr)
        return 1
    
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
        print("\n\nShutting down gracefully...")
        if 'server' in locals():
            server.stop()
        print("Server stopped.")
        return 0
    
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\nUnexpected Error: {e}", file=sys.stderr)
        print("Please check the logs for more details.", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
