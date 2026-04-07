"""
Coil - Configuration Management

Loads and validates Coil configuration from YAML files and root hints files.
"""

import yaml
import logging
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path


@dataclass
class DNSConfig:
    """Coil configuration settings"""
    listen_port: int = 53
    listen_address: str = "0.0.0.0"
    timeout: int = 5
    max_retries: int = 3
    cache_size: int = 1000
    cache_ttl: int = 3600
    log_level: str = "INFO"


class ConfigurationError(Exception):
    """Raised when configuration is invalid or cannot be loaded"""
    pass


class ConfigManager:
    """Manages Coil configuration and root hints"""
    
    def __init__(self):
        self._config: Optional[DNSConfig] = None
        self._root_hints: Optional[List[str]] = None
        self.logger = logging.getLogger(__name__)
    
    def load_config(self, path: str) -> DNSConfig:
        """
        Load configuration from YAML file.
        
        Args:
            path: Path to configuration YAML file
            
        Returns:
            DNSConfig object with loaded settings
            
        Raises:
            ConfigurationError: If file cannot be read or is invalid
        """
        self.logger.info(f"Loading configuration from {path}")
        config_path = Path(path)
        
        if not config_path.exists():
            self.logger.error(f"Configuration file not found: {path}")
            raise ConfigurationError(f"Configuration file not found: {path}")
        
        if not config_path.is_file():
            self.logger.error(f"Configuration path is not a file: {path}")
            raise ConfigurationError(f"Configuration path is not a file: {path}")
        
        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.logger.error(f"Invalid YAML in configuration file: {e}")
            raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
        except IOError as e:
            self.logger.error(f"Cannot read configuration file: {e}")
            raise ConfigurationError(f"Cannot read configuration file: {e}")
        
        if data is None:
            # Empty file, use defaults
            self.logger.info("Configuration file is empty, using defaults")
            self._config = DNSConfig()
            return self._config
        
        if not isinstance(data, dict):
            self.logger.error("Configuration file must contain a YAML dictionary")
            raise ConfigurationError("Configuration file must contain a YAML dictionary")
        
        # Extract configuration values with defaults
        try:
            config = DNSConfig(
                listen_port=data.get('listen_port', 53),
                listen_address=data.get('listen_address', '0.0.0.0'),
                timeout=data.get('timeout', 5),
                max_retries=data.get('max_retries', 3),
                cache_size=data.get('cache_size', 1000),
                cache_ttl=data.get('cache_ttl', 3600),
                log_level=data.get('log_level', 'INFO')
            )
        except (TypeError, ValueError) as e:
            self.logger.error(f"Invalid configuration values: {e}")
            raise ConfigurationError(f"Invalid configuration values: {e}")
        
        # Validate the configuration
        if not self.validate_config(config):
            self.logger.error("Configuration validation failed")
            raise ConfigurationError("Configuration validation failed")
        
        self.logger.info(f"Configuration loaded successfully: port={config.listen_port}, log_level={config.log_level}")
        self._config = config
        return config
    
    def load_root_hints(self, path: str) -> List[str]:
        """
        Load root server hints from file.
        
        The root hints file should contain IP addresses of root DNS servers,
        one per line. Lines starting with '#' or ';' are treated as comments.
        
        Args:
            path: Path to root hints file
            
        Returns:
            List of root server IP addresses
            
        Raises:
            ConfigurationError: If file cannot be read or is invalid
        """
        self.logger.info(f"Loading root hints from {path}")
        hints_path = Path(path)
        
        if not hints_path.exists():
            self.logger.error(f"Root hints file not found: {path}")
            raise ConfigurationError(f"Root hints file not found: {path}")
        
        if not hints_path.is_file():
            self.logger.error(f"Root hints path is not a file: {path}")
            raise ConfigurationError(f"Root hints path is not a file: {path}")
        
        try:
            with open(hints_path, 'r') as f:
                lines = f.readlines()
        except IOError as e:
            self.logger.error(f"Cannot read root hints file: {e}")
            raise ConfigurationError(f"Cannot read root hints file: {e}")
        
        # Parse root hints
        root_servers = []
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # Extract IP address (simple validation)
            # Support both simple IP lists and zone file format
            parts = line.split()
            if not parts:
                continue
            
            # Take the last part as IP address (handles zone file format)
            ip_address = parts[-1]
            
            # Basic IP address validation
            if self._is_valid_ip(ip_address):
                root_servers.append(ip_address)
                self.logger.debug(f"Added root server: {ip_address}")
            else:
                self.logger.error(f"Invalid IP address at line {line_num}: {ip_address}")
                raise ConfigurationError(
                    f"Invalid IP address at line {line_num}: {ip_address}"
                )
        
        if not root_servers:
            self.logger.error("Root hints file contains no valid root servers")
            raise ConfigurationError("Root hints file contains no valid root servers")
        
        self.logger.info(f"Loaded {len(root_servers)} root server(s)")
        self._root_hints = root_servers
        return root_servers
    
    def validate_config(self, config: DNSConfig) -> bool:
        """
        Validate configuration values.
        
        Args:
            config: DNSConfig object to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        if not config:
            return False
        
        # Validate port number
        if not isinstance(config.listen_port, int) or config.listen_port < 1 or config.listen_port > 65535:
            return False
        
        # Validate timeout
        if not isinstance(config.timeout, int) or config.timeout < 1:
            return False
        
        # Validate max_retries
        if not isinstance(config.max_retries, int) or config.max_retries < 0:
            return False
        
        # Validate cache_size
        if not isinstance(config.cache_size, int) or config.cache_size < 0:
            return False
        
        # Validate cache_ttl
        if not isinstance(config.cache_ttl, int) or config.cache_ttl < 0:
            return False
        
        # Validate log_level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if not isinstance(config.log_level, str) or config.log_level.upper() not in valid_log_levels:
            return False
        
        # Validate listen_address is a string
        if not isinstance(config.listen_address, str):
            return False
        
        return True
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate an IPv4 or IPv6 address.

        Args:
            ip: IP address string to validate

        Returns:
            True if valid IPv4 or IPv6 address, False otherwise
        """
        import socket as _socket
        for family in (_socket.AF_INET, _socket.AF_INET6):
            try:
                _socket.inet_pton(family, ip)
                return True
            except (OSError, ValueError):
                pass
        return False
    
    @property
    def config(self) -> Optional[DNSConfig]:
        """Get the loaded configuration"""
        return self._config
    
    @property
    def root_hints(self) -> Optional[List[str]]:
        """Get the loaded root hints"""
        return self._root_hints
