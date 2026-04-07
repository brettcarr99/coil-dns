"""
Property-based tests for DNS server configuration management.

Feature: recursive-dns-server
Tests configuration loading, validation, and root hints handling.
"""

import pytest
import tempfile
import os
from pathlib import Path
from hypothesis import given, strategies as st, settings
from dns_server.config import ConfigManager, DNSConfig, ConfigurationError


# Strategy for generating valid IPv4 addresses
@st.composite
def ipv4_address(draw):
    """Generate valid IPv4 addresses"""
    octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    return '.'.join(map(str, octets))


# Strategy for generating lists of IP addresses
@st.composite
def ip_address_list(draw):
    """Generate lists of valid IP addresses"""
    count = draw(st.integers(min_value=1, max_value=13))
    return [draw(ipv4_address()) for _ in range(count)]


class TestConfigurationProperties:
    """Property-based tests for configuration management"""
    
    @settings(max_examples=100)
    @given(ip_list=ip_address_list())
    def test_root_hints_round_trip(self, ip_list):
        """
        Property 5: Root Hints Configuration Round-trip
        
        For any valid root hints file in standard format, loading then using 
        the hints for queries should produce the expected root server contacts.
        
        **Validates: Requirements 3.1, 3.4**
        **Feature: recursive-dns-server, Property 5: Root Hints Configuration Round-trip**
        """
        # Create a temporary root hints file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hints') as f:
            hints_path = f.name
            
            # Write IP addresses in standard root hints format
            for ip in ip_list:
                f.write(f"{ip}\n")
        
        try:
            # Load the root hints
            manager = ConfigManager()
            loaded_hints = manager.load_root_hints(hints_path)
            
            # Verify round-trip: loaded hints should match original list
            assert loaded_hints == ip_list, \
                f"Round-trip failed: expected {ip_list}, got {loaded_hints}"
            
            # Verify hints are accessible via property
            assert manager.root_hints == ip_list, \
                "Root hints property should return loaded hints"
            
        finally:
            # Clean up temporary file
            os.unlink(hints_path)
    
    @settings(max_examples=100)
    @given(ip_list=ip_address_list())
    def test_root_hints_with_comments(self, ip_list):
        """
        Property 5 (variant): Root hints with comments and whitespace
        
        For any valid root hints file with comments and whitespace,
        loading should extract only the IP addresses.
        
        **Validates: Requirements 3.1, 3.4**
        **Feature: recursive-dns-server, Property 5: Root Hints Configuration Round-trip**
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hints') as f:
            hints_path = f.name
            
            # Write with comments and whitespace
            f.write("# Root DNS Servers\n")
            f.write("\n")
            for i, ip in enumerate(ip_list):
                f.write(f"; Server {i}\n")
                f.write(f"{ip}\n")
                if i % 2 == 0:
                    f.write("\n")
        
        try:
            manager = ConfigManager()
            loaded_hints = manager.load_root_hints(hints_path)
            
            # Should extract only IP addresses, ignoring comments
            assert loaded_hints == ip_list, \
                f"Failed to parse hints with comments: expected {ip_list}, got {loaded_hints}"
            
        finally:
            os.unlink(hints_path)
    
    @settings(max_examples=100)
    @given(ip_list=ip_address_list())
    def test_root_hints_zone_file_format(self, ip_list):
        """
        Property 5 (variant): Root hints in zone file format
        
        For any valid root hints in zone file format (with names),
        loading should extract the IP addresses.
        
        **Validates: Requirements 3.1, 3.4**
        **Feature: recursive-dns-server, Property 5: Root Hints Configuration Round-trip**
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hints') as f:
            hints_path = f.name
            
            # Write in zone file format: name followed by IP
            for i, ip in enumerate(ip_list):
                f.write(f"a.root-servers.net. {ip}\n")
        
        try:
            manager = ConfigManager()
            loaded_hints = manager.load_root_hints(hints_path)
            
            # Should extract IP addresses from zone file format
            assert loaded_hints == ip_list, \
                f"Failed to parse zone file format: expected {ip_list}, got {loaded_hints}"
            
        finally:
            os.unlink(hints_path)

    @settings(max_examples=100)
    @given(filename=st.text(min_size=1, max_size=50))
    def test_missing_config_file_error(self, filename):
        """
        Property 6: Configuration Error Handling - Missing Files
        
        For any missing or invalid configuration file (config or root hints),
        the server should fail to start with appropriate error messages.
        
        **Validates: Requirements 3.3, 4.3**
        **Feature: recursive-dns-server, Property 6: Configuration Error Handling**
        """
        # Generate a path that definitely doesn't exist
        nonexistent_path = f"/tmp/nonexistent_{filename}_config.yaml"
        
        # Ensure the file doesn't exist
        if os.path.exists(nonexistent_path):
            os.unlink(nonexistent_path)
        
        manager = ConfigManager()
        
        # Should raise ConfigurationError for missing config file
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config(nonexistent_path)
        
        assert "not found" in str(exc_info.value).lower(), \
            "Error message should indicate file not found"
    
    @settings(max_examples=100)
    @given(filename=st.text(min_size=1, max_size=50))
    def test_missing_root_hints_error(self, filename):
        """
        Property 6: Configuration Error Handling - Missing Root Hints
        
        For any missing root hints file, loading should fail with appropriate error.
        
        **Validates: Requirements 3.3, 4.3**
        **Feature: recursive-dns-server, Property 6: Configuration Error Handling**
        """
        # Generate a path that definitely doesn't exist
        nonexistent_path = f"/tmp/nonexistent_{filename}_hints.txt"
        
        # Ensure the file doesn't exist
        if os.path.exists(nonexistent_path):
            os.unlink(nonexistent_path)
        
        manager = ConfigManager()
        
        # Should raise ConfigurationError for missing hints file
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_root_hints(nonexistent_path)
        
        assert "not found" in str(exc_info.value).lower(), \
            "Error message should indicate file not found"
    
    @settings(max_examples=100)
    @given(invalid_content=st.text(min_size=1, max_size=100))
    def test_invalid_yaml_config_error(self, invalid_content):
        """
        Property 6: Configuration Error Handling - Invalid YAML
        
        For any invalid YAML content, loading should fail with appropriate error.
        
        **Validates: Requirements 3.3, 4.3**
        **Feature: recursive-dns-server, Property 6: Configuration Error Handling**
        """
        # Create invalid YAML (unbalanced brackets, etc.)
        invalid_yaml = f"{{{{ {invalid_content} }}}}"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            config_path = f.name
            f.write(invalid_yaml)
        
        try:
            manager = ConfigManager()
            
            # Should raise ConfigurationError for invalid YAML
            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config(config_path)
            
            assert "yaml" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower(), \
                "Error message should indicate YAML or validation error"
        
        finally:
            os.unlink(config_path)
    
    @settings(max_examples=100)
    @given(invalid_ip=st.text(min_size=1, max_size=50).filter(lambda x: '.' not in x or len(x.split('.')) != 4))
    def test_invalid_root_hints_content_error(self, invalid_ip):
        """
        Property 6: Configuration Error Handling - Invalid Root Hints Content
        
        For any invalid IP address in root hints, loading should fail with appropriate error.
        
        **Validates: Requirements 3.3, 4.3**
        **Feature: recursive-dns-server, Property 6: Configuration Error Handling**
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hints') as f:
            hints_path = f.name
            f.write(f"{invalid_ip}\n")
        
        try:
            manager = ConfigManager()
            
            # Should raise ConfigurationError for invalid IP
            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_root_hints(hints_path)
            
            error_msg = str(exc_info.value).lower()
            assert "invalid" in error_msg or "no valid" in error_msg, \
                "Error message should indicate invalid content"
        
        finally:
            os.unlink(hints_path)
    
    @settings(max_examples=100)
    @given(st.just(None))
    def test_empty_root_hints_error(self, _):
        """
        Property 6: Configuration Error Handling - Empty Root Hints
        
        For any empty root hints file, loading should fail with appropriate error.
        
        **Validates: Requirements 3.3, 4.3**
        **Feature: recursive-dns-server, Property 6: Configuration Error Handling**
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hints') as f:
            hints_path = f.name
            # Write only comments and whitespace
            f.write("# Comments only\n")
            f.write("\n")
            f.write("; More comments\n")
        
        try:
            manager = ConfigManager()
            
            # Should raise ConfigurationError for empty hints
            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_root_hints(hints_path)
            
            assert "no valid" in str(exc_info.value).lower() or "contains no" in str(exc_info.value).lower(), \
                "Error message should indicate no valid servers found"
        
        finally:
            os.unlink(hints_path)

    @settings(max_examples=100)
    @given(
        port=st.integers(min_value=1, max_value=65535),
        timeout=st.integers(min_value=1, max_value=300),
        max_retries=st.integers(min_value=0, max_value=10),
        cache_size=st.integers(min_value=0, max_value=100000),
        cache_ttl=st.integers(min_value=0, max_value=86400),
        log_level=st.sampled_from(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    )
    def test_configuration_application(self, port, timeout, max_retries, cache_size, cache_ttl, log_level):
        """
        Property 7: Configuration Application
        
        For any valid configuration file with specified settings, the server 
        should apply those settings (ports, timeouts, cache size) to its operation.
        
        **Validates: Requirements 4.2, 4.4**
        **Feature: recursive-dns-server, Property 7: Configuration Application**
        """
        # Create configuration with specific values
        config_data = {
            'listen_port': port,
            'listen_address': '127.0.0.1',
            'timeout': timeout,
            'max_retries': max_retries,
            'cache_size': cache_size,
            'cache_ttl': cache_ttl,
            'log_level': log_level
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            config_path = f.name
            import yaml
            yaml.dump(config_data, f)
        
        try:
            manager = ConfigManager()
            loaded_config = manager.load_config(config_path)
            
            # Verify all settings were applied correctly
            assert loaded_config.listen_port == port, \
                f"Port not applied: expected {port}, got {loaded_config.listen_port}"
            assert loaded_config.listen_address == '127.0.0.1', \
                f"Address not applied: expected 127.0.0.1, got {loaded_config.listen_address}"
            assert loaded_config.timeout == timeout, \
                f"Timeout not applied: expected {timeout}, got {loaded_config.timeout}"
            assert loaded_config.max_retries == max_retries, \
                f"Max retries not applied: expected {max_retries}, got {loaded_config.max_retries}"
            assert loaded_config.cache_size == cache_size, \
                f"Cache size not applied: expected {cache_size}, got {loaded_config.cache_size}"
            assert loaded_config.cache_ttl == cache_ttl, \
                f"Cache TTL not applied: expected {cache_ttl}, got {loaded_config.cache_ttl}"
            assert loaded_config.log_level == log_level, \
                f"Log level not applied: expected {log_level}, got {loaded_config.log_level}"
            
            # Verify config is accessible via property
            assert manager.config == loaded_config, \
                "Config property should return loaded configuration"
        
        finally:
            os.unlink(config_path)
    
    @settings(max_examples=100)
    @given(
        port=st.integers(min_value=1, max_value=65535),
        timeout=st.integers(min_value=1, max_value=300)
    )
    def test_partial_configuration_with_defaults(self, port, timeout):
        """
        Property 7 (variant): Partial Configuration with Defaults
        
        For any configuration file with only some settings specified,
        the server should apply specified settings and use defaults for others.
        
        **Validates: Requirements 4.2, 4.4**
        **Feature: recursive-dns-server, Property 7: Configuration Application**
        """
        # Create configuration with only some values
        config_data = {
            'listen_port': port,
            'timeout': timeout
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            config_path = f.name
            import yaml
            yaml.dump(config_data, f)
        
        try:
            manager = ConfigManager()
            loaded_config = manager.load_config(config_path)
            
            # Verify specified settings were applied
            assert loaded_config.listen_port == port, \
                f"Port not applied: expected {port}, got {loaded_config.listen_port}"
            assert loaded_config.timeout == timeout, \
                f"Timeout not applied: expected {timeout}, got {loaded_config.timeout}"
            
            # Verify defaults were used for unspecified settings
            assert loaded_config.listen_address == "0.0.0.0", \
                "Default listen_address should be 0.0.0.0"
            assert loaded_config.max_retries == 3, \
                "Default max_retries should be 3"
            assert loaded_config.cache_size == 1000, \
                "Default cache_size should be 1000"
            assert loaded_config.cache_ttl == 3600, \
                "Default cache_ttl should be 3600"
            assert loaded_config.log_level == "INFO", \
                "Default log_level should be INFO"
        
        finally:
            os.unlink(config_path)
    
    @settings(max_examples=100)
    @given(st.just(None))
    def test_empty_configuration_uses_defaults(self, _):
        """
        Property 7 (variant): Empty Configuration Uses Defaults
        
        For any empty configuration file, the server should use all default settings.
        
        **Validates: Requirements 4.2, 4.4**
        **Feature: recursive-dns-server, Property 7: Configuration Application**
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            config_path = f.name
            # Write empty file
            f.write("")
        
        try:
            manager = ConfigManager()
            loaded_config = manager.load_config(config_path)
            
            # Verify all defaults were used
            assert loaded_config.listen_port == 53, \
                "Default listen_port should be 53"
            assert loaded_config.listen_address == "0.0.0.0", \
                "Default listen_address should be 0.0.0.0"
            assert loaded_config.timeout == 5, \
                "Default timeout should be 5"
            assert loaded_config.max_retries == 3, \
                "Default max_retries should be 3"
            assert loaded_config.cache_size == 1000, \
                "Default cache_size should be 1000"
            assert loaded_config.cache_ttl == 3600, \
                "Default cache_ttl should be 3600"
            assert loaded_config.log_level == "INFO", \
                "Default log_level should be INFO"
        
        finally:
            os.unlink(config_path)
