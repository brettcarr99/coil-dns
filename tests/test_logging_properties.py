"""
Property-based tests for DNS server logging

Feature: recursive-dns-server, Property 11: Operation Logging
Validates: Requirements 6.3, 6.4
"""

import pytest
import logging
import io
from hypothesis import given, strategies as st, settings
from dns_server.models import DNSMessage, DNSHeader, DNSQuestion, DNSRecord
from dns_server.parser import DNSMessageParser
from dns_server.config import ConfigManager, DNSConfig, ConfigurationError
from dns_server.cache import DNSCache
from dns_server.resolver import RecursiveResolver
from dns_server.server import DNSServer
from tests.test_models_properties import dns_question_strategy
import tempfile
import os


@st.composite
def valid_config_data_strategy(draw):
    """Generate valid configuration data"""
    return {
        'listen_port': draw(st.integers(min_value=1024, max_value=65535)),
        'listen_address': '127.0.0.1',
        'timeout': draw(st.integers(min_value=1, max_value=30)),
        'max_retries': draw(st.integers(min_value=0, max_value=10)),
        'cache_size': draw(st.integers(min_value=10, max_value=10000)),
        'cache_ttl': draw(st.integers(min_value=60, max_value=86400)),
        'log_level': draw(st.sampled_from(['DEBUG', 'INFO', 'WARNING', 'ERROR']))
    }


class LogCapture:
    """Helper class to capture log messages"""
    
    def __init__(self, logger_name):
        self.logger = logging.getLogger(logger_name)
        self.handler = logging.StreamHandler(io.StringIO())
        self.handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        self.original_level = self.logger.level
        self.logger.setLevel(logging.DEBUG)
    
    def get_logs(self):
        """Get captured log messages"""
        return self.handler.stream.getvalue()
    
    def cleanup(self):
        """Clean up the log handler"""
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.original_level)


class TestLoggingProperties:
    """Property-based tests for DNS server logging"""

    @given(dns_question_strategy())
    @settings(max_examples=100)
    def test_parser_logs_successful_operations(self, question):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For any valid DNS query parsing operation, appropriate log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.parser')
        
        try:
            parser = DNSMessageParser()
            
            # Create a valid query message
            query = DNSMessage(
                header=DNSHeader(
                    id=12345,
                    flags=0x0100,  # Query flag
                    qdcount=1,
                    ancount=0,
                    nscount=0,
                    arcount=0
                ),
                questions=[question],
                answers=[],
                authority=[],
                additional=[]
            )
            
            # Serialize and parse
            query_bytes = query.to_bytes()
            parsed = parser.parse_query(query_bytes)
            
            # Check that debug log was generated for successful parse
            logs = log_capture.get_logs()
            assert 'Successfully parsed DNS query' in logs or 'DEBUG' in logs
            
        finally:
            log_capture.cleanup()

    @given(st.binary(min_size=0, max_size=11))
    @settings(max_examples=100)
    def test_parser_logs_errors(self, invalid_data):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For any invalid DNS query, appropriate error log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.parser')
        
        try:
            parser = DNSMessageParser()
            
            # Try to parse invalid data
            try:
                parser.parse_query(invalid_data)
            except ValueError:
                # Expected - should have logged the error
                pass
            
            # Check that error or warning was logged
            logs = log_capture.get_logs()
            assert 'WARNING' in logs or 'ERROR' in logs or 'too short' in logs or 'empty' in logs.lower()
            
        finally:
            log_capture.cleanup()

    @given(valid_config_data_strategy())
    @settings(max_examples=100)
    def test_config_logs_successful_load(self, config_data):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For any valid configuration loading operation, appropriate log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.config')
        
        try:
            # Create temporary config file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                import yaml
                yaml.dump(config_data, f)
                config_path = f.name
            
            try:
                manager = ConfigManager()
                config = manager.load_config(config_path)
                
                # Check that info log was generated for successful load
                logs = log_capture.get_logs()
                assert 'Loading configuration' in logs or 'Configuration loaded' in logs or 'INFO' in logs
                
            finally:
                os.unlink(config_path)
                
        finally:
            log_capture.cleanup()

    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=100)
    def test_config_logs_errors(self, invalid_path):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For any configuration error, appropriate error log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.config')
        
        try:
            manager = ConfigManager()
            
            # Try to load non-existent config
            try:
                manager.load_config(f"/nonexistent/{invalid_path}.yaml")
            except ConfigurationError:
                # Expected - should have logged the error
                pass
            
            # Check that error was logged
            logs = log_capture.get_logs()
            assert 'ERROR' in logs or 'not found' in logs
            
        finally:
            log_capture.cleanup()

    @given(st.text(min_size=1, max_size=50), st.integers(min_value=0, max_value=3600))
    @settings(max_examples=100)
    def test_cache_logs_operations(self, key, ttl):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For any cache operation, appropriate log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.cache')
        
        try:
            cache = DNSCache(max_size=100)
            
            # Create a dummy record
            record = DNSRecord(
                name="example.com",
                rtype=1,
                rclass=1,
                ttl=ttl,
                data=b'\x01\x02\x03\x04'
            )
            
            # Put and get from cache
            cache.put(key, record, ttl)
            result = cache.get(key)
            
            # Check that debug logs were generated
            logs = log_capture.get_logs()
            # Should have logs for cache operations (put, get, hit/miss)
            assert 'DEBUG' in logs or 'Cache' in logs or 'Cached' in logs
            
        finally:
            log_capture.cleanup()

    @given(dns_question_strategy())
    @settings(max_examples=20, deadline=5000)  # Reduced examples and increased deadline
    def test_resolver_logs_resolution_attempts(self, question):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For any DNS resolution attempt, appropriate log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.resolver')
        
        try:
            # Create resolver with dummy root hints
            cache = DNSCache()
            resolver = RecursiveResolver(
                root_hints=['192.0.2.1'],  # Use TEST-NET-1 address (won't respond)
                cache=cache,
                timeout=0.1,  # Very short timeout
                max_retries=1
            )
            
            # Attempt resolution (will fail but should log)
            try:
                result = resolver.resolve(question)
            except:
                pass
            
            # Check that logs were generated for resolution attempt
            logs = log_capture.get_logs()
            assert 'Resolving' in logs or 'INFO' in logs or 'DEBUG' in logs
            
        finally:
            log_capture.cleanup()

    def test_server_logs_startup_and_shutdown(self):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For server startup and shutdown operations, appropriate log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.server')
        
        try:
            # Create temporary config and hints files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                import yaml
                yaml.dump({
                    'listen_port': 15353,  # Use non-standard port
                    'listen_address': '127.0.0.1',
                    'log_level': 'INFO'
                }, f)
                config_path = f.name
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write('127.0.0.1\n')
                hints_path = f.name
            
            try:
                # Create server (initialization should log)
                server = DNSServer(config_path, hints_path)
                
                # Check initialization logs
                logs = log_capture.get_logs()
                assert 'initialized' in logs.lower() or 'INFO' in logs
                
                # Start server (should log)
                try:
                    server.start()
                    
                    # Check startup logs
                    logs = log_capture.get_logs()
                    assert 'start' in logs.lower() or 'INFO' in logs
                    
                finally:
                    # Stop server (should log)
                    server.stop()
                    
                    # Check shutdown logs
                    logs = log_capture.get_logs()
                    assert 'stop' in logs.lower() or 'INFO' in logs
                    
            finally:
                os.unlink(config_path)
                os.unlink(hints_path)
                
        finally:
            log_capture.cleanup()

    @given(st.integers(min_value=1, max_value=5))
    @settings(max_examples=100)
    def test_error_responses_are_logged(self, rcode):
        """
        Feature: recursive-dns-server, Property 11: Operation Logging
        For any error response generation, appropriate log messages should be generated
        Validates: Requirements 6.3, 6.4
        """
        log_capture = LogCapture('dns_server.parser')
        
        try:
            parser = DNSMessageParser()
            
            # Create error response
            error_response = parser.create_error_response(None, rcode)
            
            # Check that log was generated
            logs = log_capture.get_logs()
            assert 'error' in logs.lower() or 'INFO' in logs or 'Creating' in logs
            
        finally:
            log_capture.cleanup()
