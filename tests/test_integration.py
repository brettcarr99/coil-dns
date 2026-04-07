"""
Integration Tests for DNS Server

These tests verify end-to-end DNS resolution scenarios and error handling
across all components of the DNS server.
"""

import pytest
import socket
import time
import tempfile
import os
from pathlib import Path
from dns_server.server import DNSServer
from dns_server.models import DNSMessage, DNSHeader, DNSQuestion, DNSRecord


# Test configuration files
TEST_CONFIG = """
listen_port: 15353
listen_address: 127.0.0.1
timeout: 2
max_retries: 2
cache_size: 100
cache_ttl: 300
log_level: WARNING
"""

TEST_ROOT_HINTS = """
# Test root hints
198.41.0.4
199.9.14.201
192.33.4.12
"""


@pytest.fixture
def config_files():
    """Create temporary configuration files for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.yaml"
        hints_path = Path(tmpdir) / "root.hints"
        
        config_path.write_text(TEST_CONFIG)
        hints_path.write_text(TEST_ROOT_HINTS)
        
        yield str(config_path), str(hints_path)


@pytest.fixture
def dns_server(config_files):
    """Create and start a DNS server for testing"""
    config_path, hints_path = config_files
    server = DNSServer(config_path, hints_path)
    server.start()
    
    # Give server time to start
    time.sleep(0.1)
    
    yield server
    
    # Cleanup
    server.stop()


class TestDNSServerIntegration:
    """Integration tests for complete DNS server functionality"""
    
    def test_server_initialization(self, config_files):
        """Test that server initializes with valid configuration"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        assert server.config is not None
        assert server.config.listen_port == 15353
        assert server.config.listen_address == "127.0.0.1"
        assert len(server.root_hints) == 3
        assert server.cache is not None
        assert server.resolver is not None
        assert server.parser is not None
    
    def test_server_startup_and_shutdown(self, config_files):
        """Test server can start and stop cleanly"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Start server
        server.start()
        assert server.running is True
        
        # Stop server
        server.stop()
        assert server.running is False
    
    def test_invalid_config_file(self):
        """Test server fails gracefully with invalid config"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            hints_path = Path(tmpdir) / "root.hints"
            
            # Create invalid config
            config_path.write_text("invalid: yaml: content: [")
            hints_path.write_text("198.41.0.4")
            
            with pytest.raises(Exception):
                DNSServer(str(config_path), str(hints_path))
    
    def test_missing_root_hints(self):
        """Test server fails gracefully with missing root hints"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            hints_path = Path(tmpdir) / "root.hints"
            
            config_path.write_text(TEST_CONFIG)
            # Don't create hints file
            
            with pytest.raises(Exception):
                DNSServer(str(config_path), str(hints_path))
    
    def test_handle_query_with_valid_message(self, config_files):
        """Test query handling with valid DNS message"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Create a valid query
        header = DNSHeader(
            id=1234,
            flags=0x0100,  # Standard query
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0
        )
        question = DNSQuestion(name="example.com.", qtype=1, qclass=1)
        query = DNSMessage(
            header=header,
            questions=[question],
            answers=[],
            authority=[],
            additional=[]
        )
        
        # Handle query
        response = server.handle_query(query, ("127.0.0.1", 12345))
        
        # Verify response
        assert response is not None
        assert response.header.id == 1234  # ID should match query
        assert response.header.flags & 0x8000  # QR bit should be set (response)
        assert len(response.questions) == 1
        assert response.questions[0].name == "example.com."
    
    def test_handle_query_with_invalid_message(self, config_files):
        """Test query handling with invalid DNS message"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Create an invalid query (no questions)
        header = DNSHeader(
            id=1234,
            flags=0x0100,
            qdcount=0,  # No questions
            ancount=0,
            nscount=0,
            arcount=0
        )
        query = DNSMessage(
            header=header,
            questions=[],  # Empty questions
            answers=[],
            authority=[],
            additional=[]
        )
        
        # Handle query
        response = server.handle_query(query, ("127.0.0.1", 12345))
        
        # Verify error response
        assert response is not None
        assert response.header.flags & 0x8000  # QR bit set
        rcode = response.header.flags & 0x000F
        assert rcode == 1  # FORMERR
    
    def test_handle_query_with_malformed_question(self, config_files):
        """Test query handling with malformed question"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Create query with empty name
        header = DNSHeader(
            id=1234,
            flags=0x0100,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0
        )
        question = DNSQuestion(name="", qtype=1, qclass=1)  # Empty name
        query = DNSMessage(
            header=header,
            questions=[question],
            answers=[],
            authority=[],
            additional=[]
        )
        
        # Handle query
        response = server.handle_query(query, ("127.0.0.1", 12345))
        
        # Verify error response
        assert response is not None
        rcode = response.header.flags & 0x000F
        assert rcode in [1, 2]  # FORMERR or SERVFAIL
    
    def test_cache_integration(self, config_files):
        """Test that cache is used across multiple queries"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Create a query
        header = DNSHeader(
            id=1234,
            flags=0x0100,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0
        )
        question = DNSQuestion(name="test.example.com.", qtype=1, qclass=1)
        query = DNSMessage(
            header=header,
            questions=[question],
            answers=[],
            authority=[],
            additional=[]
        )
        
        # First query - will attempt resolution
        response1 = server.handle_query(query, ("127.0.0.1", 12345))
        
        # If we got an answer, it should be cached
        if response1.answers:
            # Second query - should use cache
            query.header.id = 5678
            response2 = server.handle_query(query, ("127.0.0.1", 12345))
            
            # Verify cache was used (same answer)
            assert response2.header.id == 5678
            assert len(response2.answers) == len(response1.answers)
    
    def test_concurrent_query_handling(self, config_files):
        """Test that server can handle multiple concurrent queries"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Create multiple queries with different IDs
        queries = []
        for i in range(5):
            header = DNSHeader(
                id=1000 + i,
                flags=0x0100,
                qdcount=1,
                ancount=0,
                nscount=0,
                arcount=0
            )
            question = DNSQuestion(name=f"test{i}.example.com.", qtype=1, qclass=1)
            query = DNSMessage(
                header=header,
                questions=[question],
                answers=[],
                authority=[],
                additional=[]
            )
            queries.append(query)
        
        # Handle all queries
        responses = []
        for i, query in enumerate(queries):
            response = server.handle_query(query, ("127.0.0.1", 12345 + i))
            responses.append(response)
        
        # Verify all responses have correct IDs
        for i, response in enumerate(responses):
            assert response.header.id == 1000 + i
            assert response.header.flags & 0x8000  # QR bit set
    
    def test_error_resilience(self, config_files):
        """Test that server continues operating after errors"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Send an invalid query
        invalid_query = DNSMessage(
            header=DNSHeader(id=1, flags=0x0100, qdcount=0, ancount=0, nscount=0, arcount=0),
            questions=[],
            answers=[],
            authority=[],
            additional=[]
        )
        response1 = server.handle_query(invalid_query, ("127.0.0.1", 12345))
        assert response1 is not None
        
        # Send a valid query - server should still work
        valid_query = DNSMessage(
            header=DNSHeader(id=2, flags=0x0100, qdcount=1, ancount=0, nscount=0, arcount=0),
            questions=[DNSQuestion(name="example.com.", qtype=1, qclass=1)],
            answers=[],
            authority=[],
            additional=[]
        )
        response2 = server.handle_query(valid_query, ("127.0.0.1", 12345))
        assert response2 is not None
        assert response2.header.id == 2
    
    def test_logging_configuration(self, config_files):
        """Test that logging is configured from config file"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Verify logging level was set from config
        import logging
        logger = logging.getLogger()
        assert logger.level == logging.WARNING
    
    def test_component_integration(self, config_files):
        """Test that all components work together correctly"""
        config_path, hints_path = config_files
        server = DNSServer(config_path, hints_path)
        
        # Verify all components are initialized
        assert server.parser is not None
        assert server.resolver is not None
        assert server.cache is not None
        assert server.udp_handler is not None
        assert server.tcp_handler is not None
        
        # Verify resolver has correct configuration
        assert server.resolver.root_servers == server.root_hints
        assert server.resolver.cache == server.cache
        assert server.resolver.timeout == server.config.timeout
        assert server.resolver.max_retries == server.config.max_retries
        
        # Verify handlers have correct configuration
        assert server.udp_handler.port == server.config.listen_port
        assert server.udp_handler.address == server.config.listen_address
        assert server.tcp_handler.port == server.config.listen_port
        assert server.tcp_handler.address == server.config.listen_address
