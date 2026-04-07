"""
Property-based tests for DNS network client

Feature: recursive-dns-server
Tests Property 10 related to error resilience
"""

import pytest
import socket
from hypothesis import given, strategies as st, settings, assume
from unittest.mock import Mock, patch, MagicMock
from dns_server.models import DNSMessage, DNSHeader, DNSQuestion, DNSRecord
from dns_server.network_client import NetworkClient
from dns_server.resolver import RecursiveResolver, TYPE_A, CLASS_IN, RCODE_SERVFAIL
from dns_server.cache import DNSCache


@st.composite
def valid_ip_address_strategy(draw):
    """Generate valid IPv4 addresses"""
    octets = [draw(st.integers(min_value=1, max_value=255)) for _ in range(4)]
    return '.'.join(str(o) for o in octets)


@st.composite
def root_hints_strategy(draw):
    """Generate list of root server IP addresses"""
    num_servers = draw(st.integers(min_value=1, max_value=13))
    return [draw(valid_ip_address_strategy()) for _ in range(num_servers)]


@st.composite
def dns_question_strategy(draw):
    """Generate valid DNS questions"""
    # Generate domain name with ASCII-only characters
    num_labels = draw(st.integers(min_value=1, max_value=4))
    # Use only lowercase letters and digits (valid DNS characters)
    labels = [draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789', min_size=1, max_size=10)) 
              for _ in range(num_labels)]
    domain = '.'.join(labels) + '.'
    
    qtype = TYPE_A
    qclass = CLASS_IN
    
    return DNSQuestion(name=domain, qtype=qtype, qclass=qclass)


@st.composite
def dns_query_strategy(draw):
    """Generate valid DNS query messages"""
    question = draw(dns_question_strategy())
    query_id = draw(st.integers(min_value=0, max_value=65535))
    
    header = DNSHeader(
        id=query_id,
        flags=0x0100,  # Standard query
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0
    )
    
    return DNSMessage(
        header=header,
        questions=[question],
        answers=[],
        authority=[],
        additional=[]
    )


class TestErrorResilience:
    """
    Property-based tests for network error resilience
    
    Feature: recursive-dns-server, Property 10: Error Resilience
    Validates: Requirements 6.2
    """
    
    @given(valid_ip_address_strategy(), dns_query_strategy())
    @settings(max_examples=100)
    def test_network_client_handles_timeout_gracefully(self, nameserver_ip, query):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any network error (timeout), the network client should handle it gracefully
        and return None without crashing
        Validates: Requirements 6.2
        """
        client = NetworkClient(timeout=1, max_retries=2)
        
        # Mock socket to simulate timeout
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.side_effect = socket.timeout("Timeout")
            
            # Should handle timeout gracefully
            result = client.query_udp(nameserver_ip, query)
            
            # Should return None on timeout
            assert result is None
            
            # Should have attempted retries
            assert mock_socket.sendto.call_count == 2  # max_retries
    
    @given(valid_ip_address_strategy(), dns_query_strategy())
    @settings(max_examples=100)
    def test_network_client_handles_socket_error_gracefully(self, nameserver_ip, query):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any network error (socket error), the network client should handle it gracefully
        and return None without crashing
        Validates: Requirements 6.2
        """
        client = NetworkClient(timeout=1, max_retries=2)
        
        # Mock socket to simulate socket error
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.sendto.side_effect = socket.error("Network unreachable")
            
            # Should handle socket error gracefully
            result = client.query_udp(nameserver_ip, query)
            
            # Should return None on error
            assert result is None
    
    @given(valid_ip_address_strategy(), dns_query_strategy())
    @settings(max_examples=100)
    def test_network_client_tcp_handles_connection_error_gracefully(self, nameserver_ip, query):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any TCP connection error, the network client should handle it gracefully
        and return None without crashing
        Validates: Requirements 6.2
        """
        client = NetworkClient(timeout=1, max_retries=2)
        
        # Mock socket to simulate connection error
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = socket.error("Connection refused")
            
            # Should handle connection error gracefully
            result = client.query_tcp(nameserver_ip, query)
            
            # Should return None on error
            assert result is None
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_continues_after_network_error(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any network error during DNS resolution, the resolver should continue
        serving other requests without interruption
        Validates: Requirements 6.2
        """
        cache = DNSCache()
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        # Track query attempts
        query_attempts = []
        
        def mock_query_udp(ns_ip, query):
            query_attempts.append(ns_ip)
            # First query fails with network error
            if len(query_attempts) == 1:
                return None  # Simulate network error
            # Second query succeeds
            else:
                answer_record = DNSRecord(
                    name=question.name,
                    rtype=question.qtype,
                    rclass=question.qclass,
                    ttl=300,
                    data=b'\x01\x02\x03\x04'
                )
                return DNSMessage(
                    header=DNSHeader(id=query.header.id, flags=0x8000, qdcount=1, ancount=1, nscount=0, arcount=0),
                    questions=[question],
                    answers=[answer_record],
                    authority=[],
                    additional=[]
                )
        
        with patch.object(resolver.network_client, 'query_udp', side_effect=mock_query_udp):
            # First resolution attempt (will encounter error but continue)
            result1 = resolver.resolve(question)
            
            # Should have tried multiple nameservers after first failure
            assert len(query_attempts) >= 1
            
            # Reset for second query
            query_attempts.clear()
            
            # Second resolution attempt (should work independently)
            result2 = resolver.resolve(question)
            
            # Should have successfully resolved second query
            # (either from cache or by querying again)
            assert result2 is not None
    
    @given(valid_ip_address_strategy(), dns_query_strategy())
    @settings(max_examples=100)
    def test_network_client_handles_malformed_response_gracefully(self, nameserver_ip, query):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any malformed response from nameserver, the network client should handle it
        gracefully and return None without crashing
        Validates: Requirements 6.2
        """
        client = NetworkClient(timeout=1, max_retries=1)
        
        # Mock socket to return malformed data
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            # Return truncated/malformed DNS message
            mock_socket.recvfrom.return_value = (b'\x00\x01\x02', ('127.0.0.1', 53))
            
            # Should handle malformed response gracefully
            result = client.query_udp(nameserver_ip, query)
            
            # Should return None on parse error
            assert result is None
    
    @given(valid_ip_address_strategy(), dns_query_strategy())
    @settings(max_examples=100)
    def test_network_client_tcp_handles_incomplete_response_gracefully(self, nameserver_ip, query):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any incomplete TCP response, the network client should handle it gracefully
        and return None without crashing
        Validates: Requirements 6.2
        """
        client = NetworkClient(timeout=1, max_retries=1)
        
        # Mock socket to return incomplete data
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            # Return length prefix but then connection closes
            mock_socket.recv.side_effect = [b'\x00\x10', b'']  # Length says 16 bytes, but no data
            
            # Should handle incomplete response gracefully
            result = client.query_tcp(nameserver_ip, query)
            
            # Should return None on incomplete response
            assert result is None
    
    @given(valid_ip_address_strategy(), dns_query_strategy())
    @settings(max_examples=100)
    def test_network_client_retries_on_transient_errors(self, nameserver_ip, query):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any transient network error, the network client should retry the query
        up to max_retries times
        Validates: Requirements 6.2
        """
        client = NetworkClient(timeout=1, max_retries=3)
        
        # Track retry attempts
        attempt_count = []
        
        def mock_sendto(*args, **kwargs):
            attempt_count.append(1)
            raise socket.timeout("Timeout")
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.sendto.side_effect = mock_sendto
            
            # Should retry on transient errors
            result = client.query_udp(nameserver_ip, query)
            
            # Should have attempted max_retries times
            assert len(attempt_count) == 3
            
            # Should return None after exhausting retries
            assert result is None
    
    @given(valid_ip_address_strategy(), dns_query_strategy())
    @settings(max_examples=100)
    def test_network_client_verifies_response_id(self, nameserver_ip, query):
        """
        Feature: recursive-dns-server, Property 10: Error Resilience
        For any response with mismatched ID, the network client should reject it
        to prevent accepting responses to different queries
        Validates: Requirements 6.2
        """
        client = NetworkClient(timeout=1, max_retries=1)
        
        # Create response with wrong ID (wrap around if at max value)
        wrong_id = (query.header.id + 1) % 65536
        # Ensure it's actually different from the query ID
        if wrong_id == query.header.id:
            wrong_id = (query.header.id + 2) % 65536
        
        wrong_response = DNSMessage(
            header=DNSHeader(
                id=wrong_id,  # Wrong ID
                flags=0x8000,
                qdcount=1,
                ancount=0,
                nscount=0,
                arcount=0
            ),
            questions=query.questions,
            answers=[],
            authority=[],
            additional=[]
        )
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recvfrom.return_value = (wrong_response.to_bytes(), ('127.0.0.1', 53))
            
            # Should reject response with wrong ID
            result = client.query_udp(nameserver_ip, query)
            
            # Should return None (or retry) when ID doesn't match
            # The implementation logs a warning and continues, which may return None
            # after retries are exhausted
            assert result is None
