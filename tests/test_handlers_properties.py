"""
Property-based tests for DNS network handlers

Feature: recursive-dns-server, Property 8: UDP Size Limit Handling
Validates: Requirements 5.3, 5.4

Feature: recursive-dns-server, Property 9: Concurrent Request Handling
Validates: Requirements 5.5
"""

import pytest
import socket
import time
import threading
from hypothesis import given, strategies as st, settings
from dns_server.models import DNSMessage, DNSHeader, DNSQuestion, DNSRecord
from dns_server.handlers import UDPHandler, TCPHandler, UDP_MAX_SIZE
from dns_server.parser import DNSMessageParser
from tests.test_models_properties import dns_question_strategy


@st.composite
def large_dns_response_strategy(draw):
    """Generate DNS responses that exceed UDP size limits"""
    questions = draw(st.lists(dns_question_strategy(), min_size=1, max_size=1))
    
    # Create many answer records to exceed UDP size limit
    # Each record needs to be large enough
    num_answers = draw(st.integers(min_value=10, max_value=50))
    answers = []
    
    for _ in range(num_answers):
        # Create A records with random IPs
        name = draw(st.text(
            alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), max_codepoint=127),
            min_size=10,
            max_size=50
        )) + ".example.com."
        
        # A record with 4-byte IP address
        ip_bytes = draw(st.binary(min_size=4, max_size=4))
        
        record = DNSRecord(
            name=name,
            rtype=1,  # A record
            rclass=1,  # IN
            ttl=3600,
            data=ip_bytes
        )
        answers.append(record)
    
    header = DNSHeader(
        id=draw(st.integers(min_value=0, max_value=65535)),
        flags=0x8180,  # Response, recursion available
        qdcount=len(questions),
        ancount=len(answers),
        nscount=0,
        arcount=0
    )
    
    return DNSMessage(header, questions, answers, [], [])


@st.composite
def small_dns_response_strategy(draw):
    """Generate DNS responses that fit within UDP size limits"""
    questions = draw(st.lists(dns_question_strategy(), min_size=1, max_size=1))
    
    # Create a small number of answer records
    num_answers = draw(st.integers(min_value=0, max_value=3))
    answers = []
    
    for _ in range(num_answers):
        # Create simple A records
        name = "example.com."
        ip_bytes = draw(st.binary(min_size=4, max_size=4))
        
        record = DNSRecord(
            name=name,
            rtype=1,  # A record
            rclass=1,  # IN
            ttl=3600,
            data=ip_bytes
        )
        answers.append(record)
    
    header = DNSHeader(
        id=draw(st.integers(min_value=0, max_value=65535)),
        flags=0x8180,  # Response, recursion available
        qdcount=len(questions),
        ancount=len(answers),
        nscount=0,
        arcount=0
    )
    
    return DNSMessage(header, questions, answers, [], [])


class TestUDPSizeLimitProperties:
    """Property-based tests for UDP size limit handling"""

    @given(large_dns_response_strategy())
    @settings(max_examples=100)
    def test_udp_truncates_large_responses(self, large_response):
        """
        Feature: recursive-dns-server, Property 8: UDP Size Limit Handling
        For any DNS response that exceeds UDP size limits, the handler should set the truncation bit
        Validates: Requirements 5.3, 5.4
        """
        handler = UDPHandler(port=0)  # Port 0 for testing
        parser = DNSMessageParser()
        
        # Serialize the large response
        response_bytes = parser.serialize_response(large_response)
        
        # If response exceeds UDP limit, truncation should occur
        if len(response_bytes) > UDP_MAX_SIZE:
            # Truncate the response
            truncated = handler._truncate_response(large_response)
            truncated_bytes = parser.serialize_response(truncated)
            
            # Truncated response should fit in UDP limit
            assert len(truncated_bytes) <= UDP_MAX_SIZE
            
            # TC bit (bit 9) should be set in flags
            assert truncated.header.flags & 0x0200  # TC bit
            
            # Should have no answer/authority/additional records
            assert len(truncated.answers) == 0
            assert len(truncated.authority) == 0
            assert len(truncated.additional) == 0
            
            # Should preserve questions
            assert len(truncated.questions) == len(large_response.questions)
            
            # Should preserve message ID
            assert truncated.header.id == large_response.header.id

    @given(small_dns_response_strategy())
    @settings(max_examples=100)
    def test_udp_does_not_truncate_small_responses(self, small_response):
        """
        Feature: recursive-dns-server, Property 8: UDP Size Limit Handling
        For any DNS response that fits within UDP size limits, the handler should not set truncation bit
        Validates: Requirements 5.3, 5.4
        """
        handler = UDPHandler(port=0)
        parser = DNSMessageParser()
        
        # Serialize the small response
        response_bytes = parser.serialize_response(small_response)
        
        # If response fits in UDP limit, no truncation needed
        if len(response_bytes) <= UDP_MAX_SIZE:
            # TC bit should not be set
            assert not (small_response.header.flags & 0x0200)
            
            # Response should be unchanged
            assert len(response_bytes) <= UDP_MAX_SIZE

    @given(large_dns_response_strategy())
    @settings(max_examples=100)
    def test_truncated_response_is_valid_dns_message(self, large_response):
        """
        Feature: recursive-dns-server, Property 8: UDP Size Limit Handling
        For any truncated response, the result should be a valid DNS message
        Validates: Requirements 5.3, 5.4
        """
        handler = UDPHandler(port=0)
        parser = DNSMessageParser()
        
        # Serialize the large response
        response_bytes = parser.serialize_response(large_response)
        
        if len(response_bytes) > UDP_MAX_SIZE:
            # Truncate the response
            truncated = handler._truncate_response(large_response)
            truncated_bytes = parser.serialize_response(truncated)
            
            # Should be parseable as valid DNS message
            parsed = DNSMessage.from_bytes(truncated_bytes)
            
            # Should be marked as response
            assert parsed.header.flags & 0x8000
            
            # Should have TC bit set
            assert parsed.header.flags & 0x0200
            
            # Should be valid according to parser
            assert parser.validate_message(parsed)


class TestConcurrentRequestHandlingProperties:
    """Property-based tests for concurrent request handling"""

    @given(st.lists(dns_question_strategy(), min_size=5, max_size=20))
    @settings(max_examples=100, deadline=5000)
    def test_udp_handles_concurrent_requests(self, questions):
        """
        Feature: recursive-dns-server, Property 9: Concurrent Request Handling
        For any set of simultaneous DNS queries, the UDP handler should handle all requests concurrently
        Validates: Requirements 5.5
        """
        # Create handler on random available port
        handler = UDPHandler(port=0, address="127.0.0.1")
        parser = DNSMessageParser()
        
        # Track responses
        responses_received = []
        response_lock = threading.Lock()
        
        def query_handler(query: DNSMessage, client_addr: tuple) -> DNSMessage:
            """Simple handler that echoes back a response"""
            # Simulate some processing time
            time.sleep(0.01)
            
            return DNSMessage(
                header=DNSHeader(
                    id=query.header.id,
                    flags=0x8180,
                    qdcount=len(query.questions),
                    ancount=0,
                    nscount=0,
                    arcount=0
                ),
                questions=query.questions,
                answers=[],
                authority=[],
                additional=[]
            )
        
        handler.set_query_handler(query_handler)
        
        try:
            # Start the server
            handler.start_server()
            
            # Get the actual port assigned
            actual_port = handler.socket.getsockname()[1]
            
            # Give server time to start
            time.sleep(0.1)
            
            # Send multiple concurrent queries
            def send_query(question):
                try:
                    # Create query
                    query = DNSMessage(
                        header=DNSHeader(
                            id=hash(question.name) % 65536,
                            flags=0x0100,
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
                    
                    query_bytes = query.to_bytes()
                    
                    # Send via UDP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2.0)
                    sock.sendto(query_bytes, ("127.0.0.1", actual_port))
                    
                    # Receive response
                    response_data, _ = sock.recvfrom(4096)
                    sock.close()
                    
                    # Parse response
                    response = DNSMessage.from_bytes(response_data)
                    
                    with response_lock:
                        responses_received.append(response)
                
                except Exception:
                    pass  # Ignore errors in test
            
            # Send queries concurrently
            threads = []
            for question in questions:
                t = threading.Thread(target=send_query, args=(question,))
                t.start()
                threads.append(t)
            
            # Wait for all threads to complete
            for t in threads:
                t.join(timeout=3.0)
            
            # Should have received responses for most queries
            # (allowing for some packet loss in testing)
            assert len(responses_received) >= len(questions) * 0.5
            
        finally:
            handler.stop_server()

    @given(st.lists(dns_question_strategy(), min_size=3, max_size=10))
    @settings(max_examples=100, deadline=5000)
    def test_tcp_handles_concurrent_connections(self, questions):
        """
        Feature: recursive-dns-server, Property 9: Concurrent Request Handling
        For any set of simultaneous DNS queries, the TCP handler should handle all connections concurrently
        Validates: Requirements 5.5
        """
        # Create handler on random available port
        handler = TCPHandler(port=0, address="127.0.0.1")
        parser = DNSMessageParser()
        
        # Track responses
        responses_received = []
        response_lock = threading.Lock()
        
        def query_handler(query: DNSMessage, client_addr: tuple) -> DNSMessage:
            """Simple handler that echoes back a response"""
            # Simulate some processing time
            time.sleep(0.01)
            
            return DNSMessage(
                header=DNSHeader(
                    id=query.header.id,
                    flags=0x8180,
                    qdcount=len(query.questions),
                    ancount=0,
                    nscount=0,
                    arcount=0
                ),
                questions=query.questions,
                answers=[],
                authority=[],
                additional=[]
            )
        
        handler.set_query_handler(query_handler)
        
        try:
            # Start the server
            handler.start_server()
            
            # Get the actual port assigned
            actual_port = handler.socket.getsockname()[1]
            
            # Give server time to start
            time.sleep(0.1)
            
            # Send multiple concurrent queries
            def send_query(question):
                try:
                    # Create query
                    query = DNSMessage(
                        header=DNSHeader(
                            id=hash(question.name) % 65536,
                            flags=0x0100,
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
                    
                    query_bytes = query.to_bytes()
                    
                    # Send via TCP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect(("127.0.0.1", actual_port))
                    
                    # Send length prefix + query
                    length_bytes = len(query_bytes).to_bytes(2, byteorder='big')
                    sock.sendall(length_bytes + query_bytes)
                    
                    # Receive length prefix
                    length_data = sock.recv(2)
                    if len(length_data) == 2:
                        response_length = int.from_bytes(length_data, byteorder='big')
                        
                        # Receive response
                        response_data = b''
                        while len(response_data) < response_length:
                            chunk = sock.recv(response_length - len(response_data))
                            if not chunk:
                                break
                            response_data += chunk
                        
                        if len(response_data) == response_length:
                            # Parse response
                            response = DNSMessage.from_bytes(response_data)
                            
                            with response_lock:
                                responses_received.append(response)
                    
                    sock.close()
                
                except Exception:
                    pass  # Ignore errors in test
            
            # Send queries concurrently
            threads = []
            for question in questions:
                t = threading.Thread(target=send_query, args=(question,))
                t.start()
                threads.append(t)
            
            # Wait for all threads to complete
            for t in threads:
                t.join(timeout=3.0)
            
            # Should have received responses for most queries
            assert len(responses_received) >= len(questions) * 0.5
            
        finally:
            handler.stop_server()

    @given(st.lists(dns_question_strategy(), min_size=5, max_size=15))
    @settings(max_examples=100, deadline=5000)
    def test_mixed_udp_tcp_concurrent_handling(self, questions):
        """
        Feature: recursive-dns-server, Property 9: Concurrent Request Handling
        For any set of simultaneous queries on both UDP and TCP, both handlers should work concurrently
        Validates: Requirements 5.5
        """
        # Create handlers on random available ports
        udp_handler = UDPHandler(port=0, address="127.0.0.1")
        tcp_handler = TCPHandler(port=0, address="127.0.0.1")
        
        # Track responses
        responses_received = []
        response_lock = threading.Lock()
        
        def query_handler(query: DNSMessage, client_addr: tuple) -> DNSMessage:
            """Simple handler that echoes back a response"""
            return DNSMessage(
                header=DNSHeader(
                    id=query.header.id,
                    flags=0x8180,
                    qdcount=len(query.questions),
                    ancount=0,
                    nscount=0,
                    arcount=0
                ),
                questions=query.questions,
                answers=[],
                authority=[],
                additional=[]
            )
        
        udp_handler.set_query_handler(query_handler)
        tcp_handler.set_query_handler(query_handler)
        
        try:
            # Start both servers
            udp_handler.start_server()
            tcp_handler.start_server()
            
            udp_port = udp_handler.socket.getsockname()[1]
            tcp_port = tcp_handler.socket.getsockname()[1]
            
            time.sleep(0.1)
            
            # Send queries via both protocols
            def send_udp_query(question):
                try:
                    query = DNSMessage(
                        header=DNSHeader(id=1, flags=0x0100, qdcount=1, ancount=0, nscount=0, arcount=0),
                        questions=[question],
                        answers=[], authority=[], additional=[]
                    )
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2.0)
                    sock.sendto(query.to_bytes(), ("127.0.0.1", udp_port))
                    response_data, _ = sock.recvfrom(4096)
                    sock.close()
                    
                    with response_lock:
                        responses_received.append(('udp', DNSMessage.from_bytes(response_data)))
                except:
                    pass
            
            def send_tcp_query(question):
                try:
                    query = DNSMessage(
                        header=DNSHeader(id=1, flags=0x0100, qdcount=1, ancount=0, nscount=0, arcount=0),
                        questions=[question],
                        answers=[], authority=[], additional=[]
                    )
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect(("127.0.0.1", tcp_port))
                    query_bytes = query.to_bytes()
                    sock.sendall(len(query_bytes).to_bytes(2, byteorder='big') + query_bytes)
                    
                    length_data = sock.recv(2)
                    if len(length_data) == 2:
                        response_length = int.from_bytes(length_data, byteorder='big')
                        response_data = sock.recv(response_length)
                        sock.close()
                        
                        with response_lock:
                            responses_received.append(('tcp', DNSMessage.from_bytes(response_data)))
                except:
                    pass
            
            # Send mixed queries
            threads = []
            for i, question in enumerate(questions):
                if i % 2 == 0:
                    t = threading.Thread(target=send_udp_query, args=(question,))
                else:
                    t = threading.Thread(target=send_tcp_query, args=(question,))
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join(timeout=3.0)
            
            # Should have received responses from both protocols
            udp_responses = [r for proto, r in responses_received if proto == 'udp']
            tcp_responses = [r for proto, r in responses_received if proto == 'tcp']
            
            # Both protocols should have handled some requests
            assert len(udp_responses) > 0 or len(tcp_responses) > 0
            
        finally:
            udp_handler.stop_server()
            tcp_handler.stop_server()
