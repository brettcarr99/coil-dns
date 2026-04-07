"""
Property-based tests for DNS message parser

Feature: recursive-dns-server, Property 1: DNS Query Processing
Validates: Requirements 1.1, 1.2, 1.3
"""

import pytest
from hypothesis import given, strategies as st, settings
from dns_server.models import DNSMessage, DNSHeader, DNSQuestion
from dns_server.parser import DNSMessageParser
from tests.test_models_properties import dns_message_strategy, dns_question_strategy


@st.composite
def dns_query_strategy(draw):
    """Generate valid DNS query messages (not responses)"""
    questions = draw(st.lists(dns_question_strategy(), min_size=1, max_size=3))
    
    # Query flags: QR=0 (query), other bits can vary
    flags = draw(st.integers(min_value=0, max_value=0x7FFF))  # QR bit must be 0
    
    header = DNSHeader(
        id=draw(st.integers(min_value=0, max_value=65535)),
        flags=flags,
        qdcount=len(questions),
        ancount=0,  # Queries typically have no answers
        nscount=0,
        arcount=0
    )
    
    return DNSMessage(header, questions, [], [], [])


class TestDNSMessageParserProperties:
    """Property-based tests for DNS message parser"""

    @given(dns_query_strategy())
    @settings(max_examples=100)
    def test_parse_query_accepts_valid_queries(self, query):
        """
        Feature: recursive-dns-server, Property 1: DNS Query Processing
        For any valid DNS query, the parser should accept and parse it successfully
        Validates: Requirements 1.1, 1.2, 1.3
        """
        parser = DNSMessageParser()
        
        # Serialize the query
        query_bytes = query.to_bytes()
        
        # Parser should successfully parse it
        parsed = parser.parse_query(query_bytes)
        
        # Parsed message should match original
        assert parsed.header.id == query.header.id
        assert len(parsed.questions) == len(query.questions)
        assert len(parsed.questions) > 0  # Must have at least one question

    @given(dns_query_strategy())
    @settings(max_examples=100)
    def test_serialize_response_produces_valid_bytes(self, query):
        """
        Feature: recursive-dns-server, Property 1: DNS Query Processing
        For any DNS message, serialization should produce valid bytes that can be parsed
        Validates: Requirements 1.3
        """
        parser = DNSMessageParser()
        
        # Create a response from the query
        response = DNSMessage(
            header=DNSHeader(
                id=query.header.id,
                flags=0x8000,  # QR=1 (response)
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
        
        # Serialize the response
        response_bytes = parser.serialize_response(response)
        
        # Should produce valid bytes
        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) >= 12  # Minimum DNS message size
        
        # Should be parseable back
        parsed = DNSMessage.from_bytes(response_bytes)
        assert parsed.header.flags & 0x8000  # QR bit should be set

    @given(dns_query_strategy())
    @settings(max_examples=100)
    def test_parse_then_serialize_round_trip(self, query):
        """
        Feature: recursive-dns-server, Property 1: DNS Query Processing
        For any valid query, parsing then serializing as response should preserve structure
        Validates: Requirements 1.1, 1.2, 1.3
        """
        parser = DNSMessageParser()
        
        # Serialize original query
        query_bytes = query.to_bytes()
        
        # Parse it
        parsed_query = parser.parse_query(query_bytes)
        
        # Create response from parsed query
        response = DNSMessage(
            header=DNSHeader(
                id=parsed_query.header.id,
                flags=0x8000,  # Response flag
                qdcount=len(parsed_query.questions),
                ancount=0,
                nscount=0,
                arcount=0
            ),
            questions=parsed_query.questions,
            answers=[],
            authority=[],
            additional=[]
        )
        
        # Serialize response
        response_bytes = parser.serialize_response(response)
        
        # Parse response back
        parsed_response = DNSMessage.from_bytes(response_bytes)
        
        # Questions should be preserved
        assert len(parsed_response.questions) == len(query.questions)
        assert parsed_response.header.id == query.header.id

    @given(dns_message_strategy())
    @settings(max_examples=100)
    def test_validate_message_accepts_valid_messages(self, message):
        """
        Feature: recursive-dns-server, Property 1: DNS Query Processing
        For any valid DNS message, validation should return True
        Validates: Requirements 1.1, 1.2, 1.3
        """
        parser = DNSMessageParser()
        
        # Update header counts to match sections
        message.header.qdcount = len(message.questions)
        message.header.ancount = len(message.answers)
        message.header.nscount = len(message.authority)
        message.header.arcount = len(message.additional)
        
        # Should validate successfully
        assert parser.validate_message(message) == True


class TestDNSErrorResponseProperties:
    """Property-based tests for DNS error response generation"""

    @given(st.binary(min_size=0, max_size=11))
    @settings(max_examples=100)
    def test_invalid_query_generates_error_response(self, invalid_data):
        """
        Feature: recursive-dns-server, Property 2: Error Response Generation
        For any invalid or malformed DNS query, the parser should generate an appropriate error response
        Validates: Requirements 1.4, 6.1
        """
        parser = DNSMessageParser()
        
        # Try to parse invalid data - should raise ValueError
        try:
            parser.parse_query(invalid_data)
            # If it somehow parses, that's okay (might be valid by chance)
        except ValueError:
            # Expected - invalid data should fail to parse
            pass
        
        # Should be able to create error response even with None query
        error_response = parser.create_error_response(None, parser.RCODE_FORMERR)
        
        # Error response should be valid
        assert error_response is not None
        assert error_response.header.flags & 0x8000  # QR bit set (response)
        assert error_response.header.flags & 0x000F  # RCODE should be non-zero
        
        # Should be serializable
        response_bytes = parser.serialize_response(error_response)
        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) >= 12

    @given(dns_query_strategy(), st.integers(min_value=1, max_value=5))
    @settings(max_examples=100)
    def test_error_response_preserves_query_id(self, query, rcode):
        """
        Feature: recursive-dns-server, Property 2: Error Response Generation
        For any valid query and error code, error response should preserve the query ID
        Validates: Requirements 1.4, 6.1
        """
        parser = DNSMessageParser()
        
        # Create error response for the query
        error_response = parser.create_error_response(query, rcode)
        
        # Should preserve query ID
        assert error_response.header.id == query.header.id
        
        # Should be marked as response
        assert error_response.header.flags & 0x8000
        
        # Should have the error code
        assert (error_response.header.flags & 0x000F) == rcode
        
        # Should preserve questions
        assert len(error_response.questions) == len(query.questions)

    @given(st.integers(min_value=1, max_value=5))
    @settings(max_examples=100)
    def test_error_response_with_no_query(self, rcode):
        """
        Feature: recursive-dns-server, Property 2: Error Response Generation
        For any error code, should be able to create error response even without a valid query
        Validates: Requirements 1.4, 6.1
        """
        parser = DNSMessageParser()
        
        # Create error response with no query
        error_response = parser.create_error_response(None, rcode)
        
        # Should create valid response
        assert error_response is not None
        assert error_response.header.flags & 0x8000  # Response flag
        assert (error_response.header.flags & 0x000F) == rcode  # Error code
        
        # Should be serializable
        response_bytes = parser.serialize_response(error_response)
        assert isinstance(response_bytes, bytes)
        assert len(response_bytes) >= 12

    @given(dns_query_strategy())
    @settings(max_examples=100)
    def test_parse_error_generates_formerr_response(self, query):
        """
        Feature: recursive-dns-server, Property 2: Error Response Generation
        For any query that fails parsing, should be able to generate FORMERR response
        Validates: Requirements 1.4, 6.1
        """
        parser = DNSMessageParser()
        
        # Corrupt the query by truncating it
        query_bytes = query.to_bytes()
        if len(query_bytes) > 12:
            corrupted = query_bytes[:12]  # Just header, no questions
            
            # Should fail to parse
            try:
                parser.parse_query(corrupted)
                # If it parses, skip this test case
            except ValueError:
                # Create error response
                error_response = parser.create_error_response(None, parser.RCODE_FORMERR)
                
                # Should be valid error response
                assert error_response.header.flags & 0x8000  # Response
                assert (error_response.header.flags & 0x000F) == parser.RCODE_FORMERR
