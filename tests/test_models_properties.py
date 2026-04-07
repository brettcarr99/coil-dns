"""
Property-based tests for DNS message data models

Feature: recursive-dns-server, Property 1: DNS message serialization round-trip
Validates: Requirements 1.3
"""

import pytest
from hypothesis import given, strategies as st, assume
from dns_server.models import DNSHeader, DNSQuestion, DNSRecord, DNSMessage


# Strategies for generating test data
@st.composite
def dns_header_strategy(draw):
    """Generate valid DNS headers"""
    return DNSHeader(
        id=draw(st.integers(min_value=0, max_value=65535)),
        flags=draw(st.integers(min_value=0, max_value=65535)),
        qdcount=draw(st.integers(min_value=0, max_value=65535)),
        ancount=draw(st.integers(min_value=0, max_value=65535)),
        nscount=draw(st.integers(min_value=0, max_value=65535)),
        arcount=draw(st.integers(min_value=0, max_value=65535))
    )


@st.composite
def dns_name_strategy(draw):
    """Generate valid DNS names (ASCII only)"""
    # Generate simple domain names with ASCII characters only
    labels = draw(st.lists(
        st.text(alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                min_size=1, max_size=10),
        min_size=1, max_size=4
    ))
    
    # Ensure each label is valid (no empty, not too long)
    valid_labels = []
    for label in labels:
        if label and len(label) <= 63:
            valid_labels.append(label)
    
    assume(len(valid_labels) > 0)
    return '.'.join(valid_labels) + '.'


@st.composite
def dns_question_strategy(draw):
    """Generate valid DNS questions"""
    return DNSQuestion(
        name=draw(dns_name_strategy()),
        qtype=draw(st.integers(min_value=1, max_value=65535)),
        qclass=draw(st.integers(min_value=1, max_value=65535))
    )


@st.composite
def dns_record_strategy(draw):
    """Generate valid DNS records"""
    return DNSRecord(
        name=draw(dns_name_strategy()),
        rtype=draw(st.integers(min_value=1, max_value=65535)),
        rclass=draw(st.integers(min_value=1, max_value=65535)),
        ttl=draw(st.integers(min_value=0, max_value=2147483647)),
        data=draw(st.binary(min_size=0, max_size=100))
    )


@st.composite
def dns_message_strategy(draw):
    """Generate valid DNS messages"""
    questions = draw(st.lists(dns_question_strategy(), min_size=0, max_size=3))
    answers = draw(st.lists(dns_record_strategy(), min_size=0, max_size=3))
    authority = draw(st.lists(dns_record_strategy(), min_size=0, max_size=3))
    additional = draw(st.lists(dns_record_strategy(), min_size=0, max_size=3))
    
    header = DNSHeader(
        id=draw(st.integers(min_value=0, max_value=65535)),
        flags=draw(st.integers(min_value=0, max_value=65535)),
        qdcount=len(questions),
        ancount=len(answers),
        nscount=len(authority),
        arcount=len(additional)
    )
    
    return DNSMessage(header, questions, answers, authority, additional)


class TestDNSMessageProperties:
    """Property-based tests for DNS message serialization"""

    @given(dns_header_strategy())
    def test_dns_header_round_trip(self, header):
        """
        Feature: recursive-dns-server, Property 1: DNS message serialization round-trip
        Test that DNS headers can be serialized and deserialized without loss
        """
        serialized = header.to_bytes()
        deserialized = DNSHeader.from_bytes(serialized)
        assert header == deserialized

    @given(dns_question_strategy())
    def test_dns_question_round_trip(self, question):
        """
        Feature: recursive-dns-server, Property 1: DNS message serialization round-trip
        Test that DNS questions can be serialized and deserialized without loss
        """
        serialized = question.to_bytes()
        deserialized, offset = DNSQuestion.from_bytes(serialized, 0)
        assert question == deserialized
        assert offset == len(serialized)

    @given(dns_record_strategy())
    def test_dns_record_round_trip(self, record):
        """
        Feature: recursive-dns-server, Property 1: DNS message serialization round-trip
        Test that DNS records can be serialized and deserialized without loss
        """
        serialized = record.to_bytes()
        deserialized, offset = DNSRecord.from_bytes(serialized, 0)
        assert record == deserialized
        assert offset == len(serialized)

    @given(dns_message_strategy())
    def test_dns_message_round_trip(self, message):
        """
        Feature: recursive-dns-server, Property 1: DNS message serialization round-trip
        Test that complete DNS messages can be serialized and deserialized without loss
        Validates: Requirements 1.3
        """
        serialized = message.to_bytes()
        deserialized = DNSMessage.from_bytes(serialized)
        assert message == deserialized