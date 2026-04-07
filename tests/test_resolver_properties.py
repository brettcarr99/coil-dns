"""
Property-based tests for DNS recursive resolver

Feature: recursive-dns-server
Tests Properties 3 and 4 related to recursive resolution
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from unittest.mock import Mock, patch, MagicMock
from dns_server.models import DNSMessage, DNSHeader, DNSQuestion, DNSRecord
from dns_server.resolver import RecursiveResolver, TYPE_A, TYPE_NS, CLASS_IN, RCODE_NOERROR, RCODE_SERVFAIL
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
    # Generate domain name
    num_labels = draw(st.integers(min_value=1, max_value=4))
    labels = [draw(st.text(alphabet=st.characters(whitelist_categories=('Ll', 'Nd')), min_size=1, max_size=10)) 
              for _ in range(num_labels)]
    domain = '.'.join(labels) + '.'
    
    qtype = draw(st.sampled_from([TYPE_A, TYPE_NS]))
    qclass = CLASS_IN
    
    return DNSQuestion(name=domain, qtype=qtype, qclass=qclass)


class TestRecursiveResolutionInitiation:
    """
    Property-based tests for recursive resolution initiation
    
    Feature: recursive-dns-server, Property 3: Recursive Resolution Initiation
    Validates: Requirements 2.1, 3.2
    """
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_queries_root_servers_for_cache_miss(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 3: Recursive Resolution Initiation
        For any DNS query not found in cache, the server should initiate recursive 
        resolution by first querying the root servers specified in the root hints file
        Validates: Requirements 2.1, 3.2
        """
        # Create cache and resolver
        cache = DNSCache()
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        # Track which nameservers were queried
        queried_servers = []
        
        def mock_query_nameserver(ns_ip, q):
            queried_servers.append(ns_ip)
            # Return SERVFAIL to stop recursion
            return resolver._create_error_response(q, RCODE_SERVFAIL)
        
        # Patch the query method
        with patch.object(resolver, '_query_nameserver', side_effect=mock_query_nameserver):
            # Resolve the question
            result = resolver.resolve(question)
            
            # Should have queried at least one root server
            assert len(queried_servers) > 0
            
            # All queried servers should be from root hints
            for server in queried_servers:
                assert server in root_hints
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_uses_cache_when_available(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 3: Recursive Resolution Initiation
        For any DNS query found in cache, the resolver should return cached result
        without querying root servers
        Validates: Requirements 2.1
        """
        # Create cache with a record
        cache = DNSCache()
        cached_record = DNSRecord(
            name=question.name,
            rtype=question.qtype,
            rclass=question.qclass,
            ttl=300,
            data=b'\x01\x02\x03\x04'  # Dummy IP
        )
        cache_key = f"{question.name}:{question.qtype}:{question.qclass}"
        cache.put(cache_key, cached_record, 300)
        
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        # Track if any nameserver was queried
        query_called = []
        
        def mock_query_nameserver(ns_ip, q):
            query_called.append(True)
            return None
        
        with patch.object(resolver, '_query_nameserver', side_effect=mock_query_nameserver):
            # Resolve the question
            result = resolver.resolve(question)
            
            # Should NOT have queried any nameserver (used cache)
            assert len(query_called) == 0
            
            # Should have returned a response with the cached answer
            assert result is not None
            assert len(result.answers) > 0
    
    @given(dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_requires_non_empty_root_hints(self, question):
        """
        Feature: recursive-dns-server, Property 3: Recursive Resolution Initiation
        For any resolver initialization, root hints must be non-empty
        Validates: Requirements 3.2
        """
        cache = DNSCache()
        
        # Should raise ValueError with empty root hints
        with pytest.raises(ValueError, match="Root hints cannot be empty"):
            RecursiveResolver([], cache)
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_starts_with_root_servers(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 3: Recursive Resolution Initiation
        For any DNS query requiring recursion, resolution should start with root servers
        Validates: Requirements 2.1, 3.2
        """
        cache = DNSCache()
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        # Track the first server queried
        first_server_queried = []
        
        def mock_query_nameserver(ns_ip, q):
            if not first_server_queried:
                first_server_queried.append(ns_ip)
            return resolver._create_error_response(q, RCODE_SERVFAIL)
        
        with patch.object(resolver, '_query_nameserver', side_effect=mock_query_nameserver):
            resolver.resolve(question)
            
            # First server queried should be from root hints
            if first_server_queried:
                assert first_server_queried[0] in root_hints


class TestDNSHierarchyTraversal:
    """
    Property-based tests for DNS hierarchy traversal
    
    Feature: recursive-dns-server, Property 4: DNS Hierarchy Traversal
    Validates: Requirements 2.2, 2.3, 2.4
    """
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_follows_referrals(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 4: DNS Hierarchy Traversal
        For any DNS query requiring recursion, the server should follow referrals 
        through each level of the DNS hierarchy until reaching an authoritative answer
        Validates: Requirements 2.2, 2.3, 2.4
        """
        cache = DNSCache()
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        # Track query sequence
        query_sequence = []
        
        def mock_query_nameserver(ns_ip, q):
            query_sequence.append(ns_ip)
            
            # First query (root) returns referral
            if len(query_sequence) == 1:
                # Create referral response with NS record and glue
                ns_record = DNSRecord(
                    name=question.name,
                    rtype=TYPE_NS,
                    rclass=CLASS_IN,
                    ttl=3600,
                    data=b'\x03ns1\x07example\x03com\x00'  # ns1.example.com
                )
                
                # Glue record (A record for the NS)
                glue_record = DNSRecord(
                    name='ns1.example.com.',
                    rtype=TYPE_A,
                    rclass=CLASS_IN,
                    ttl=3600,
                    data=b'\xc0\xa8\x01\x01'  # 192.168.1.1
                )
                
                return DNSMessage(
                    header=DNSHeader(id=1, flags=0x8000, qdcount=1, ancount=0, nscount=1, arcount=1),
                    questions=[q],
                    answers=[],
                    authority=[ns_record],
                    additional=[glue_record]
                )
            
            # Second query returns answer
            else:
                answer_record = DNSRecord(
                    name=question.name,
                    rtype=question.qtype,
                    rclass=question.qclass,
                    ttl=300,
                    data=b'\x01\x02\x03\x04'
                )
                
                return DNSMessage(
                    header=DNSHeader(id=1, flags=0x8000, qdcount=1, ancount=1, nscount=0, arcount=0),
                    questions=[q],
                    answers=[answer_record],
                    authority=[],
                    additional=[]
                )
        
        with patch.object(resolver, '_query_nameserver', side_effect=mock_query_nameserver):
            result = resolver.resolve(question)
            
            # Should have queried multiple servers (followed referral)
            assert len(query_sequence) >= 2
            
            # First query should be to root server
            assert query_sequence[0] in root_hints
            
            # Should have gotten an answer
            assert result is not None
            assert len(result.answers) > 0
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_returns_authoritative_answer(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 4: DNS Hierarchy Traversal
        For any DNS query, when an authoritative answer is found, the resolver 
        should return the complete response to the client
        Validates: Requirements 2.4
        """
        cache = DNSCache()
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        # Create an authoritative answer
        answer_record = DNSRecord(
            name=question.name,
            rtype=question.qtype,
            rclass=question.qclass,
            ttl=300,
            data=b'\x01\x02\x03\x04'
        )
        
        authoritative_response = DNSMessage(
            header=DNSHeader(id=1, flags=0x8400, qdcount=1, ancount=1, nscount=0, arcount=0),  # AA bit set
            questions=[question],
            answers=[answer_record],
            authority=[],
            additional=[]
        )
        
        def mock_query_nameserver(ns_ip, q):
            return authoritative_response
        
        with patch.object(resolver, '_query_nameserver', side_effect=mock_query_nameserver):
            result = resolver.resolve(question)
            
            # Should return the authoritative answer
            assert result is not None
            assert len(result.answers) > 0
            assert result.answers[0].name == question.name
            assert result.answers[0].rtype == question.qtype
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_extracts_nameserver_info_from_referrals(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 4: DNS Hierarchy Traversal
        For any referral response, the resolver should extract nameserver information 
        and continue the query chain
        Validates: Requirements 2.3
        """
        cache = DNSCache()
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        # Create a referral response
        ns_record = DNSRecord(
            name=question.name,
            rtype=TYPE_NS,
            rclass=CLASS_IN,
            ttl=3600,
            data=b'\x03ns1\x07example\x03com\x00'
        )
        
        glue_record = DNSRecord(
            name='ns1.example.com.',
            rtype=TYPE_A,
            rclass=CLASS_IN,
            ttl=3600,
            data=b'\xc0\xa8\x01\x01'  # 192.168.1.1
        )
        
        referral_response = DNSMessage(
            header=DNSHeader(id=1, flags=0x8000, qdcount=1, ancount=0, nscount=1, arcount=1),
            questions=[question],
            answers=[],
            authority=[ns_record],
            additional=[glue_record]
        )
        
        # Test extraction
        extracted_ips = resolver._extract_nameserver_ips(referral_response)
        
        # Should extract the glue IP
        assert len(extracted_ips) > 0
        assert '192.168.1.1' in extracted_ips
    
    @given(root_hints_strategy(), dns_question_strategy())
    @settings(max_examples=100)
    def test_resolver_handles_servfail_gracefully(self, root_hints, question):
        """
        Feature: recursive-dns-server, Property 4: DNS Hierarchy Traversal
        For any DNS query where all nameservers fail, resolver should return SERVFAIL
        Validates: Requirements 2.2, 2.3, 2.4
        """
        cache = DNSCache()
        resolver = RecursiveResolver(root_hints, cache, timeout=1, max_retries=1)
        
        def mock_query_nameserver(ns_ip, q):
            # All queries fail
            return None
        
        with patch.object(resolver, '_query_nameserver', side_effect=mock_query_nameserver):
            result = resolver.resolve(question)
            
            # Should return SERVFAIL response
            assert result is not None
            rcode = result.header.flags & 0x000F
            assert rcode == RCODE_SERVFAIL
