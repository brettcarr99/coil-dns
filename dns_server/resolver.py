"""
Coil - Recursive DNS Resolver

Core recursive resolution logic for Coil. Starts with root servers and
follows referrals down the DNS hierarchy until reaching authoritative answers.
"""

import random
import logging
from typing import List, Optional, Set
from dns_server.models import DNSMessage, DNSHeader, DNSQuestion, DNSRecord
from dns_server.cache import DNSCache
from dns_server.network_client import NetworkClient


# DNS Record Types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_AAAA = 28

# DNS Classes
CLASS_IN = 1

# DNS Response Codes
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
RCODE_SERVFAIL = 2


class RecursiveResolver:
    """
    Coil recursive DNS resolver.

    Queries root servers and follows referrals to resolve domain names.
    """
    
    def __init__(self, root_hints: List[str], cache: DNSCache, timeout: int = 5, max_retries: int = 3):
        """
        Initialize the recursive resolver.
        
        Args:
            root_hints: List of root server IP addresses
            cache: DNS cache instance for storing/retrieving records
            timeout: Query timeout in seconds
            max_retries: Maximum number of retry attempts per query
        """
        if not root_hints:
            raise ValueError("Root hints cannot be empty")
        
        self.root_servers = root_hints
        self.cache = cache
        self.timeout = timeout
        self.max_retries = max_retries
        self.network_client = NetworkClient(timeout=timeout, max_retries=max_retries)
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Recursive resolver initialized with {len(root_hints)} root servers")
    
    MAX_CNAME_DEPTH = 10

    def resolve(self, question: DNSQuestion) -> DNSMessage:
        """
        Resolve a DNS question using recursive resolution.

        Checks the cache first, then performs recursive resolution starting
        from root servers. Follows CNAME chains up to MAX_CNAME_DEPTH hops,
        detecting loops along the way.

        Args:
            question: DNS question to resolve

        Returns:
            DNSMessage containing the resolution result
        """
        self.logger.info(f"Resolving query: {question.name} (type {question.qtype})")

        # Check cache first
        cache_key = self._make_cache_key(question)
        cached_record = self.cache.get(cache_key)

        if cached_record:
            self.logger.debug(f"Cache hit for {question.name}")
            return self._create_response_from_cache(question, cached_record)

        self.logger.debug(f"Cache miss for {question.name}, starting recursive resolution")

        try:
            result = self._resolve_with_cname_following(question)

            if result and result.answers:
                self.logger.info(f"Successfully resolved {question.name} with {len(result.answers)} answer(s)")
                min_ttl = min((a.ttl for a in result.answers if a.ttl > 0), default=0)
                if min_ttl > 0:
                    self.cache.put(cache_key, result.answers, min_ttl)
            else:
                rcode = result.header.flags & 0x000F if result else RCODE_SERVFAIL
                rcode_names = {RCODE_NOERROR: "NOERROR", RCODE_NXDOMAIN: "NXDOMAIN", RCODE_SERVFAIL: "SERVFAIL"}
                self.logger.warning(f"Resolution failed for {question.name} with rcode {rcode_names.get(rcode, rcode)}")

            return result

        except Exception as e:
            self.logger.error(f"Exception during resolution of {question.name}: {e}")
            return self._create_error_response(question, RCODE_SERVFAIL)

    def _resolve_with_cname_following(self, question: DNSQuestion) -> DNSMessage:
        """
        Resolve a question and follow any CNAME chain in the response.

        Collects all intermediate CNAME records into the final answer section
        so the client sees the full chain. Detects loops and caps the chain
        at MAX_CNAME_DEPTH hops to prevent infinite resolution.

        Args:
            question: The original DNS question

        Returns:
            DNSMessage with the full answer (CNAME chain + final records)
        """
        current_question = question
        accumulated_answers: list = []
        seen_names: Set[str] = {question.name.lower()}

        for _ in range(self.MAX_CNAME_DEPTH):
            result = self._iterate_query(current_question, self.root_servers, set())

            if not result:
                return self._create_error_response(question, RCODE_SERVFAIL)

            # Separate CNAME records from non-CNAME records in the answer
            cname_records = [r for r in result.answers if r.rtype == TYPE_CNAME]
            other_records = [r for r in result.answers if r.rtype != TYPE_CNAME]

            accumulated_answers.extend(cname_records)

            if other_records:
                # Reached the end of the chain — attach final records and return
                accumulated_answers.extend(other_records)
                result.answers = accumulated_answers
                result.header.ancount = len(accumulated_answers)
                return result

            if not cname_records:
                # No answers at all (NXDOMAIN, SERVFAIL, etc.) — return as-is
                if accumulated_answers:
                    result.answers = accumulated_answers
                    result.header.ancount = len(accumulated_answers)
                return result

            # Decode the CNAME target from the last CNAME record's rdata
            try:
                cname_target, _ = DNSQuestion._decode_name(cname_records[-1].data, 0)
            except Exception as e:
                self.logger.warning(f"Failed to decode CNAME target: {e}")
                result.answers = accumulated_answers
                result.header.ancount = len(accumulated_answers)
                return result

            cname_target_lower = cname_target.lower()
            if cname_target_lower in seen_names:
                self.logger.warning(
                    f"CNAME loop detected: {current_question.name} -> {cname_target}"
                )
                return self._create_error_response(question, RCODE_SERVFAIL)

            seen_names.add(cname_target_lower)
            self.logger.debug(f"Following CNAME: {current_question.name} -> {cname_target}")
            current_question = DNSQuestion(
                name=cname_target,
                qtype=question.qtype,
                qclass=question.qclass
            )

        self.logger.warning(
            f"CNAME chain exceeded max depth ({self.MAX_CNAME_DEPTH}) for {question.name}"
        )
        return self._create_error_response(question, RCODE_SERVFAIL)
    
    def _iterate_query(self, question: DNSQuestion, nameservers: List[str], visited: Set[str], depth: int = 0) -> DNSMessage:
        """
        Iterate through DNS hierarchy by querying nameservers and following referrals.
        
        This implements the core recursive resolution algorithm:
        1. Query the provided nameservers
        2. If we get an answer, return it
        3. If we get a referral (NS records), extract nameserver IPs and recurse
        4. Continue until we get an authoritative answer or exhaust options
        
        Args:
            question: DNS question to resolve
            nameservers: List of nameserver IP addresses to query
            visited: Set of already-visited nameservers (to prevent loops)
            depth: Current recursion depth (to prevent infinite loops)
            
        Returns:
            DNSMessage with resolution result
        """
        MAX_DEPTH = 20
        if depth >= MAX_DEPTH:
            self.logger.warning(f"Max recursion depth ({MAX_DEPTH}) reached for {question.name}")
            return self._create_error_response(question, RCODE_SERVFAIL)

        self.logger.debug(f"Iterating query for {question.name} with {len(nameservers)} nameserver(s)")
        
        for ns_ip in nameservers:
            # Prevent infinite loops
            if ns_ip in visited:
                self.logger.debug(f"Skipping already-visited nameserver: {ns_ip}")
                continue
            
            visited.add(ns_ip)
            
            try:
                self.logger.debug(f"Querying nameserver {ns_ip} for {question.name}")
                
                # Query this nameserver
                response = self._query_nameserver(ns_ip, question)
                
                if not response:
                    self.logger.debug(f"No response from nameserver {ns_ip}")
                    continue
                
                # Check if we got an answer
                if response.answers:
                    self.logger.debug(f"Received {len(response.answers)} answer(s) from {ns_ip}")
                    return response
                
                # Check if we got a referral (authority section with NS records)
                if response.authority:
                    # Extract nameserver IPs from authority and additional sections
                    next_nameservers = self._extract_nameserver_ips(response)
                    
                    if next_nameservers:
                        self.logger.debug(f"Following referral to {len(next_nameservers)} nameserver(s)")
                        # Recurse with the new nameservers
                        result = self._iterate_query(question, next_nameservers, visited, depth + 1)
                        if result and result.answers:
                            return result
                
                # Check response code
                rcode = response.header.flags & 0x000F
                if rcode == RCODE_NXDOMAIN:
                    # Authoritative NXDOMAIN - domain doesn't exist
                    self.logger.info(f"Received authoritative NXDOMAIN for {question.name}")
                    return response
                
            except Exception as e:
                # Continue to next nameserver on error
                self.logger.warning(f"Error querying nameserver {ns_ip}: {e}")
                continue
        
        # Exhausted all nameservers without getting an answer
        self.logger.warning(f"Exhausted all nameservers for {question.name} without answer")
        return self._create_error_response(question, RCODE_SERVFAIL)
    
    def _query_nameserver(self, ns_ip: str, question: DNSQuestion) -> Optional[DNSMessage]:
        """
        Send a DNS query to a specific nameserver and get the response.
        
        Uses the NetworkClient to handle UDP queries with timeout and retry logic.
        
        Args:
            ns_ip: IP address of the nameserver
            question: DNS question to send
            
        Returns:
            DNSMessage response, or None if query failed
        """
        # Create query message
        query = self._create_query(question)
        
        # Use network client to send query via UDP
        response = self.network_client.query_udp(ns_ip, query)
        
        return response
    
    def _extract_nameserver_ips(self, response: DNSMessage) -> List[str]:
        """
        Extract nameserver IP addresses from a DNS response.
        
        Looks in the additional section for A records corresponding to
        NS records in the authority section. If no glue records are found
        (out-of-bailiwick nameservers), resolves the NS names separately.
        
        Args:
            response: DNS response message
            
        Returns:
            List of nameserver IP addresses
        """
        nameserver_ips = []
        
        # Get NS record names from authority section
        ns_names = set()
        for record in response.authority:
            if record.rtype == TYPE_NS:
                try:
                    ns_name, _ = DNSQuestion._decode_name(record.data, 0)
                    ns_names.add(ns_name)
                except:
                    pass
        
        # Look for A records in additional section matching NS names
        for record in response.additional:
            if record.rtype == TYPE_A and record.name in ns_names:
                if len(record.data) == 4:
                    ip = '.'.join(str(b) for b in record.data)
                    nameserver_ips.append(ip)
        
        # If no glue records found, resolve NS names ourselves
        if not nameserver_ips and ns_names:
            self.logger.debug(f"No glue records found, resolving {len(ns_names)} NS name(s)")
            for ns_name in ns_names:
                try:
                    ns_question = DNSQuestion(name=ns_name, qtype=TYPE_A, qclass=CLASS_IN)
                    
                    # Check cache first
                    cache_key = self._make_cache_key(ns_question)
                    cached = self.cache.get(cache_key)
                    if cached:
                        for rec in cached:
                            if rec.rtype == TYPE_A and len(rec.data) == 4:
                                ip = '.'.join(str(b) for b in rec.data)
                                nameserver_ips.append(ip)
                                self.logger.debug(f"Resolved NS {ns_name} from cache: {ip}")
                        if nameserver_ips:
                            continue
                    
                    # Resolve from root servers
                    ns_response = self._iterate_query(ns_question, self.root_servers, set())
                    if ns_response and ns_response.answers:
                        for answer in ns_response.answers:
                            if answer.rtype == TYPE_A and len(answer.data) == 4:
                                ip = '.'.join(str(b) for b in answer.data)
                                nameserver_ips.append(ip)
                                self.logger.debug(f"Resolved NS {ns_name}: {ip}")
                                # Cache it
                                if answer.ttl > 0:
                                    self.cache.put(cache_key, answer, answer.ttl)
                except Exception as e:
                    self.logger.debug(f"Failed to resolve NS {ns_name}: {e}")
                    continue
        
        return nameserver_ips
    
    def _create_query(self, question: DNSQuestion) -> DNSMessage:
        """
        Create a DNS query message for a question.
        
        Args:
            question: DNS question
            
        Returns:
            DNSMessage query
        """
        query_id = random.randint(0, 65535)
        
        header = DNSHeader(
            id=query_id,
            flags=0x0100,  # Standard query with recursion desired
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
    
    def _create_response_from_cache(self, question: DNSQuestion, records) -> DNSMessage:
        """
        Create a DNS response message from cached records.
        
        Args:
            question: Original DNS question
            records: Cached DNS record or list of records
            
        Returns:
            DNSMessage response
        """
        if isinstance(records, DNSRecord):
            records = [records]
        
        header = DNSHeader(
            id=0,  # Will be set by caller
            flags=0x8180,  # Response, recursion available
            qdcount=1,
            ancount=len(records),
            nscount=0,
            arcount=0
        )
        
        return DNSMessage(
            header=header,
            questions=[question],
            answers=records,
            authority=[],
            additional=[]
        )
    
    def _create_error_response(self, question: DNSQuestion, rcode: int) -> DNSMessage:
        """
        Create an error response message.
        
        Args:
            question: Original DNS question
            rcode: DNS response code
            
        Returns:
            DNSMessage error response
        """
        header = DNSHeader(
            id=0,  # Will be set by caller
            flags=0x8180 | rcode,  # Response with error code
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
    
    def _make_cache_key(self, question: DNSQuestion) -> str:
        """
        Create a cache key from a DNS question.
        
        Args:
            question: DNS question
            
        Returns:
            Cache key string
        """
        return f"{question.name}:{question.qtype}:{question.qclass}"
