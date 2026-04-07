"""
Coil - DNS Message Parser

Parsing and serialization for DNS messages, with validation of incoming
queries and outgoing responses.
"""

import struct
import logging
from typing import Optional
from dns_server.models import DNSMessage, DNSHeader


# DNS Response Codes
RCODE_NOERROR = 0
RCODE_FORMERR = 1  # Format error
RCODE_SERVFAIL = 2  # Server failure
RCODE_NXDOMAIN = 3  # Non-existent domain


class DNSMessageParser:
    """Parser for DNS messages with validation"""
    
    # DNS Response Codes
    RCODE_NOERROR = 0
    RCODE_FORMERR = 1  # Format error
    RCODE_SERVFAIL = 2  # Server failure
    RCODE_NXDOMAIN = 3  # Non-existent domain
    
    def __init__(self):
        """Initialize DNS message parser with logging"""
        self.logger = logging.getLogger(__name__)

    def parse_query(self, data: bytes) -> DNSMessage:
        """
        Parse incoming DNS query from bytes.
        
        Args:
            data: Raw bytes of DNS query
            
        Returns:
            Parsed DNSMessage object
            
        Raises:
            ValueError: If the message is invalid or malformed
        """
        if not data:
            self.logger.warning("Received empty DNS query data")
            raise ValueError("Empty DNS query data")
        
        if len(data) < 12:
            self.logger.warning(f"DNS query too short: {len(data)} bytes (minimum 12 required)")
            raise ValueError("DNS query too short (minimum 12 bytes required)")
        
        try:
            message = DNSMessage.from_bytes(data)
            
            # Validate that it's a query (QR bit should be 0)
            if message.header.flags & 0x8000:
                self.logger.warning("Received response instead of query")
                raise ValueError("Message is a response, not a query")
            
            # Validate that there's at least one question
            if len(message.questions) == 0:
                self.logger.warning("DNS query contains no questions")
                raise ValueError("DNS query must contain at least one question")
            
            self.logger.debug(f"Successfully parsed DNS query with {len(message.questions)} question(s)")
            return message
            
        except (ValueError, struct.error, UnicodeDecodeError) as e:
            self.logger.error(f"Failed to parse DNS query: {str(e)}")
            raise ValueError(f"Failed to parse DNS query: {str(e)}")

    def serialize_response(self, response: DNSMessage) -> bytes:
        """
        Serialize DNS response to bytes for transmission.
        
        Args:
            response: DNSMessage object to serialize
            
        Returns:
            Serialized bytes ready for transmission
            
        Raises:
            ValueError: If the response is invalid
        """
        if not response:
            self.logger.error("Attempted to serialize None response")
            raise ValueError("Response message cannot be None")
        
        # Ensure QR bit is set (this is a response)
        response.header.flags |= 0x8000
        
        try:
            serialized = response.to_bytes()
            self.logger.debug(f"Serialized DNS response: {len(serialized)} bytes")
            return serialized
        except (ValueError, struct.error) as e:
            self.logger.error(f"Failed to serialize DNS response: {str(e)}")
            raise ValueError(f"Failed to serialize DNS response: {str(e)}")

    def validate_message(self, message: DNSMessage) -> bool:
        """
        Validate a DNS message structure.
        
        Args:
            message: DNSMessage to validate
            
        Returns:
            True if message is valid, False otherwise
        """
        if not message:
            self.logger.debug("Validation failed: message is None")
            return False
        
        try:
            # Check header exists
            if not message.header:
                self.logger.debug("Validation failed: missing header")
                return False
            
            # Check counts match actual sections
            if message.header.qdcount != len(message.questions):
                self.logger.debug(f"Validation failed: question count mismatch (header: {message.header.qdcount}, actual: {len(message.questions)})")
                return False
            if message.header.ancount != len(message.answers):
                self.logger.debug(f"Validation failed: answer count mismatch (header: {message.header.ancount}, actual: {len(message.answers)})")
                return False
            if message.header.nscount != len(message.authority):
                self.logger.debug(f"Validation failed: authority count mismatch (header: {message.header.nscount}, actual: {len(message.authority)})")
                return False
            if message.header.arcount != len(message.additional):
                self.logger.debug(f"Validation failed: additional count mismatch (header: {message.header.arcount}, actual: {len(message.additional)})")
                return False
            
            # Check that questions have valid names
            for question in message.questions:
                if not question.name:
                    self.logger.debug("Validation failed: question with empty name")
                    return False
            
            # Check that records have valid names
            for record in (message.answers + message.authority + message.additional):
                if not record.name:
                    self.logger.debug("Validation failed: record with empty name")
                    return False
            
            self.logger.debug("Message validation successful")
            return True
            
        except (AttributeError, TypeError) as e:
            self.logger.debug(f"Validation failed with exception: {e}")
            return False

    def create_error_response(self, query: Optional[DNSMessage], rcode: int) -> DNSMessage:
        """
        Create an error response for a query.
        
        Args:
            query: Original query message (can be None if query was unparseable)
            rcode: DNS response code (RCODE_FORMERR, RCODE_SERVFAIL, etc.)
            
        Returns:
            DNSMessage with error response
        """
        rcode_names = {
            self.RCODE_NOERROR: "NOERROR",
            self.RCODE_FORMERR: "FORMERR",
            self.RCODE_SERVFAIL: "SERVFAIL",
            self.RCODE_NXDOMAIN: "NXDOMAIN"
        }
        rcode_name = rcode_names.get(rcode, f"RCODE_{rcode}")
        
        # If we have a valid query, copy its ID and questions
        if query and query.header:
            self.logger.info(f"Creating error response {rcode_name} for query ID {query.header.id}")
            header = DNSHeader(
                id=query.header.id,
                flags=0x8000 | rcode,  # QR=1 (response), RCODE=rcode
                qdcount=len(query.questions),
                ancount=0,
                nscount=0,
                arcount=0
            )
            questions = query.questions
        else:
            # If query is invalid, create minimal error response
            self.logger.info(f"Creating error response {rcode_name} for unparseable query")
            header = DNSHeader(
                id=0,
                flags=0x8000 | rcode,  # QR=1 (response), RCODE=rcode
                qdcount=0,
                ancount=0,
                nscount=0,
                arcount=0
            )
            questions = []
        
        return DNSMessage(
            header=header,
            questions=questions,
            answers=[],
            authority=[],
            additional=[]
        )
