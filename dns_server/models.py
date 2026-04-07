"""
Coil - DNS Message Data Models

Core data structures for DNS messages: headers, questions, records,
and complete messages.
"""

from dataclasses import dataclass
from typing import List
import struct


@dataclass
class DNSHeader:
    """DNS message header structure"""
    id: int
    flags: int
    qdcount: int  # Number of questions
    ancount: int  # Number of answer records
    nscount: int  # Number of authority records
    arcount: int  # Number of additional records

    def to_bytes(self) -> bytes:
        """Serialize header to bytes"""
        return struct.pack('!HHHHHH', 
                          self.id, self.flags, self.qdcount, 
                          self.ancount, self.nscount, self.arcount)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DNSHeader':
        """Parse header from bytes"""
        if len(data) < 12:
            raise ValueError("DNS header must be at least 12 bytes")
        
        values = struct.unpack('!HHHHHH', data[:12])
        return cls(*values)


@dataclass
class DNSQuestion:
    """DNS question section"""
    name: str
    qtype: int
    qclass: int

    def to_bytes(self) -> bytes:
        """Serialize question to bytes"""
        # Encode domain name
        name_bytes = self._encode_name(self.name)
        # Add type and class
        return name_bytes + struct.pack('!HH', self.qtype, self.qclass)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> tuple['DNSQuestion', int]:
        """Parse question from bytes, returns (question, new_offset)"""
        name, new_offset = cls._decode_name(data, offset)
        if new_offset + 4 > len(data):
            raise ValueError("Insufficient data for question type and class")
        
        qtype, qclass = struct.unpack('!HH', data[new_offset:new_offset + 4])
        return cls(name, qtype, qclass), new_offset + 4

    @staticmethod
    def _encode_name(name: str) -> bytes:
        """Encode domain name to DNS wire format"""
        if not name or name == '.':
            return b'\x00'
        
        parts = name.rstrip('.').split('.')
        result = b''
        for part in parts:
            if len(part) > 63:
                raise ValueError(f"Label too long: {part}")
            result += bytes([len(part)]) + part.encode('ascii')
        result += b'\x00'  # Root label
        return result

    @classmethod
    def _decode_name(cls, data: bytes, offset: int) -> tuple[str, int]:
        """Decode domain name from DNS wire format"""
        labels = []
        original_offset = offset
        jumped = False
        
        while offset < len(data):
            length = data[offset]
            
            if length == 0:  # End of name
                offset += 1
                break
            elif length & 0xC0 == 0xC0:  # Compression pointer
                if offset + 1 >= len(data):
                    raise ValueError("Invalid compression pointer")
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = pointer
            else:  # Regular label
                if offset + length + 1 > len(data):
                    raise ValueError("Label extends beyond data")
                label = data[offset + 1:offset + 1 + length].decode('ascii')
                labels.append(label)
                offset += length + 1
        
        if not labels:
            # Root domain (no labels)
            name = '.'
        else:
            name = '.'.join(labels)
            if not name.endswith('.'):
                name += '.'
        
        return name, original_offset if jumped else offset


@dataclass
class DNSRecord:
    """DNS resource record"""
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: bytes

    def to_bytes(self) -> bytes:
        """Serialize record to bytes"""
        name_bytes = DNSQuestion._encode_name(self.name)
        header = struct.pack('!HHIH', self.rtype, self.rclass, self.ttl, len(self.data))
        return name_bytes + header + self.data

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> tuple['DNSRecord', int]:
        """Parse record from bytes, returns (record, new_offset)"""
        name, new_offset = DNSQuestion._decode_name(data, offset)
        
        if new_offset + 10 > len(data):
            raise ValueError("Insufficient data for record header")
        
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[new_offset:new_offset + 10])
        new_offset += 10
        
        if new_offset + rdlength > len(data):
            raise ValueError("Insufficient data for record data")
        
        rdata_start = new_offset
        rdata = data[new_offset:new_offset + rdlength]
        
        # Decompress domain names in RDATA for certain record types
        # This is necessary because compression pointers reference the full message
        rdata = cls._decompress_rdata(data, rdata_start, rdlength, rtype)
        return cls(name, rtype, rclass, ttl, rdata), new_offset + rdlength
    
    @classmethod
    def _decompress_rdata(cls, full_message: bytes, rdata_offset: int, rdlength: int, rtype: int) -> bytes:
        """
        Decompress domain names in RDATA.
        
        Some record types contain domain names in their RDATA that may use
        compression pointers. We need to decompress these so they can be
        re-serialized in a different message context.
        
        Args:
            full_message: The complete DNS message bytes
            rdata_offset: Offset where RDATA starts in full_message
            rdlength: Length of RDATA
            rtype: Record type
            
        Returns:
            Decompressed RDATA bytes
        """
        # Record types that contain domain names in RDATA
        TYPE_NS = 2
        TYPE_CNAME = 5
        TYPE_SOA = 6
        TYPE_PTR = 12
        TYPE_MX = 15
        
        if rtype == TYPE_SOA:
            # SOA: MNAME, RNAME, then 5 32-bit integers
            try:
                offset = rdata_offset
                # Decode MNAME
                mname, offset = DNSQuestion._decode_name(full_message, offset)
                # Decode RNAME
                rname, offset = DNSQuestion._decode_name(full_message, offset)
                # Get the 5 integers
                if offset + 20 > rdata_offset + rdlength:
                    # Not enough data, return original
                    return full_message[rdata_offset:rdata_offset + rdlength]
                integers = full_message[offset:offset + 20]
                
                # Re-encode without compression
                result = DNSQuestion._encode_name(mname)
                result += DNSQuestion._encode_name(rname)
                result += integers
                return result
            except:
                # If decompression fails, return original
                return full_message[rdata_offset:rdata_offset + rdlength]
        
        elif rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
            # These types contain a single domain name
            try:
                name, _ = DNSQuestion._decode_name(full_message, rdata_offset)
                return DNSQuestion._encode_name(name)
            except:
                return full_message[rdata_offset:rdata_offset + rdlength]
        
        elif rtype == TYPE_MX:
            # MX: 16-bit preference, then domain name
            try:
                if rdlength < 2:
                    return full_message[rdata_offset:rdata_offset + rdlength]
                preference = full_message[rdata_offset:rdata_offset + 2]
                name, _ = DNSQuestion._decode_name(full_message, rdata_offset + 2)
                return preference + DNSQuestion._encode_name(name)
            except:
                return full_message[rdata_offset:rdata_offset + rdlength]
        
        # For other types, return RDATA as-is
        return full_message[rdata_offset:rdata_offset + rdlength]


@dataclass
class DNSMessage:
    """Complete DNS message"""
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authority: List[DNSRecord]
    additional: List[DNSRecord]

    def to_bytes(self) -> bytes:
        """Serialize complete message to bytes"""
        # Update header counts
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authority)
        self.header.arcount = len(self.additional)
        
        result = self.header.to_bytes()
        
        for question in self.questions:
            result += question.to_bytes()
        
        for record in self.answers + self.authority + self.additional:
            result += record.to_bytes()
        
        return result

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DNSMessage':
        """Parse complete message from bytes"""
        if len(data) < 12:
            raise ValueError("DNS message too short")
        
        header = DNSHeader.from_bytes(data)
        offset = 12
        
        questions = []
        for _ in range(header.qdcount):
            question, offset = DNSQuestion.from_bytes(data, offset)
            questions.append(question)
        
        answers = []
        for _ in range(header.ancount):
            record, offset = DNSRecord.from_bytes(data, offset)
            answers.append(record)
        
        authority = []
        for _ in range(header.nscount):
            record, offset = DNSRecord.from_bytes(data, offset)
            authority.append(record)
        
        additional = []
        for _ in range(header.arcount):
            record, offset = DNSRecord.from_bytes(data, offset)
            additional.append(record)
        
        return cls(header, questions, answers, authority, additional)

    def __eq__(self, other) -> bool:
        """Compare DNS messages for equality"""
        if not isinstance(other, DNSMessage):
            return False
        
        return (self.header == other.header and
                self.questions == other.questions and
                self.answers == other.answers and
                self.authority == other.authority and
                self.additional == other.additional)