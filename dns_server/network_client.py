"""
Coil - Network Client

Sends DNS queries to upstream nameservers over UDP and TCP, with
configurable timeout and retry logic.
"""

import socket
import struct
import logging
from typing import Optional
from dns_server.models import DNSMessage


logger = logging.getLogger(__name__)


class NetworkClient:
    """
    Network client for sending DNS queries to upstream nameservers.
    
    Supports both UDP and TCP protocols with configurable timeout and retry logic.
    Handles network errors gracefully and logs issues for monitoring.
    """
    
    def __init__(self, timeout: int = 5, max_retries: int = 3):
        """
        Initialize the network client.
        
        Args:
            timeout: Query timeout in seconds (default: 5)
            max_retries: Maximum number of retry attempts per query (default: 3)
        """
        self.timeout = timeout
        self.max_retries = max_retries
    
    def query_udp(self, nameserver_ip: str, query: DNSMessage, port: int = 53) -> Optional[DNSMessage]:
        """
        Send a DNS query via UDP to a nameserver.
        
        Args:
            nameserver_ip: IP address of the nameserver
            query: DNS query message to send
            port: DNS port (default: 53)
            
        Returns:
            DNSMessage response, or None if query failed
        """
        query_bytes = query.to_bytes()
        
        for attempt in range(self.max_retries):
            sock = None
            try:
                # Create UDP socket with random source port (Kaminsky defence)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('', 0))
                sock.settimeout(self.timeout)
                
                # Send query
                sock.sendto(query_bytes, (nameserver_ip, port))
                
                # Receive response
                response_bytes, _ = sock.recvfrom(4096)
                
                # Parse response
                response = DNSMessage.from_bytes(response_bytes)
                
                # Verify response ID matches query ID
                if response.header.id == query.header.id:
                    logger.debug(f"UDP query to {nameserver_ip} succeeded")
                    return response
                else:
                    logger.warning(f"Response ID mismatch from {nameserver_ip}: expected {query.header.id}, got {response.header.id}")
                    
            except socket.timeout:
                logger.warning(f"UDP query to {nameserver_ip} timed out (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    continue
                else:
                    logger.error(f"UDP query to {nameserver_ip} failed after {self.max_retries} attempts")
                    return None
                    
            except socket.error as e:
                logger.error(f"UDP socket error querying {nameserver_ip}: {e}")
                if attempt < self.max_retries - 1:
                    continue
                else:
                    return None
                    
            except (ValueError, struct.error) as e:
                logger.error(f"Failed to parse UDP response from {nameserver_ip}: {e}")
                return None
                
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
        
        return None
    
    def query_tcp(self, nameserver_ip: str, query: DNSMessage, port: int = 53) -> Optional[DNSMessage]:
        """
        Send a DNS query via TCP to a nameserver.
        
        TCP queries are prefixed with a 2-byte length field as per RFC 1035.
        
        Args:
            nameserver_ip: IP address of the nameserver
            query: DNS query message to send
            port: DNS port (default: 53)
            
        Returns:
            DNSMessage response, or None if query failed
        """
        query_bytes = query.to_bytes()
        
        for attempt in range(self.max_retries):
            sock = None
            try:
                # Create TCP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                # Connect to nameserver
                sock.connect((nameserver_ip, port))
                
                # Send query with 2-byte length prefix (RFC 1035)
                length_prefix = struct.pack('!H', len(query_bytes))
                sock.sendall(length_prefix + query_bytes)
                
                # Receive response length
                length_bytes = self._recv_exact(sock, 2)
                if not length_bytes:
                    logger.error(f"Failed to receive response length from {nameserver_ip}")
                    if attempt < self.max_retries - 1:
                        continue
                    else:
                        return None
                
                response_length = struct.unpack('!H', length_bytes)[0]
                
                # Receive response data
                response_bytes = self._recv_exact(sock, response_length)
                if not response_bytes:
                    logger.error(f"Failed to receive complete response from {nameserver_ip}")
                    if attempt < self.max_retries - 1:
                        continue
                    else:
                        return None
                
                # Parse response
                response = DNSMessage.from_bytes(response_bytes)
                
                # Verify response ID matches query ID
                if response.header.id == query.header.id:
                    logger.debug(f"TCP query to {nameserver_ip} succeeded")
                    return response
                else:
                    logger.warning(f"Response ID mismatch from {nameserver_ip}: expected {query.header.id}, got {response.header.id}")
                    
            except socket.timeout:
                logger.warning(f"TCP query to {nameserver_ip} timed out (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    continue
                else:
                    logger.error(f"TCP query to {nameserver_ip} failed after {self.max_retries} attempts")
                    return None
                    
            except socket.error as e:
                logger.error(f"TCP socket error querying {nameserver_ip}: {e}")
                if attempt < self.max_retries - 1:
                    continue
                else:
                    return None
                    
            except (ValueError, struct.error) as e:
                logger.error(f"Failed to parse TCP response from {nameserver_ip}: {e}")
                return None
                
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
        
        return None
    
    def query(self, nameserver_ip: str, query: DNSMessage, use_tcp: bool = False, port: int = 53) -> Optional[DNSMessage]:
        """
        Send a DNS query to a nameserver using the specified protocol.
        
        This is a convenience method that delegates to query_udp or query_tcp.
        
        Args:
            nameserver_ip: IP address of the nameserver
            query: DNS query message to send
            use_tcp: If True, use TCP; otherwise use UDP (default: False)
            port: DNS port (default: 53)
            
        Returns:
            DNSMessage response, or None if query failed
        """
        if use_tcp:
            return self.query_tcp(nameserver_ip, query, port)
        else:
            return self.query_udp(nameserver_ip, query, port)
    
    def _recv_exact(self, sock: socket.socket, num_bytes: int) -> Optional[bytes]:
        """
        Receive exactly num_bytes from a socket.
        
        This helper ensures we receive the complete message even if it arrives
        in multiple chunks.
        
        Args:
            sock: Socket to receive from
            num_bytes: Number of bytes to receive
            
        Returns:
            Bytes received, or None if connection closed prematurely
        """
        data = b''
        while len(data) < num_bytes:
            try:
                chunk = sock.recv(num_bytes - len(data))
                if not chunk:
                    # Connection closed
                    return None
                data += chunk
            except socket.error as e:
                logger.error(f"Error receiving data: {e}")
                return None
        
        return data
