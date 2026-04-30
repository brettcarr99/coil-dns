"""
Coil - Network Handlers

UDP and TCP handlers for accepting and processing DNS queries from clients.
"""

import socket
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional
from dns_server.models import DNSMessage
from dns_server.parser import DNSMessageParser


# UDP size limits
UDP_MAX_SIZE = 512  # Standard DNS UDP message size limit
UDP_BUFFER_SIZE = 4096  # Buffer size for receiving


class UDPHandler:
    """
    UDP handler for DNS queries.
    
    Handles UDP socket operations, respects UDP size limitations,
    and sets truncation bit when responses exceed size limits.
    """
    
    def __init__(self, port: int = 53, address: str = "0.0.0.0", max_workers: int = 50):
        """
        Initialize UDP handler.

        Args:
            port: Port to listen on (default 53)
            address: Address to bind to (default 0.0.0.0)
            max_workers: Thread pool size for handling requests (default 50)
        """
        self.port = port
        self.address = address
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.parser = DNSMessageParser()
        self.query_handler: Optional[Callable[[DNSMessage, tuple], DNSMessage]] = None
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self.logger = logging.getLogger(__name__)
    
    def set_query_handler(self, handler: Callable[[DNSMessage, tuple], DNSMessage]):
        """
        Set the callback function for handling DNS queries.
        
        Args:
            handler: Function that takes (DNSMessage, client_addr) and returns DNSMessage
        """
        self.query_handler = handler
    
    def start_server(self):
        """
        Start the UDP server and begin listening for requests.
        
        Raises:
            OSError: If socket binding fails
        """
        if self.running:
            self.logger.warning("UDP server already running")
            return
        
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address and port
            self.socket.bind((self.address, self.port))
            self.running = True
            
            self.logger.info(f"UDP server started on {self.address}:{self.port}")
            
            # Start listening in a separate thread
            listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            listen_thread.start()
            
        except OSError as e:
            self.logger.error(f"Failed to start UDP server: {e}")
            raise
    
    def stop_server(self):
        """Stop the UDP server and close the socket."""
        if not self.running:
            return
        
        self.running = False

        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

        self._executor.shutdown(wait=False)
        self.logger.info("UDP server stopped")
    
    def _listen_loop(self):
        """Main listening loop for UDP requests."""
        while self.running and self.socket:
            try:
                # Receive data from client
                data, client_addr = self.socket.recvfrom(UDP_BUFFER_SIZE)
                
                self._executor.submit(self._handle_request, data, client_addr)
                
            except OSError:
                # Socket closed or error - exit loop
                if self.running:
                    self.logger.error("UDP socket error in listen loop")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in UDP listen loop: {e}")
                continue
    
    def _handle_request(self, data: bytes, client_addr: tuple):
        """
        Handle a single UDP DNS request.
        
        Args:
            data: Raw DNS query bytes
            client_addr: Client address tuple (ip, port)
        """
        try:
            self.logger.debug(f"Handling UDP request from {client_addr[0]}:{client_addr[1]}")
            
            # Parse the query
            query = self.parser.parse_query(data)
            
            # Process query through handler
            if self.query_handler:
                response = self.query_handler(query, client_addr)
            else:
                # No handler set - return SERVFAIL
                self.logger.error("No query handler set for UDP server")
                response = self.parser.create_error_response(
                    query,
                    DNSMessageParser.RCODE_SERVFAIL
                )
            
            # Serialize response
            response_bytes = self.parser.serialize_response(response)
            
            # Check UDP size limit
            if len(response_bytes) > UDP_MAX_SIZE:
                # Response too large - set truncation bit
                self.logger.info(f"UDP response too large ({len(response_bytes)} bytes), setting truncation bit")
                response = self._truncate_response(response)
                response_bytes = self.parser.serialize_response(response)
            
            # Send response back to client
            self._send_response(response_bytes, client_addr)
            self.logger.debug(f"Sent UDP response to {client_addr[0]}:{client_addr[1]} ({len(response_bytes)} bytes)")
            
        except ValueError as e:
            # Parse error - send FORMERR
            self.logger.warning(f"Invalid query from {client_addr}: {e}")
            try:
                error_response = self.parser.create_error_response(
                    None,
                    DNSMessageParser.RCODE_FORMERR
                )
                response_bytes = self.parser.serialize_response(error_response)
                self._send_response(response_bytes, client_addr)
            except:
                pass  # Best effort
        
        except Exception as e:
            # Unexpected error - log and continue
            self.logger.error(f"Error handling UDP request from {client_addr}: {e}")
    
    def _truncate_response(self, response: DNSMessage) -> DNSMessage:
        """
        Truncate a DNS response by setting the TC (truncation) bit.

        Sets the TC bit and removes all answer/authority/additional records,
        signalling the client to retry over TCP per RFC 1035.

        Args:
            response: Original response message

        Returns:
            Truncated response with TC bit set and no records
        """
        from dns_server.models import DNSHeader

        # Set TC bit (bit 9) in flags
        truncated_flags = response.header.flags | 0x0200

        truncated_header = DNSHeader(
            id=response.header.id,
            flags=truncated_flags,
            qdcount=len(response.questions),
            ancount=0,
            nscount=0,
            arcount=0
        )

        return DNSMessage(
            header=truncated_header,
            questions=response.questions,
            answers=[],
            authority=[],
            additional=[]
        )
    
    def _send_response(self, data: bytes, client_addr: tuple):
        """
        Send response data to client.
        
        Args:
            data: Response bytes to send
            client_addr: Client address tuple (ip, port)
        """
        try:
            if self.socket and self.running:
                self.socket.sendto(data, client_addr)
        except OSError as e:
            self.logger.error(f"Failed to send UDP response to {client_addr}: {e}")


class TCPHandler:
    """
    TCP handler for DNS queries.
    
    Handles TCP socket operations and connection management.
    Supports concurrent connections.
    """
    
    def __init__(self, port: int = 53, address: str = "0.0.0.0", max_workers: int = 50):
        """
        Initialize TCP handler.

        Args:
            port: Port to listen on (default 53)
            address: Address to bind to (default 0.0.0.0)
            max_workers: Thread pool size for handling connections (default 50)
        """
        self.port = port
        self.address = address
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.parser = DNSMessageParser()
        self.query_handler: Optional[Callable[[DNSMessage, tuple], DNSMessage]] = None
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self.logger = logging.getLogger(__name__)
    
    def set_query_handler(self, handler: Callable[[DNSMessage, tuple], DNSMessage]):
        """
        Set the callback function for handling DNS queries.
        
        Args:
            handler: Function that takes (DNSMessage, client_addr) and returns DNSMessage
        """
        self.query_handler = handler
    
    def start_server(self):
        """
        Start the TCP server and begin listening for connections.
        
        Raises:
            OSError: If socket binding fails
        """
        if self.running:
            self.logger.warning("TCP server already running")
            return
        
        try:
            # Create TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address and port
            self.socket.bind((self.address, self.port))
            
            # Listen for connections (backlog of 5)
            self.socket.listen(5)
            self.running = True
            
            self.logger.info(f"TCP server started on {self.address}:{self.port}")
            
            # Start accepting connections in a separate thread
            accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
            accept_thread.start()
            
        except OSError as e:
            self.logger.error(f"Failed to start TCP server: {e}")
            raise
    
    def stop_server(self):
        """Stop the TCP server and close the socket."""
        if not self.running:
            return
        
        self.running = False

        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

        self._executor.shutdown(wait=False)
        self.logger.info("TCP server stopped")
    
    def _accept_loop(self):
        """Main loop for accepting TCP connections."""
        while self.running and self.socket:
            try:
                # Accept new connection
                conn, client_addr = self.socket.accept()
                
                self._executor.submit(self._handle_connection, conn, client_addr)
                
            except OSError:
                # Socket closed or error - exit loop
                if self.running:
                    self.logger.error("TCP socket error in accept loop")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in TCP accept loop: {e}")
                continue
    
    def _handle_connection(self, conn: socket.socket, client_addr: tuple):
        """
        Handle a single TCP connection.
        
        TCP DNS messages are prefixed with a 2-byte length field.
        
        Args:
            conn: Client socket connection
            client_addr: Client address tuple (ip, port)
        """
        try:
            self.logger.debug(f"Handling TCP connection from {client_addr[0]}:{client_addr[1]}")
            
            # Read 2-byte length prefix
            length_bytes = self._recv_exact(conn, 2)
            if not length_bytes:
                self.logger.debug(f"TCP connection closed by {client_addr[0]}:{client_addr[1]}")
                return
            
            # Parse length (big-endian)
            message_length = int.from_bytes(length_bytes, byteorder='big')
            self.logger.debug(f"Expecting TCP message of {message_length} bytes from {client_addr[0]}:{client_addr[1]}")
            
            # Read the DNS message
            data = self._recv_exact(conn, message_length)
            if not data:
                self.logger.warning(f"Failed to receive complete TCP message from {client_addr[0]}:{client_addr[1]}")
                return
            
            # Parse the query
            query = self.parser.parse_query(data)
            
            # Process query through handler
            if self.query_handler:
                response = self.query_handler(query, client_addr)
            else:
                # No handler set - return SERVFAIL
                self.logger.error("No query handler set for TCP server")
                response = self.parser.create_error_response(
                    query,
                    DNSMessageParser.RCODE_SERVFAIL
                )
            
            # Serialize response
            response_bytes = self.parser.serialize_response(response)
            
            # Send response with length prefix
            self._send_response(conn, response_bytes)
            self.logger.debug(f"Sent TCP response to {client_addr[0]}:{client_addr[1]} ({len(response_bytes)} bytes)")
            
        except ValueError as e:
            # Parse error - send FORMERR
            self.logger.warning(f"Invalid query from {client_addr}: {e}")
            try:
                error_response = self.parser.create_error_response(
                    None,
                    DNSMessageParser.RCODE_FORMERR
                )
                response_bytes = self.parser.serialize_response(error_response)
                self._send_response(conn, response_bytes)
            except:
                pass  # Best effort
        
        except Exception as e:
            # Unexpected error - log and continue
            self.logger.error(f"Error handling TCP connection from {client_addr}: {e}")
        
        finally:
            # Close connection
            try:
                conn.close()
                self.logger.debug(f"Closed TCP connection from {client_addr[0]}:{client_addr[1]}")
            except:
                pass
    
    def _recv_exact(self, conn: socket.socket, length: int) -> Optional[bytes]:
        """
        Receive exactly the specified number of bytes from a socket.
        
        Args:
            conn: Socket connection
            length: Number of bytes to receive
            
        Returns:
            Bytes received, or None if connection closed
        """
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                # Connection closed
                return None
            data += chunk
        return data
    
    def _send_response(self, conn: socket.socket, data: bytes):
        """
        Send response data to client with length prefix.
        
        Args:
            conn: Socket connection
            data: Response bytes to send
        """
        try:
            # Send length prefix (2 bytes, big-endian)
            length_bytes = len(data).to_bytes(2, byteorder='big')
            conn.sendall(length_bytes + data)
        except OSError as e:
            self.logger.error(f"Failed to send TCP response: {e}")
