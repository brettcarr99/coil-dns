"""
Coil - DNS Server Coordinator

Main DNSServer class that ties together all Coil components: parser, resolver,
cache, and network handlers to provide a complete recursive DNS server.
"""

import logging
import signal
import sys
from typing import Optional
from dns_server.models import DNSMessage
from dns_server.parser import DNSMessageParser
from dns_server.resolver import RecursiveResolver
from dns_server.cache import DNSCache
from dns_server.handlers import UDPHandler, TCPHandler
from dns_server.config import ConfigManager, DNSConfig


class DNSServer:
    """
    Coil DNS server — integrates all components.

    Manages the server lifecycle, coordinates query handling between
    components, and provides startup/shutdown functionality.
    """
    
    def __init__(self, config_path: str, hints_path: str):
        """
        Initialize DNS server with configuration.
        
        Args:
            config_path: Path to configuration YAML file
            hints_path: Path to root hints file
            
        Raises:
            ConfigurationError: If configuration or hints cannot be loaded
        """
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config_manager = ConfigManager()
        try:
            self.config = self.config_manager.load_config(config_path)
            self.root_hints = self.config_manager.load_root_hints(hints_path)
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            raise
        
        # Update logging level from config
        logging.getLogger().setLevel(self.config.log_level)
        
        # Initialize components
        self.cache = DNSCache(max_size=self.config.cache_size)
        self.resolver = RecursiveResolver(
            root_hints=self.root_hints,
            cache=self.cache,
            timeout=self.config.timeout,
            max_retries=self.config.max_retries
        )
        self.parser = DNSMessageParser()
        
        # Initialize network handlers
        self.udp_handler = UDPHandler(
            port=self.config.listen_port,
            address=self.config.listen_address
        )
        self.tcp_handler = TCPHandler(
            port=self.config.listen_port,
            address=self.config.listen_address
        )
        
        # Set query handlers
        self.udp_handler.set_query_handler(self.handle_query)
        self.tcp_handler.set_query_handler(self.handle_query)
        
        # Server state
        self.running = False
        
        self.logger.info("Coil DNS server initialized")
    
    def start(self) -> None:
        """
        Start the DNS server.
        
        Starts both UDP and TCP handlers and begins accepting queries.
        
        Raises:
            OSError: If server cannot bind to configured port
        """
        if self.running:
            self.logger.warning("Server already running")
            return
        
        try:
            # Start network handlers
            self.logger.info(f"Starting Coil on {self.config.listen_address}:{self.config.listen_port}")
            
            self.udp_handler.start_server()
            self.tcp_handler.start_server()
            
            self.running = True
            self.logger.info("Coil started successfully")
            
        except OSError as e:
            self.logger.error(f"Failed to start Coil: {e}")
            self.stop()
            raise
    
    def stop(self) -> None:
        """
        Stop the DNS server.
        
        Stops all network handlers and cleans up resources.
        """
        if not self.running:
            return
        
        self.logger.info("Stopping Coil")
        
        # Stop network handlers
        self.udp_handler.stop_server()
        self.tcp_handler.stop_server()
        
        # Clear cache
        self.cache.clear()
        
        self.running = False
        self.logger.info("Coil stopped")
    
    def handle_query(self, query: DNSMessage, client_addr: tuple) -> DNSMessage:
        """
        Handle a DNS query from a client.
        
        This is the main query processing logic that coordinates between
        the parser, resolver, and cache to produce a response.
        
        Args:
            query: Parsed DNS query message
            client_addr: Client address tuple (ip, port)
            
        Returns:
            DNS response message
        """
        try:
            # Validate query
            if not self.parser.validate_message(query):
                self.logger.warning(f"Invalid query from {client_addr}")
                return self.parser.create_error_response(
                    query,
                    DNSMessageParser.RCODE_FORMERR
                )
            
            # Check that we have at least one question
            if not query.questions:
                self.logger.warning(f"Query with no questions from {client_addr}")
                return self.parser.create_error_response(
                    query,
                    DNSMessageParser.RCODE_FORMERR
                )
            
            # Process the first question (standard DNS behavior)
            question = query.questions[0]
            
            self.logger.info(f"Resolving query for {question.name} (type {question.qtype}) from {client_addr}")
            
            # Resolve the query
            response = self.resolver.resolve(question)
            
            # Copy the query ID to the response
            response.header.id = query.header.id
            
            # Log the result
            rcode = response.header.flags & 0x000F
            if rcode == DNSMessageParser.RCODE_NOERROR:
                self.logger.info(f"Successfully resolved {question.name} with {len(response.answers)} answers")
            else:
                self.logger.warning(f"Resolution failed for {question.name} with rcode {rcode}")
            
            return response
            
        except Exception as e:
            # Log error and return SERVFAIL
            self.logger.error(f"Error handling query from {client_addr}: {e}")
            return self.parser.create_error_response(
                query,
                DNSMessageParser.RCODE_SERVFAIL
            )
    
    def run(self) -> None:
        """
        Run the DNS server until interrupted.
        
        This method starts the server and blocks until a shutdown signal
        is received (SIGINT or SIGTERM).
        """
        # Set up signal handlers
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, shutting down")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start the server
        self.start()
        
        # Keep the main thread alive
        self.logger.info("Coil running. Press Ctrl+C to stop.")
        signal.pause()
