"""
Coil - DNS Cache

Thread-safe TTL-based cache for DNS records.
"""

import time
import threading
import logging
from typing import Optional
from dataclasses import dataclass
from dns_server.models import DNSRecord


@dataclass
class CacheEntry:
    """Cache entry with expiration time"""
    records: list  # List of DNSRecord
    expiration: float  # Unix timestamp when entry expires

    def is_expired(self) -> bool:
        """Check if this cache entry has expired"""
        return time.time() >= self.expiration


class DNSCache:
    """Thread-safe DNS cache with TTL support"""

    def __init__(self, max_size: int = 1000):
        """
        Initialize DNS cache
        
        Args:
            max_size: Maximum number of entries to store
        """
        self._cache: dict[str, CacheEntry] = {}
        self._max_size = max_size
        self._lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"DNS cache initialized with max_size={max_size}")

    def get(self, key: str) -> Optional[list]:
        """
        Retrieve records from cache
        
        Args:
            key: Cache key (typically domain name + record type)
            
        Returns:
            List of DNSRecord if found and not expired, None otherwise
        """
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self.logger.debug(f"Cache miss for key: {key}")
                return None
            
            if entry.is_expired():
                # Remove expired entry
                self.logger.debug(f"Cache entry expired for key: {key}")
                del self._cache[key]
                return None
            
            self.logger.debug(f"Cache hit for key: {key}")
            return entry.records

    def put(self, key: str, records, ttl: int) -> None:
        """
        Store records in cache with TTL
        
        Args:
            key: Cache key (typically domain name + record type)
            records: DNSRecord or list of DNSRecord to cache
            ttl: Time-to-live in seconds
        """
        # Normalize to list
        if isinstance(records, DNSRecord):
            records = [records]
        
        with self._lock:
            # If cache is full, remove oldest expired entries
            if len(self._cache) >= self._max_size:
                self.logger.debug(f"Cache full ({len(self._cache)} entries), cleaning up expired entries")
                self._cleanup_expired()
                
                # If still full after cleanup, remove oldest entry
                if len(self._cache) >= self._max_size:
                    # Remove the entry with earliest expiration
                    oldest_key = min(self._cache.keys(), 
                                   key=lambda k: self._cache[k].expiration)
                    self.logger.debug(f"Cache still full after cleanup, evicting oldest entry: {oldest_key}")
                    del self._cache[oldest_key]
            
            expiration = time.time() + ttl
            self._cache[key] = CacheEntry(records, expiration)
            self.logger.debug(f"Cached {len(records)} record(s) for key: {key} with TTL: {ttl}s")

    def cleanup_expired(self) -> None:
        """Remove all expired entries from cache (public method)"""
        with self._lock:
            self._cleanup_expired()

    def _cleanup_expired(self) -> None:
        """Remove all expired entries from cache (internal, assumes lock held)"""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self._cache.items()
            if entry.expiration <= current_time
        ]
        
        if expired_keys:
            self.logger.debug(f"Removing {len(expired_keys)} expired cache entries")
        
        for key in expired_keys:
            del self._cache[key]

    def clear(self) -> None:
        """Clear all entries from cache"""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self.logger.info(f"Cache cleared ({count} entries removed)")

    def size(self) -> int:
        """Return current number of entries in cache"""
        with self._lock:
            return len(self._cache)
