"""
Unit tests for DNS Cache

Tests cache hit/miss scenarios, TTL expiration, and thread safety.
"""

import time
import threading
import pytest
from dns_server.cache import DNSCache
from dns_server.models import DNSRecord


class TestDNSCache:
    """Unit tests for DNSCache class"""

    def test_cache_miss(self):
        """Test that get returns None for non-existent keys"""
        cache = DNSCache()
        result = cache.get("nonexistent.example.com")
        assert result is None

    def test_cache_hit(self):
        """Test that put and get work for valid entries"""
        cache = DNSCache()
        record = DNSRecord(
            name="example.com.",
            rtype=1,  # A record
            rclass=1,  # IN
            ttl=300,
            data=b'\x01\x02\x03\x04'  # IP address
        )
        
        cache.put("example.com:A", record, ttl=300)
        result = cache.get("example.com:A")
        
        assert result is not None
        assert result[0].name == "example.com."
        assert result[0].rtype == 1
        assert result[0].data == b'\x01\x02\x03\x04'

    def test_ttl_expiration(self):
        """Test that entries expire after TTL"""
        cache = DNSCache()
        record = DNSRecord(
            name="example.com.",
            rtype=1,
            rclass=1,
            ttl=1,
            data=b'\x01\x02\x03\x04'
        )
        
        # Put with 1 second TTL
        cache.put("example.com:A", record, ttl=1)
        
        # Should be available immediately
        result = cache.get("example.com:A")
        assert result is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired now
        result = cache.get("example.com:A")
        assert result is None

    def test_cache_overwrite(self):
        """Test that putting same key overwrites previous value"""
        cache = DNSCache()
        record1 = DNSRecord(
            name="example.com.",
            rtype=1,
            rclass=1,
            ttl=300,
            data=b'\x01\x02\x03\x04'
        )
        record2 = DNSRecord(
            name="example.com.",
            rtype=1,
            rclass=1,
            ttl=300,
            data=b'\x05\x06\x07\x08'
        )
        
        cache.put("example.com:A", record1, ttl=300)
        cache.put("example.com:A", record2, ttl=300)
        
        result = cache.get("example.com:A")
        assert result is not None
        assert result[0].data == b'\x05\x06\x07\x08'

    def test_cleanup_expired(self):
        """Test manual cleanup of expired entries"""
        cache = DNSCache()
        record = DNSRecord(
            name="example.com.",
            rtype=1,
            rclass=1,
            ttl=1,
            data=b'\x01\x02\x03\x04'
        )
        
        cache.put("example.com:A", record, ttl=1)
        assert cache.size() == 1
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Cleanup should remove expired entry
        cache.cleanup_expired()
        assert cache.size() == 0

    def test_max_size_eviction(self):
        """Test that cache evicts oldest entries when full"""
        cache = DNSCache(max_size=3)
        
        for i in range(5):
            record = DNSRecord(
                name=f"example{i}.com.",
                rtype=1,
                rclass=1,
                ttl=300,
                data=bytes([i, i, i, i])
            )
            cache.put(f"example{i}.com:A", record, ttl=300)
        
        # Cache should only have 3 entries
        assert cache.size() == 3

    def test_thread_safety_concurrent_reads(self):
        """Test concurrent reads from multiple threads"""
        cache = DNSCache()
        record = DNSRecord(
            name="example.com.",
            rtype=1,
            rclass=1,
            ttl=300,
            data=b'\x01\x02\x03\x04'
        )
        cache.put("example.com:A", record, ttl=300)
        
        results = []
        
        def read_cache():
            for _ in range(100):
                result = cache.get("example.com:A")
                results.append(result is not None)
        
        threads = [threading.Thread(target=read_cache) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All reads should succeed
        assert all(results)

    def test_thread_safety_concurrent_writes(self):
        """Test concurrent writes from multiple threads"""
        cache = DNSCache()
        
        def write_cache(thread_id):
            for i in range(50):
                record = DNSRecord(
                    name=f"example{thread_id}-{i}.com.",
                    rtype=1,
                    rclass=1,
                    ttl=300,
                    data=bytes([thread_id, i, 0, 0])
                )
                cache.put(f"example{thread_id}-{i}.com:A", record, ttl=300)
        
        threads = [threading.Thread(target=write_cache, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Cache should have entries (exact count depends on max_size)
        assert cache.size() > 0

    def test_clear(self):
        """Test clearing all cache entries"""
        cache = DNSCache()
        
        for i in range(5):
            record = DNSRecord(
                name=f"example{i}.com.",
                rtype=1,
                rclass=1,
                ttl=300,
                data=bytes([i, i, i, i])
            )
            cache.put(f"example{i}.com:A", record, ttl=300)
        
        assert cache.size() == 5
        cache.clear()
        assert cache.size() == 0
