<?php

namespace Capito\CapPhpServer;

/**
 * Rate limiter implementation using token bucket algorithm
 * Enhanced with persistent storage support for multi-process environments
 */
class RateLimiter
{
    private int $rps;
    private int $burst;
    private $storage; // Can be MysqlStorage, FileStorage, etc.
    private int $bucketExpiry;

    /**
     * Create a new rate limiter
     * @param int $rps Requests per second
     * @param int $burst Maximum burst capacity
     * @param object|null $storage Storage backend with rate limit methods (null for in-memory)
     * @param int $bucketExpiry Bucket expiry time in seconds (default: 1 hour)
     */
    public function __construct(int $rps = 10, int $burst = 50, $storage = null, int $bucketExpiry = 3600)
    {
        $this->rps = $rps;
        $this->burst = $burst;
        $this->storage = $storage;
        $this->bucketExpiry = $bucketExpiry;
    }

    /**
     * Check if request is allowed for the given key
     * @param string $key Identifier for rate limiting (e.g., IP address)
     * @param int|null $limit Custom limit for this request (optional)
     * @param int|null $window Custom window for this request (optional)
     * @return bool Whether request is allowed
     */
    public function allow(string $key, ?int $limit = null, ?int $window = null): bool
    {
        $limit = $limit ?? $this->rps;
        $window = $window ?? 1; // 1 second window
        
        if ($limit <= 0 || $this->burst <= 0) {
            return true; // Rate limiting disabled
        }

        $now = microtime(true);
        
        // Get bucket from storage or create new one
        $bucket = $this->getBucket($key);
        if ($bucket === null) {
            $bucket = [
                'tokens' => $this->burst,
                'last_refill' => $now
            ];
        }
        
        // Calculate tokens to add based on time elapsed
        $elapsed = $now - $bucket['last_refill'];
        $tokensToAdd = $elapsed * $limit / $window;
        
        // Refill tokens
        $bucket['tokens'] = min($this->burst, $bucket['tokens'] + $tokensToAdd);
        $bucket['last_refill'] = $now;

        // Check if we can consume a token
        if ($bucket['tokens'] >= 1) {
            $bucket['tokens']--;
            $this->setBucket($key, $bucket);
            return true;
        }

        $this->setBucket($key, $bucket);
        return false;
    }

    /**
     * Get bucket data from storage or fallback to in-memory
     * @param string $key Rate limit identifier
     * @return array|null Bucket data or null if not found
     */
    private function getBucket(string $key): ?array
    {
        if ($this->storage !== null && method_exists($this->storage, 'getRateLimitBucket')) {
            return $this->storage->getRateLimitBucket($key);
        }
        return null; // No storage, no persistence
    }

    /**
     * Set bucket data in storage
     * @param string $key Rate limit identifier
     * @param array $bucket Bucket data
     */
    private function setBucket(string $key, array $bucket): void
    {
        if ($this->storage !== null && method_exists($this->storage, 'setRateLimitBucket')) {
            $expiresTs = time() + $this->bucketExpiry;
            $this->storage->setRateLimitBucket($key, $bucket, $expiresTs);
        }
    }

    /**
     * Reset rate limit for a specific key
     * @param string $key Identifier to reset
     */
    public function reset(string $key): void
    {
        if ($this->storage !== null && method_exists($this->storage, 'deleteRateLimitBucket')) {
            $this->storage->deleteRateLimitBucket($key);
        }
    }

    /**
     * Get current token count for a key
     * @param string $key Identifier
     * @return float Current token count
     */
    public function getTokens(string $key): float
    {
        $bucket = $this->getBucket($key);
        if ($bucket === null) {
            return $this->burst;
        }

        $now = microtime(true);
        $elapsed = $now - $bucket['last_refill'];
        $tokensToAdd = $elapsed * $this->rps;
        
        return min($this->burst, $bucket['tokens'] + $tokensToAdd);
    }

    /**
     * Set rate limit parameters
     * @param int $rps Requests per second
     * @param int $burst Maximum burst capacity
     */
    public function setLimits(int $rps, int $burst): void
    {
        $this->rps = $rps;
        $this->burst = $burst;
    }

    /**
     * Get current rate limit settings
     * @return array ['rps' => int, 'burst' => int]
     */
    public function getLimits(): array
    {
        return [
            'rps' => $this->rps,
            'burst' => $this->burst
        ];
    }
}