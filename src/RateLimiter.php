<?php

namespace Capito\CapPhpServer;

/**
 * Brute Force Protection Rate Limiter
 * Tracks request counts with rolling penalty system - blocked requests must wait full penalty duration
 */
class RateLimiter
{
    private $storage; // Can be MysqlStorage, FileStorage, etc.
    private int $bucketExpiry;

    /**
     * Create a new brute force protection rate limiter
     * @param object|null $storage Storage backend with rate limit methods (null for in-memory)
     * @param int $bucketExpiry Bucket expiry time in seconds (default: 1 hour)
     */
    public function __construct($storage = null, int $bucketExpiry = 3600)
    {
        $this->storage = $storage;
        $this->bucketExpiry = $bucketExpiry;
    }

    /**
     * Check if request is allowed with rolling penalty system
     * @param string $key Identifier for rate limiting (e.g., IP address)
     * @param int $limit Maximum requests allowed in the time window
     * @param int $window Time window in seconds for counting requests
     * @param int $penalty Penalty duration in seconds for blocked requests (0 = disabled)
     * @return bool Whether request is allowed
     */
    public function allow(string $key, int $limit, int $window, int $penalty = 60): bool
    {
        if ($limit <= 0 || $penalty <= 0) {
            return true; // Rate limiting disabled
        }
        $now = time();
        $bucket = $this->getBucket($key);
        // Check conditions for creating a new bucket
        $isFirstRequest = ($bucket === null);
        $hasPenalty = ($bucket !== null && $bucket['penalty_until'] !== null);
        $isPenaltyExpired = ($hasPenalty && $now >= $bucket['penalty_until']);
        $isWindowExpired = ($bucket !== null && $now >= $bucket['window_end']);       
        // Create new bucket if: no bucket exists, penalty expired, or window expired
        if ($isFirstRequest || $isPenaltyExpired || $isWindowExpired) {
            $bucket = [
                'count' => 1,
                'window_start' => $now,
                'window_end' => $now + $window,
                'penalty_until' => null
            ];
            $this->setBucket($key, $bucket);
            return true;
        }
        // Check if we're under penalty from previous blocked request
        if ($hasPenalty && !$isPenaltyExpired){
            // Still under penalty : extend penalty by making another blocked request
            $bucket['penalty_until'] = $now + $penalty;
            $this->setBucket($key, $bucket);
            return false;
        }       
        // We're still in the current window - check if we can allow this request
        if ($bucket['count'] < $limit) {
            $bucket['count']++;
            $this->setBucket($key, $bucket);
            return true;
        }    
        // Rate limit exceeded - impose rolling penalty
        $bucket['penalty_until'] = $now + $penalty;
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
     * Get remaining request allowance for a key with rolling penalty system
     * @param string $key Identifier
     * @param int $limit Maximum requests allowed in the window (defaults to 5)
     * @param int $window Time window in seconds (defaults to 60)
     * @param int $penalty Penalty duration in seconds (defaults to 60)
     * @return int Remaining requests allowed (0 if under penalty)
     */
    public function getTokens(string $key, int $limit = 5, int $window = 60, int $penalty = 60): int
    {
        $bucket = $this->getBucket($key);
        if ($bucket === null) {
            return $limit; // No requests made yet, full allowance available
        }

        $now = time();
        
        // Check if we're under penalty
        if ($bucket['penalty_until'] !== null && $now < $bucket['penalty_until']) {
            return 0; // Under penalty, no requests allowed
        }
        
        // Check if penalty has expired
        if ($bucket['penalty_until'] !== null && $now >= $bucket['penalty_until']) {
            return $limit; // Penalty expired, full allowance available
        }
        
        // Check if current window has expired - if so, full allowance is available
        if ($now >= $bucket['window_end']) {
            return $limit; // Window expired, full allowance available
        }
        
        // We're still in the current window - return remaining allowance
        return max(0, $limit - $bucket['count']);
    }

    /**
     * Get information about rate limiting status
     * @param string $key Identifier
     * @return array Rate limiting information
     */
    public function getLimits(): array
    {
        return [
            'type' => 'rolling_penalty',
            'description' => 'Brute force protection with rolling penalty system - blocked requests must wait full penalty duration'
        ];
    }

    /**
     * Get penalty status for a key
     * @param string $key Identifier
     * @return array Penalty status information
     */
    public function getPenaltyStatus(string $key): array
    {
        $bucket = $this->getBucket($key);
        if ($bucket === null) {
            return [
                'under_penalty' => false,
                'penalty_until' => null,
                'seconds_remaining' => 0
            ];
        }

        $now = time();
        $underPenalty = $bucket['penalty_until'] !== null && $now < $bucket['penalty_until'];
        
        return [
            'under_penalty' => $underPenalty,
            'penalty_until' => $bucket['penalty_until'],
            'seconds_remaining' => $underPenalty ? $bucket['penalty_until'] - $now : 0
        ];
    }
}