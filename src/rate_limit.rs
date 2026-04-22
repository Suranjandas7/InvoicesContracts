use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Track failed attempts for rate limiting
#[derive(Debug, Clone)]
struct AttemptTracker {
    count: u32,
    window_start: DateTime<Utc>,
}

/// Rate limiter for UUID verification attempts
#[derive(Debug, Clone)]
pub struct RateLimiter {
    attempts: Arc<RwLock<HashMap<IpAddr, AttemptTracker>>>,
    max_attempts: u32,
    window_minutes: i64,
}

impl RateLimiter {
    /// Create a new rate limiter with default settings
    /// Default: 5 attempts per 15 minutes
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts: 5,
            window_minutes: 15,
        }
    }

    /// Check if an IP address is currently rate limited
    /// Returns Ok(()) if allowed, Err if rate limited
    pub async fn check_rate_limit(&self, ip: IpAddr) -> Result<(), String> {
        let mut attempts = self.attempts.write().await;
        let now = Utc::now();

        // Clean up old entries (> 30 minutes old)
        attempts.retain(|_, tracker| {
            now.signed_duration_since(tracker.window_start)
                .num_minutes()
                < 30
        });

        if let Some(tracker) = attempts.get(&ip) {
            let elapsed = now
                .signed_duration_since(tracker.window_start)
                .num_minutes();

            // If window has expired, remove the entry
            if elapsed >= self.window_minutes {
                attempts.remove(&ip);
                return Ok(());
            }

            // Check if limit exceeded
            if tracker.count >= self.max_attempts {
                let remaining = self.window_minutes - elapsed;
                return Err(format!(
                    "Too many failed attempts. Please try again in {} minutes.",
                    remaining
                ));
            }
        }

        Ok(())
    }

    /// Record a failed verification attempt
    pub async fn record_failed_attempt(&self, ip: IpAddr) {
        let mut attempts = self.attempts.write().await;
        let now = Utc::now();

        attempts
            .entry(ip)
            .and_modify(|tracker| {
                let elapsed = now
                    .signed_duration_since(tracker.window_start)
                    .num_minutes();

                // Reset counter if window has expired
                if elapsed >= self.window_minutes {
                    tracker.count = 1;
                    tracker.window_start = now;
                } else {
                    tracker.count += 1;
                }
            })
            .or_insert(AttemptTracker {
                count: 1,
                window_start: now,
            });
    }

    /// Reset attempts for an IP address (called on successful verification)
    pub async fn reset_attempts(&self, ip: IpAddr) {
        let mut attempts = self.attempts.write().await;
        attempts.remove(&ip);
    }

    /// Get current attempt count for an IP (for debugging/monitoring)
    #[allow(dead_code)]
    pub async fn get_attempt_count(&self, ip: IpAddr) -> u32 {
        let attempts = self.attempts.read().await;
        attempts.get(&ip).map(|t| t.count).unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_rate_limit_allows_initial_attempts() {
        let limiter = RateLimiter::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        // First 5 attempts should be allowed
        for i in 0..5 {
            assert!(
                limiter.check_rate_limit(ip).await.is_ok(),
                "Attempt {} should be allowed",
                i + 1
            );
            limiter.record_failed_attempt(ip).await;
        }
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_after_max_attempts() {
        let limiter = RateLimiter::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        // Record 5 failed attempts
        for _ in 0..5 {
            limiter.record_failed_attempt(ip).await;
        }

        // 6th attempt should be blocked
        assert!(limiter.check_rate_limit(ip).await.is_err());
    }

    #[tokio::test]
    async fn test_reset_clears_attempts() {
        let limiter = RateLimiter::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        // Record some attempts
        limiter.record_failed_attempt(ip).await;
        limiter.record_failed_attempt(ip).await;
        assert_eq!(limiter.get_attempt_count(ip).await, 2);

        // Reset should clear
        limiter.reset_attempts(ip).await;
        assert_eq!(limiter.get_attempt_count(ip).await, 0);
        assert!(limiter.check_rate_limit(ip).await.is_ok());
    }

    #[tokio::test]
    async fn test_different_ips_tracked_separately() {
        let limiter = RateLimiter::new();
        let ip1 = IpAddr::from_str("127.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.1.1").unwrap();

        // Max out IP1
        for _ in 0..5 {
            limiter.record_failed_attempt(ip1).await;
        }

        // IP1 should be blocked
        assert!(limiter.check_rate_limit(ip1).await.is_err());

        // IP2 should still be allowed
        assert!(limiter.check_rate_limit(ip2).await.is_ok());
    }
}
