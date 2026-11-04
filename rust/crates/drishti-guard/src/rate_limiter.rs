//! Multi-budget rate limiter with atomic token-bucket replenishment and RAII concurrency semaphores.
//!
//! Enforces:
//! 1. Requests-per-second (RPS) rate limits with burst capacity.
//! 2. Active concurrency ceiling across parallel test workers.
//! 3. Per-test request ceilings (retries consume budget).
//! 4. Global session request caps.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Rate limiting and budget configuration.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Token replenish rate in requests per second
    pub requests_per_second: f64,
    /// Maximum burst bucket capacity
    pub burst_capacity: u32,
    /// Maximum simultaneous active HTTP probes
    pub max_concurrency: usize,
    /// Request budget per individual test execution
    pub max_requests_per_test: u32,
    /// Absolute ceiling across the entire testing session
    pub global_request_allowance: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10.0,
            burst_capacity: 15,
            max_concurrency: 5,
            max_requests_per_test: 30,
            global_request_allowance: 500,
        }
    }
}

/// Thread-safe multi-budget rate limiter and concurrency coordinator.
#[derive(Debug, Clone)]
pub struct MultiBudgetRateLimiter {
    config: RateLimiterConfig,
    state: Arc<Mutex<TokenBucketState>>,
    active_concurrency: Arc<AtomicUsize>,
    global_requests_used: Arc<AtomicU32>,
}

#[derive(Debug)]
struct TokenBucketState {
    tokens: f64,
    last_replenish: Instant,
    test_budgets: HashMap<String, u32>,
}

/// RAII concurrency permit that decrements the active concurrency counter on drop.
#[derive(Debug)]
pub struct ConcurrencyPermit {
    active_counter: Arc<AtomicUsize>,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.active_counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl MultiBudgetRateLimiter {
    /// Creates a new rate limiter with the specified configuration.
    pub fn new(config: RateLimiterConfig) -> Self {
        let initial_tokens = config.burst_capacity as f64;
        Self {
            config,
            state: Arc::new(Mutex::new(TokenBucketState {
                tokens: initial_tokens,
                last_replenish: Instant::now(),
                test_budgets: HashMap::new(),
            })),
            active_concurrency: Arc::new(AtomicUsize::new(0)),
            global_requests_used: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Atomically evaluates all budgets and acquires an execution permit.
    pub fn acquire(&self, test_id: &str) -> Result<ConcurrencyPermit, RateLimitError> {
        // 1. Check Global Budget
        let current_global = self.global_requests_used.load(Ordering::SeqCst);
        if current_global >= self.config.global_request_allowance {
            return Err(RateLimitError::GlobalBudgetExhausted {
                limit: self.config.global_request_allowance,
                used: current_global,
            });
        }

        // 2. Check Concurrency Ceiling
        let current_concurrency = self.active_concurrency.load(Ordering::SeqCst);
        if current_concurrency >= self.config.max_concurrency {
            return Err(RateLimitError::ConcurrencyCeilingReached {
                active: current_concurrency,
                max: self.config.max_concurrency,
            });
        }

        // 3. Atomically check Per-Test Budget and Token Bucket
        {
            let mut state = self.state.lock().unwrap();

            // Check Per-Test Budget
            let test_used = state.test_budgets.get(test_id).copied().unwrap_or(0);
            if test_used >= self.config.max_requests_per_test {
                return Err(RateLimitError::TestBudgetExhausted {
                    test_id: test_id.to_string(),
                    limit: self.config.max_requests_per_test,
                });
            }

            // Replenish Tokens
            let now = Instant::now();
            let elapsed = now.duration_since(state.last_replenish).as_secs_f64();
            let added_tokens = elapsed * self.config.requests_per_second;
            state.tokens = (state.tokens + added_tokens).min(self.config.burst_capacity as f64);
            state.last_replenish = now;

            // Check Token Availability
            if state.tokens < 1.0 {
                return Err(RateLimitError::RateThrottled {
                    available: state.tokens,
                });
            }

            // Deduct token & consume budgets
            state.tokens -= 1.0;
            state.test_budgets.insert(test_id.to_string(), test_used + 1);
        }

        // Increment Global & Concurrency
        self.global_requests_used.fetch_add(1, Ordering::SeqCst);
        self.active_concurrency.fetch_add(1, Ordering::SeqCst);

        Ok(ConcurrencyPermit {
            active_counter: Arc::clone(&self.active_concurrency),
        })
    }

    /// Read active concurrent request count.
    pub fn active_concurrency(&self) -> usize {
        self.active_concurrency.load(Ordering::SeqCst)
    }

    /// Read total global requests consumed.
    pub fn global_requests_used(&self) -> u32 {
        self.global_requests_used.load(Ordering::SeqCst)
    }
}

/// Rate limiting and budget errors.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RateLimitError {
    #[error("Rate throttled: insufficient tokens ({available:.2} available)")]
    RateThrottled { available: f64 },
    #[error("Concurrency ceiling reached: {active} active probes (max {max})")]
    ConcurrencyCeilingReached { active: usize, max: usize },
    #[error("Per-test request budget exhausted for '{test_id}' (limit: {limit})")]
    TestBudgetExhausted { test_id: String, limit: u32 },
    #[error("Global testing session allowance exhausted ({used}/{limit} requests used)")]
    GlobalBudgetExhausted { limit: u32, used: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_concurrency_ceiling() {
        let config = RateLimiterConfig {
            max_concurrency: 2,
            ..Default::default()
        };
        let limiter = MultiBudgetRateLimiter::new(config);

        let p1 = limiter.acquire("test-1").unwrap();
        assert_eq!(limiter.active_concurrency(), 1);

        let p2 = limiter.acquire("test-1").unwrap();
        assert_eq!(limiter.active_concurrency(), 2);

        // Third acquisition must fail on concurrency ceiling
        let p3_err = limiter.acquire("test-1");
        assert!(matches!(
            p3_err,
            Err(RateLimitError::ConcurrencyCeilingReached { .. })
        ));

        // Dropping p1 releases permit
        drop(p1);
        assert_eq!(limiter.active_concurrency(), 1);

        // Now p3 succeeds
        let p3 = limiter.acquire("test-1");
        assert!(p3.is_ok());
        drop(p2);
        drop(p3);
    }

    #[test]
    fn test_per_test_budget_exhaustion() {
        let config = RateLimiterConfig {
            max_requests_per_test: 2,
            burst_capacity: 10,
            ..Default::default()
        };
        let limiter = MultiBudgetRateLimiter::new(config);

        let _p1 = limiter.acquire("test-scoped");
        let _p2 = limiter.acquire("test-scoped");

        // Third request on the same test exhausts budget
        let p3 = limiter.acquire("test-scoped");
        assert!(matches!(
            p3,
            Err(RateLimitError::TestBudgetExhausted { .. })
        ));

        // Different test ID still has its own budget
        let p_other = limiter.acquire("other-test");
        assert!(p_other.is_ok());
    }

    #[test]
    fn test_global_budget_exhaustion() {
        let config = RateLimiterConfig {
            global_request_allowance: 2,
            burst_capacity: 10,
            ..Default::default()
        };
        let limiter = MultiBudgetRateLimiter::new(config);

        let _p1 = limiter.acquire("t1");
        let _p2 = limiter.acquire("t2");

        let p3 = limiter.acquire("t3");
        assert!(matches!(
            p3,
            Err(RateLimitError::GlobalBudgetExhausted { .. })
        ));
    }
}
