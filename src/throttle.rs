//! Per-IP limiting of failed `AUTH` attempts. Laravel does not rate-limit the
//! credentials endpoint, so this is the only brake on password guessing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_TRACKED_IPS: usize = 10_000;
const MAX_DELAY_STEPS: u32 = 5;

pub struct AuthThrottle {
    max_failures: u32,
    window: Duration,
    delay_step: Duration,
    state: Mutex<HashMap<IpAddr, Entry>>,
}

struct Entry {
    failures: u32,
    window_start: Instant,
}

impl AuthThrottle {
    pub fn new(max_failures: u32, window: Duration, delay_step: Duration) -> Self {
        Self { max_failures, window, delay_step, state: Mutex::new(HashMap::new()) }
    }

    /// True once an IP has used up its failures for the current window.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let state = self.state.lock().unwrap();
        state
            .get(&ip)
            .is_some_and(|e| e.window_start.elapsed() < self.window && e.failures >= self.max_failures)
    }

    /// Records a failure and returns how long to stall before answering.
    pub fn record_failure(&self, ip: IpAddr) -> Duration {
        let mut state = self.state.lock().unwrap();
        if state.len() >= MAX_TRACKED_IPS {
            let window = self.window;
            state.retain(|_, e| e.window_start.elapsed() < window);
        }
        let entry = state.entry(ip).or_insert_with(|| Entry { failures: 0, window_start: Instant::now() });
        if entry.window_start.elapsed() >= self.window {
            *entry = Entry { failures: 0, window_start: Instant::now() };
        }
        entry.failures += 1;
        self.delay_step * entry.failures.min(MAX_DELAY_STEPS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_per_ip() {
        let t = AuthThrottle::new(3, Duration::from_secs(60), Duration::from_millis(10));
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..2 {
            t.record_failure(a);
            assert!(!t.is_blocked(a));
        }
        assert_eq!(t.record_failure(a), Duration::from_millis(30));
        assert!(t.is_blocked(a));
        assert!(!t.is_blocked(b));
    }

    #[test]
    fn window_expiry_unblocks() {
        let t = AuthThrottle::new(1, Duration::ZERO, Duration::ZERO);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        t.record_failure(a);
        assert!(!t.is_blocked(a));
    }
}
