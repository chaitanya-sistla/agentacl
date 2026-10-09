//! Secrets and admin access: random values, hashes, the admin password,
//! sessions and login throttling.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};

/// PBKDF2-SHA256 work factor for the admin password.
pub const ITERATIONS: u32 = 600_000;
/// Admin sessions last this long.
pub const SESSION_SECS: i64 = 12 * 3600;

/// 32 random bytes, hex.
pub fn random_hex() -> String {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("reading /dev/urandom");
    hex::encode(b)
}

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// HMAC-SHA256 (RFC 2104).
fn hmac_sha256(key: &[u8], msg: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for m in msg {
        inner.update(m);
    }
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// PBKDF2-HMAC-SHA256 (RFC 8018), one 32-byte block.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut u = hmac_sha256(password, &[salt, &1u32.to_be_bytes()]);
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &[&u]);
        out.iter_mut().zip(u).for_each(|(o, x)| *o ^= x);
    }
    out
}

/// `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>`.
pub fn hash_password(password: &str) -> String {
    let salt = random_hex();
    let out = pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), ITERATIONS);
    format!("pbkdf2-sha256${ITERATIONS}${salt}${}", hex::encode(out))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    let [scheme, iters, salt, hash] = parts[..] else { return false };
    let Ok(iters) = iters.parse::<u32>() else { return false };
    if scheme != "pbkdf2-sha256" || iters == 0 {
        return false;
    }
    let out = pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), iters);
    constant_eq(hex::encode(out).as_bytes(), hash.as_bytes())
}

pub fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reads the admin password: from the file named by
/// `AGENTACL_SERVER_ADMIN_PASSWORD_FILE`, else from standard input.
pub fn read_password() -> Result<String> {
    let raw = match std::env::var_os("AGENTACL_SERVER_ADMIN_PASSWORD_FILE") {
        Some(f) => std::fs::read_to_string(&f).with_context(|| format!("reading {}", std::path::Path::new(&f).display()))?,
        None => {
            eprint!("Admin password (input is not hidden; or set AGENTACL_SERVER_ADMIN_PASSWORD_FILE): ");
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            s
        }
    };
    let p = raw.trim_end_matches(['\r', '\n']).to_string();
    anyhow::ensure!(p.chars().count() >= 12, "the admin password must have at least 12 characters");
    Ok(p)
}

/// Slows failed logins per client address: one attempt a second, then
/// doubling after five failures, up to a minute.
#[derive(Default)]
pub struct Throttle {
    failures: HashMap<String, (u32, Instant)>,
}

impl Throttle {
    fn wait_for(n: u32) -> Duration {
        if n < 5 {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(2u64.saturating_pow(n - 4).min(60))
        }
    }

    /// How long `client` must still wait before trying again.
    pub fn blocked(&mut self, client: &str) -> Option<Duration> {
        self.failures.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(3600));
        let (n, t) = self.failures.get(client)?;
        Self::wait_for(*n).checked_sub(t.elapsed())
    }

    pub fn failed(&mut self, client: &str) {
        let e = self.failures.entry(client.to_string()).or_insert((0, Instant::now()));
        e.0 += 1;
        e.1 = Instant::now();
    }

    pub fn succeeded(&mut self, client: &str) {
        self.failures.remove(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_and_pbkdf2_match_published_vectors() {
        // RFC 4231 test case 2.
        assert_eq!(hex::encode(hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"])), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // RFC 4231 test case 6 (a key longer than the block).
        assert_eq!(hex::encode(hmac_sha256(&[0xaa; 131], &[b"Test Using Larger Than Block-Size Key - Hash Key First"])), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        // PBKDF2-HMAC-SHA256 ("password", "salt"), c = 1 and 4096.
        assert_eq!(hex::encode(pbkdf2_sha256(b"password", b"salt", 1)), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        assert_eq!(hex::encode(pbkdf2_sha256(b"password", b"salt", 4096)), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    }

    #[test]
    fn passwords_hash_and_verify() {
        // Fewer iterations would be faster, but this is the stored format.
        let h = hash_password("correct horse battery staple");
        assert!(h.starts_with("pbkdf2-sha256$600000$"));
        assert!(verify_password("correct horse battery staple", &h));
        assert!(!verify_password("correct horse battery stapl", &h));
        assert!(!verify_password("x", "garbage"));
        assert_ne!(hash_password("same password!"), hash_password("same password!"), "salted");
    }

    #[test]
    fn failed_logins_are_slowed() {
        let mut t = Throttle::default();
        assert!(t.blocked("1.2.3.4").is_none());
        t.failed("1.2.3.4");
        assert!(t.blocked("1.2.3.4").is_some());
        assert!(t.blocked("5.6.7.8").is_none(), "per address");
        assert_eq!(Throttle::wait_for(4), Duration::from_secs(1));
        assert_eq!(Throttle::wait_for(6), Duration::from_secs(4));
        assert_eq!(Throttle::wait_for(20), Duration::from_secs(60));
        t.succeeded("1.2.3.4");
        assert!(t.blocked("1.2.3.4").is_none());
    }
}
