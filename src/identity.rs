//! When two Hosts are the same machine, and when two Results are the same.
//!
//! Hosts: compare `fqdn` if both have one (ignoring case and a trailing
//! dot), otherwise `ip` if both have one, otherwise `name`. A Host whose IP
//! changed but whose FQDN didn't still matches; two FQDNs never match on IP.
//! Results: the Host, plugin_id, port and protocol.

use serde_json::Value;
use std::collections::HashMap;

fn fqdn(h: &Value) -> Option<String> {
    h.get("fqdn")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
}

fn member<'a>(h: &'a Value, k: &str) -> Option<&'a str> {
    h.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// True when two `host` members name the same machine.
pub fn same_host(a: &Value, b: &Value) -> bool {
    if let (Some(x), Some(y)) = (fqdn(a), fqdn(b)) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (member(a, "ip"), member(b, "ip")) {
        return x == y;
    }
    member(a, "name").unwrap_or_default() == member(b, "name").unwrap_or_default()
}

/// Gives each distinct Host a number, the first match winning, so Results
/// can be keyed. A Host is matched once and remembered by its exact JSON.
#[derive(Default)]
pub struct Hosts {
    known: Vec<Value>,
    cache: HashMap<String, usize>,
}

impl Hosts {
    /// The number of the Host this one matches, adding it if none does.
    pub fn id(&mut self, h: &Value) -> usize {
        self.find(h).unwrap_or_else(|| {
            self.known.push(h.clone());
            let id = self.known.len() - 1;
            self.cache.insert(h.to_string(), id);
            id
        })
    }

    /// The number of a known Host this one matches, if any.
    pub fn find(&mut self, h: &Value) -> Option<usize> {
        let key = h.to_string();
        if let Some(&id) = self.cache.get(&key) {
            return Some(id);
        }
        let id = self.known.iter().position(|k| same_host(k, h))?;
        self.cache.insert(key, id);
        Some(id)
    }
}

/// A Result's key: its Host's number, plugin_id, port and protocol.
pub type Key = (usize, u64, u16, String);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_on_fqdn_then_ip_then_name() {
        let a = json!({"name":"x","ip":"192.0.2.1","fqdn":"Web.Example.test."});
        assert!(same_host(&a, &json!({"name":"y","ip":"192.0.2.9","fqdn":"web.example.test"})));
        assert!(!same_host(&a, &json!({"name":"x","ip":"192.0.2.1","fqdn":"other.example.test"})));
        assert!(same_host(&a, &json!({"name":"z","ip":"192.0.2.1"})));
        assert!(!same_host(&a, &json!({"name":"x","ip":"192.0.2.2"})));
        assert!(same_host(&json!({"name":"agent-1"}), &json!({"name":"agent-1","ip":"192.0.2.3"})));
    }

    #[test]
    fn numbers_hosts_by_first_match() {
        let mut h = Hosts::default();
        let a = h.id(&json!({"name":"a","ip":"192.0.2.1"}));
        let b = h.id(&json!({"name":"b","ip":"192.0.2.2"}));
        assert_ne!(a, b);
        assert_eq!(h.id(&json!({"name":"renamed","ip":"192.0.2.1"})), a);
        assert_eq!(h.find(&json!({"name":"c","ip":"192.0.2.3"})), None);
    }
}
