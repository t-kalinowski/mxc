// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, OnceLock};

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenStatistics, TOKEN_QUERY, TOKEN_STATISTICS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::mxc_common::models::ContainerPolicy;
use crate::mxc_common::process_util::OwnedHandle;

use super::MAX_CHANGE_TEXT_BYTES;

pub(super) const REUSED_CHANGE_PREFIX: &str = "Policy mutation cache reused: ";
const MAX_ENTRIES: usize = 16;
const MAX_RETAINED_BYTES: usize = 4 * MAX_CHANGE_TEXT_BYTES;

type Creator = [(u32, i32); 4];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Key {
    policy: [u8; 32],
    creator: Creator,
}

pub(super) struct Entry {
    key: Key,
    pub policy: ContainerPolicy,
    pub proxy_enabled: bool,
    pub changes: Vec<String>,
    retained_bytes: usize,
}

#[derive(Default)]
pub(super) struct Cache {
    entries: VecDeque<Entry>,
    retained_bytes: usize,
}

impl Cache {
    pub fn get(&self, key: Key) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.key == key)
    }

    pub fn remember(
        &mut self,
        key: Key,
        policy: &ContainerPolicy,
        changes: &[String],
    ) -> Result<(), String> {
        if changes.is_empty() {
            return Ok(());
        }
        if creator()? != key.creator {
            return Err("the caller identity changed during negotiation".into());
        }
        let rendered_bytes = changes
            .iter()
            .map(|change| REUSED_CHANGE_PREFIX.len().saturating_add(change.len()))
            .fold(0usize, usize::saturating_add);
        if rendered_bytes > MAX_CHANGE_TEXT_BYTES {
            return Err("the reusable mutation descriptions exceed the text limit".into());
        }
        let mut remembered = policy.clone();
        let proxy_enabled = remembered.network_proxy.is_enabled();
        // Reuse only proxy intent, never credentials or endpoint metadata.
        remembered.network_proxy = Default::default();
        let retained_bytes = serde_json::to_vec(&remembered)
            .map_err(|error| format!("cannot measure the remembered policy: {error}"))?
            .len()
            .saturating_add(rendered_bytes)
            .saturating_add(std::mem::size_of::<Entry>());
        if retained_bytes > MAX_RETAINED_BYTES {
            return Err("the remembered policy exceeds the in-process cache budget".into());
        }
        if let Some(index) = self.entries.iter().position(|entry| entry.key == key) {
            if let Some(previous) = self.entries.remove(index) {
                self.retained_bytes -= previous.retained_bytes;
            }
        }
        self.entries.push_front(Entry {
            key,
            policy: remembered,
            proxy_enabled,
            changes: changes.to_vec(),
            retained_bytes,
        });
        self.retained_bytes += retained_bytes;
        while self.entries.len() > MAX_ENTRIES || self.retained_bytes > MAX_RETAINED_BYTES {
            if let Some(entry) = self.entries.pop_back() {
                self.retained_bytes -= entry.retained_bytes;
            }
        }
        Ok(())
    }
}

pub(super) fn shared() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

pub(super) fn lock<'a>(
    cache: &'a Mutex<Cache>,
    warnings: &mut Vec<String>,
) -> MutexGuard<'a, Cache> {
    match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            // This is disposable optimization state, not a cached policy approval.
            let mut guard = poisoned.into_inner();
            *guard = Cache::default();
            cache.clear_poison();
            warnings.push(
                "Policy mutation cache reset after an interrupted negotiation; \
                 Windows will evaluate this creation again."
                    .into(),
            );
            guard
        }
    }
}

pub(super) fn key(policy: &ContainerPolicy) -> Result<Key, String> {
    let proxy = policy
        .network_proxy
        .address
        .as_ref()
        .map(|address| (&address.address, address.port, &address.original_url));
    let input = serde_json::to_vec(&(
        policy,
        proxy,
        policy.network_specified,
        policy.network_mode_specified,
        policy.runtime_network_proxy_specified,
        policy.ui_specified,
    ))
    .map_err(|error| format!("cannot identify the requested policy: {error}"))?;
    Ok(Key {
        policy: Sha256::digest(input).into(),
        creator: creator()?,
    })
}

fn token_identity(token: HANDLE) -> Result<[(u32, i32); 2], String> {
    let mut statistics = TOKEN_STATISTICS::default();
    let mut written = 0;
    let size = std::mem::size_of::<TOKEN_STATISTICS>() as u32;
    // SAFETY: token is an owned query-capable handle; storage is
    // writable and sized for the requested fixed TOKEN_STATISTICS structure.
    unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            Some((&mut statistics as *mut TOKEN_STATISTICS).cast()),
            size,
            &mut written,
        )
    }
    .map_err(|error| format!("cannot query the caller token: {error}"))?;
    if written != size {
        return Err("the caller token query returned an invalid size".into());
    }
    Ok([
        (statistics.TokenId.LowPart, statistics.TokenId.HighPart),
        (
            statistics.ModifiedId.LowPart,
            statistics.ModifiedId.HighPart,
        ),
    ])
}

fn creator() -> Result<Creator, String> {
    let mut process = HANDLE::default();
    // SAFETY: current process is valid and output points to writable handle storage.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process) }
        .map_err(|error| format!("cannot open the creator process token: {error}"))?;
    let process = OwnedHandle::new(process);
    let mut thread = HANDLE::default();
    // SAFETY: current thread is valid; request query access only, checked as self.
    let thread = match unsafe {
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut thread)
    } {
        Ok(()) => Some(OwnedHandle::new(thread)),
        Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_NO_TOKEN.0) => None,
        Err(error) => return Err(format!("cannot open the effective creator token: {error}")),
    };
    let process = token_identity(process.get())?;
    let effective = match thread {
        Some(thread) => token_identity(thread.get())?,
        None => process,
    };
    Ok([process[0], process[1], effective[0], effective[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_cache_keys_partition_policy_and_caller_and_bound_retained_entries() {
        let mut cache = Cache::default();
        let policy = ContainerPolicy::default();
        let first = key(&policy).unwrap();
        let change = vec!["synthetic restrictive change".into()];
        cache.remember(first, &policy, &change).unwrap();
        let mut other = first;
        other.creator[0].0 ^= 1;
        assert!(cache.get(other).is_none());
        for index in 1..=MAX_ENTRIES {
            let mut next = first;
            next.policy[0] ^= index as u8;
            cache.remember(next, &policy, &change).unwrap();
        }
        assert_eq!(cache.entries.len(), MAX_ENTRIES);
        assert!(cache.get(first).is_none());
        assert!(cache.retained_bytes <= MAX_RETAINED_BYTES);
    }

    #[test]
    fn mutation_cache_rejects_oversized_state_without_losing_a_valid_entry() {
        let mut cache = Cache::default();
        let policy = ContainerPolicy::default();
        let first = key(&policy).unwrap();
        cache
            .remember(first, &policy, &["retained".into()])
            .unwrap();
        let changes = vec!["x".repeat(MAX_CHANGE_TEXT_BYTES)];
        assert!(cache.remember(first, &policy, &changes).is_err());
        assert_eq!(cache.get(first).unwrap().changes, ["retained"]);
        let mut large = policy;
        large.enumerate_paths = vec!["x".repeat(MAX_RETAINED_BYTES)];
        assert!(cache
            .remember(first, &large, &["small change".into()])
            .is_err());
        assert_eq!(cache.get(first).unwrap().changes, ["retained"]);
    }

    #[test]
    fn mutation_cache_recovers_by_discarding_interrupted_optimization_state() {
        let cache = std::sync::Arc::new(Mutex::new(Cache::default()));
        let writer = cache.clone();
        assert!(std::thread::spawn(move || {
            let _guard = writer.lock().unwrap();
            panic!("interrupt cache ownership");
        })
        .join()
        .is_err());
        let mut warnings = Vec::new();
        let guard = lock(&cache, &mut warnings);
        assert!(guard.entries.is_empty());
        assert!(!cache.is_poisoned());
        assert!(warnings[0].contains("cache reset"));
    }
}
