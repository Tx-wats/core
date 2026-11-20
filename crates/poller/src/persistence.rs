//! State persistence for cursors, cooldowns, and NoActivity states.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use txwatch_config::AppConfig;
use txwatch_rules::{CooldownTracker, NoActivityState};

/// Persisted state document containing cursors, cooldowns, and NoActivity states.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct StateDocument {
    #[serde(default)]
    pub cursors: HashMap<String, String>,
    #[serde(default)]
    pub cooldowns: HashMap<String, CooldownTracker>,
    /// NoActivity states keyed by contract name, then by stable rule identity.
    #[serde(default)]
    pub no_activity: HashMap<String, HashMap<String, NoActivityState>>,
}

impl StateDocument {
    pub fn from_cursors(cursors: HashMap<String, String>) -> Self {
        Self {
            cursors,
            cooldowns: HashMap::new(),
            no_activity: HashMap::new(),
        }
    }

    pub fn from_parts(
        cursors: HashMap<String, String>,
        cooldowns: HashMap<String, CooldownTracker>,
        no_activity: HashMap<String, HashMap<String, NoActivityState>>,
    ) -> Self {
        Self {
            cursors,
            cooldowns,
            no_activity,
        }
    }
}

pub struct StateLock(Option<PathBuf>);

impl Drop for StateLock {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn acquire_state_lock(cursor_file: Option<&str>) -> Result<StateLock> {
    let Some(path_str) = cursor_file else {
        return Ok(StateLock(None));
    };
    let lock_path = PathBuf::from(format!("{}.lock", path_str));
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .with_context(|| format!("failed to acquire lock '{}'", lock_path.display()))?;
    Ok(StateLock(Some(lock_path)))
}

pub fn load_state(cfg: &AppConfig) -> StateDocument {
    let Some(path) = state_path(cfg) else {
        return StateDocument::default();
    };
    let Ok(content) = fs::read_to_string(path) else {
        return StateDocument::default();
    };
    // Issue #375: try the legacy cursor-only map first. Every field of
    // `StateDocument` is `#[serde(default)]`, so a legacy map would otherwise
    // parse as an empty document and its cursors would be lost.
    let doc = if let Ok(cursors) = serde_json::from_str::<HashMap<String, String>>(&content) {
        StateDocument::from_cursors(cursors)
    } else if let Ok(doc) = serde_json::from_str::<StateDocument>(&content) {
        doc
    } else {
        StateDocument::default()
    };
    prune_state(cfg, doc)
}

/// Prune persisted tracker entries whose rule no longer exists in the config.
pub fn prune_state(cfg: &AppConfig, mut doc: StateDocument) -> StateDocument {
    let mut valid_contracts: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut valid_rule_hashes: std::collections::HashSet<String> = std::collections::HashSet::new();
    for contract in &cfg.contracts {
        // Issue #375: state is keyed by cursor key, as the writer stores it.
        valid_contracts.insert(contract.cursor_key());
        for rule in &contract.rules {
            valid_rule_hashes.insert(txwatch_rules::rule_identity(rule));
        }
    }

    doc.cooldowns.retain(|key, _| valid_contracts.contains(key));

    doc.no_activity.retain(|contract, states| {
        if !valid_contracts.contains(contract) {
            return false;
        }
        states.retain(|hash, _| valid_rule_hashes.contains(hash));
        !states.is_empty()
    });

    doc
}

pub fn save_state(cfg: &AppConfig, doc: &StateDocument) -> Result<()> {
    let Some(path) = state_path(cfg) else {
        return Ok(());
    };
    write_state_blocking(Path::new(path), doc)
}

/// Write `doc` to `path` atomically and durably: a temp file in the same
/// directory is written and fsynced, then renamed over the target, and the
/// directory is fsynced so the rename itself survives a crash or power loss.
/// An interrupted write therefore leaves the previous file intact rather than
/// an empty or truncated one.
///
/// This is synchronous and must only be called from a blocking context.
pub fn write_state_blocking(path: &Path, doc: &StateDocument) -> Result<()> {
    use std::io::Write;

    let raw = serde_json::to_string_pretty(doc).context("failed to serialize state document")?;
    let tmp = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut file = fs::File::create(&tmp)
        .with_context(|| format!("failed to write state file '{}'", tmp.display()))?;
    file.write_all(raw.as_bytes())
        .with_context(|| format!("failed to write state file '{}'", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to fsync state file '{}'", tmp.display()))?;
    drop(file);
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename state file '{}'", path.display()))?;
    sync_parent_dir(path)?;
    Ok(())
}

/// Fsync the directory containing `path` so a preceding rename is durable.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("failed to fsync directory '{}'", dir.display()))
}

/// Directories cannot be opened for fsync on this platform; the rename is
/// already durable once it returns.
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

/// Merge a single [`StateUpdate`] into the state document already on disk and
/// write the result atomically.
///
/// This is the synchronous counterpart of the background writer task: it lets
/// callers (notably crash-survival tests) persist an update immediately without
/// waiting for the writer task to drain its channel. The on-disk document is
/// re-read first so unrelated keys are preserved.
pub fn write_state_update_blocking(path: &Path, update: &StateUpdate) -> Result<()> {
    let mut doc = if let Ok(content) = fs::read_to_string(path) {
        serde_json::from_str::<StateDocument>(&content).unwrap_or_default()
    } else {
        StateDocument::default()
    };
    doc.cursors
        .insert(update.cursor_key.clone(), update.cursor.clone());
    doc.cooldowns
        .insert(update.cursor_key.clone(), update.cooldowns.clone());
    doc.no_activity
        .insert(update.cursor_key.clone(), update.no_activity.clone());
    write_state_blocking(path, &doc)
}

#[derive(Debug, Clone)]
pub struct StateUpdate {
    pub cursor_key: String,
    pub cursor: String,
    pub cooldowns: CooldownTracker,
    pub no_activity: HashMap<String, NoActivityState>,
}

/// Messages understood by the state writer task.
enum WriterMessage {
    /// Merge one contract's latest state into the document and write it.
    Update(StateUpdate),
    /// Replace the whole document (e.g. the full snapshot taken on shutdown
    /// or reload) and write it.
    Replace(StateDocument),
    /// Acknowledge once every earlier message has been written.
    Flush(tokio::sync::oneshot::Sender<()>),
    /// Stop after every earlier message has been written. Explicit, so
    /// shutdown does not depend on every `StateHandle` clone being dropped.
    Shutdown,
}

#[derive(Clone)]
pub struct StateHandle {
    sender: Option<tokio::sync::mpsc::UnboundedSender<WriterMessage>>,
}

impl StateHandle {
    pub fn send(&self, update: StateUpdate) {
        if let Some(s) = &self.sender {
            let _ = s.send(WriterMessage::Update(update));
        }
    }

    /// Replace the persisted document with `doc`. Issue #438: used for the
    /// shutdown/reload flush so cooldown and NoActivity state are written
    /// alongside every contract's cursor instead of being dropped.
    pub fn replace(&self, doc: StateDocument) {
        if let Some(s) = &self.sender {
            let _ = s.send(WriterMessage::Replace(doc));
        }
    }

    /// Wait until every message sent before this call has been written.
    pub async fn flush(&self) {
        let Some(s) = &self.sender else { return };
        let (tx, rx) = tokio::sync::oneshot::channel();
        if s.send(WriterMessage::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

pub struct StateWriter {
    handle: StateHandle,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl StateWriter {
    pub fn handle(&self) -> StateHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(sender) = self.handle.sender.take() {
            let _ = sender.send(WriterMessage::Shutdown);
        }
        if let Some(join) = self.join_handle.take() {
            let _ = join.await;
        }
    }
}

/// The file the state document is read from and written to: `state_file`,
/// falling back to `cursor_file`. Loading and writing must agree on this.
pub fn state_path(cfg: &AppConfig) -> Option<&str> {
    cfg.state_file.as_deref().or(cfg.cursor_file.as_deref())
}

/// Spawn the single task that owns writes to `state_path`.
///
/// Issue #439: the writer starts from `initial` (the document loaded at
/// startup) rather than an empty document, so the first write after startup
/// keeps every other contract's saved cursor, cooldowns and NoActivity state.
pub fn spawn_state_writer(state_path: Option<&str>, initial: StateDocument) -> StateWriter {
    let Some(path_str) = state_path else {
        return StateWriter {
            handle: StateHandle { sender: None },
            join_handle: None,
        };
    };
    let path = PathBuf::from(path_str);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<WriterMessage>();
    let join = tokio::spawn(async move {
        let mut current_doc = initial;
        while let Some(message) = rx.recv().await {
            match message {
                WriterMessage::Update(update) => {
                    current_doc
                        .cursors
                        .insert(update.cursor_key.clone(), update.cursor);
                    current_doc
                        .cooldowns
                        .insert(update.cursor_key.clone(), update.cooldowns);
                    current_doc
                        .no_activity
                        .insert(update.cursor_key, update.no_activity);
                }
                WriterMessage::Replace(doc) => current_doc = doc,
                WriterMessage::Flush(ack) => {
                    let _ = ack.send(());
                    continue;
                }
                WriterMessage::Shutdown => break,
            }
            let _ = write_state_blocking(&path, &current_doc);
        }
    });
    StateWriter {
        handle: StateHandle { sender: Some(tx) },
        join_handle: Some(join),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "txwatch_persistence_{}_{}_{}.json",
            name,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn read_doc(path: &Path) -> StateDocument {
        serde_json::from_str(&fs::read_to_string(path).expect("state file written"))
            .expect("state file is a StateDocument")
    }

    fn update(key: &str, cursor: &str) -> StateUpdate {
        StateUpdate {
            cursor_key: key.into(),
            cursor: cursor.into(),
            cooldowns: CooldownTracker::new(),
            no_activity: Vec::new(),
        }
    }

    /// Issue #439: with several contracts on disk, the first write after
    /// startup must not drop the contracts that have not advanced yet, even
    /// when the process then crashes without a graceful shutdown.
    #[tokio::test]
    async fn writer_keeps_every_contract_cursor_across_a_crash() {
        let path = temp_state_path("multi_contract_crash");
        let mut loaded = StateDocument::default();
        for (key, cursor) in [
            ("testnet:A", "100"),
            ("testnet:B", "200"),
            ("mainnet:C", "300"),
        ] {
            loaded.cursors.insert(key.into(), cursor.into());
        }
        let mut cooldowns = CooldownTracker::new();
        cooldowns.check("B", "AnyTransaction", 3600, chrono::Utc::now());
        loaded.cooldowns.insert("testnet:B".into(), cooldowns);
        loaded.no_activity.insert(
            "mainnet:C".into(),
            HashMap::from([("rule".to_string(), NoActivityState::default())]),
        );
        write_state_blocking(&path, &loaded).unwrap();

        let writer = spawn_state_writer(path.to_str(), loaded.clone());
        let handle = writer.handle();
        // Only contract A advances before the "crash".
        handle.send(update("testnet:A", "150"));
        handle.flush().await;
        // Crash: the writer task is torn down without a graceful shutdown.
        if let Some(join) = writer.join_handle.as_ref() {
            join.abort();
        }

        let on_disk = read_doc(&path);
        assert_eq!(
            on_disk.cursors.get("testnet:A").map(String::as_str),
            Some("150")
        );
        assert_eq!(
            on_disk.cursors.get("testnet:B").map(String::as_str),
            Some("200")
        );
        assert_eq!(
            on_disk.cursors.get("mainnet:C").map(String::as_str),
            Some("300")
        );
        assert!(
            on_disk.cooldowns.contains_key("testnet:B"),
            "B's cooldowns lost"
        );
        assert!(
            on_disk.no_activity.contains_key("mainnet:C"),
            "C's NoActivity lost"
        );
        let _ = fs::remove_file(&path);
    }

    /// `replace` swaps the whole document and later updates build on it.
    #[tokio::test]
    async fn writer_replace_then_update_keeps_the_replaced_document() {
        let path = temp_state_path("replace");
        let writer = spawn_state_writer(path.to_str(), StateDocument::default());
        let handle = writer.handle();

        let mut full = StateDocument::default();
        full.cursors.insert("testnet:A".into(), "1".into());
        full.cursors.insert("testnet:B".into(), "2".into());
        handle.replace(full);
        handle.send(update("testnet:B", "3"));
        writer.shutdown().await;

        let on_disk = read_doc(&path);
        assert_eq!(
            on_disk.cursors.get("testnet:A").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            on_disk.cursors.get("testnet:B").map(String::as_str),
            Some("3")
        );
        let _ = fs::remove_file(&path);
    }

    /// `flush` returns only after earlier messages are on disk.
    #[tokio::test]
    async fn flush_waits_for_pending_writes() {
        let path = temp_state_path("flush");
        let writer = spawn_state_writer(path.to_str(), StateDocument::default());
        let handle = writer.handle();
        for i in 0..50 {
            handle.send(update("testnet:A", &i.to_string()));
        }
        handle.flush().await;
        assert_eq!(
            read_doc(&path).cursors.get("testnet:A").map(String::as_str),
            Some("49")
        );
        writer.shutdown().await;
        let _ = fs::remove_file(&path);
    }

    /// Without a state path the writer is a no-op and `flush` still returns.
    #[tokio::test]
    async fn writer_without_path_is_a_no_op() {
        let writer = spawn_state_writer(None, StateDocument::default());
        let handle = writer.handle();
        handle.send(update("testnet:A", "1"));
        handle.flush().await;
        writer.shutdown().await;
    }

    /// Shutdown completes even while other `StateHandle` clones are alive
    /// (the reload loop keeps one for the whole run).
    #[tokio::test]
    async fn shutdown_does_not_wait_for_outstanding_handles() {
        let path = temp_state_path("shutdown");
        let writer = spawn_state_writer(path.to_str(), StateDocument::default());
        let outstanding = writer.handle();
        outstanding.send(update("testnet:A", "9"));
        tokio::time::timeout(std::time::Duration::from_secs(5), writer.shutdown())
            .await
            .expect("shutdown hung while a handle clone was alive");
        assert_eq!(
            read_doc(&path).cursors.get("testnet:A").map(String::as_str),
            Some("9")
        );
        drop(outstanding);
        let _ = fs::remove_file(&path);
    }
}
