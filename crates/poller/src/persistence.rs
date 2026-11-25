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
    let path = cfg.state_file.as_deref().or(cfg.cursor_file.as_deref());
    let Some(path) = path else {
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
    let path = cfg.state_file.as_deref().or(cfg.cursor_file.as_deref());
    let Some(path) = path else {
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
    
    // Issue #444: use a unique temp file name to prevent collisions between
    // concurrent writers (async state writer, save_cursors, reload migration, etc.)
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
    
    let mut temp_file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temp file in '{}'", parent.display()))?;
    
    temp_file.write_all(raw.as_bytes())
        .with_context(|| format!("failed to write temp state file"))?;
    temp_file.sync_all()
        .with_context(|| format!("failed to fsync temp state file"))?;
    
    temp_file.persist(path)
        .with_context(|| format!("failed to rename state file to '{}'", path.display()))?;
    
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

enum StateCommand {
    Update(StateUpdate),
    Flush(tokio::sync::oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct StateHandle {
    sender: Option<tokio::sync::mpsc::UnboundedSender<StateCommand>>,
}

impl StateHandle {
    pub fn send(&self, update: StateUpdate) {
        if let Some(s) = &self.sender {
            let _ = s.send(StateCommand::Update(update));
        }
    }

    /// Issue #446: flush now waits for the writer to actually persist the latest state.
    /// Returns once the file on disk contains all updates sent before this call.
    pub async fn flush(&self) {
        let Some(sender) = &self.sender else {
            return;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = sender.send(StateCommand::Flush(tx));
        let _ = rx.await;
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
        self.handle.sender.take();
        if let Some(join) = self.join_handle.take() {
            let _ = join.await;
        }
    }
}

pub fn spawn_state_writer(cursor_file: Option<&str>) -> StateWriter {
    let Some(path_str) = cursor_file else {
        return StateWriter {
            handle: StateHandle { sender: None },
            join_handle: None,
        };
    };
    let path = PathBuf::from(path_str);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StateCommand>();
    let join = tokio::spawn(async move {
        let mut current_doc = StateDocument::default();
        let mut pending_flushes: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();
        
        while let Some(cmd) = rx.recv().await {
            match cmd {
                StateCommand::Update(update) => {
                    // Apply this update to the in-memory document
                    current_doc.cursors.insert(update.cursor_key.clone(), update.cursor);
                    current_doc.cooldowns.insert(update.cursor_key.clone(), update.cooldowns);
                    current_doc.no_activity.insert(update.cursor_key, update.no_activity);
                }
                StateCommand::Flush(ack) => {
                    pending_flushes.push(ack);
                }
            }
            
            // Issue #446: batch queued updates by draining the channel with try_recv
            loop {
                match rx.try_recv() {
                    Ok(StateCommand::Update(update)) => {
                        current_doc.cursors.insert(update.cursor_key.clone(), update.cursor);
                        current_doc.cooldowns.insert(update.cursor_key.clone(), update.cooldowns);
                        current_doc.no_activity.insert(update.cursor_key, update.no_activity);
                    }
                    Ok(StateCommand::Flush(ack)) => {
                        pending_flushes.push(ack);
                    }
                    Err(_) => break, // channel is empty, write the batched updates now
                }
            }
            
            // Issue #446: run the write in spawn_blocking to avoid blocking Tokio workers
            let doc_clone = current_doc.clone();
            let path_clone = path.clone();
            let write_result = tokio::task::spawn_blocking(move || {
                write_state_blocking(&path_clone, &doc_clone)
            }).await;
            
            // Issue #445: log write errors instead of silently discarding them
            match write_result {
                Ok(Ok(())) => {
                    // Write succeeded, acknowledge all pending flushes
                    for ack in pending_flushes.drain(..) {
                        let _ = ack.send(());
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!("failed to persist state to '{}': {:?}", path.display(), e);
                    // Drop the flush acknowledgements; flush callers will see a closed channel
                    pending_flushes.clear();
                }
                Err(e) => {
                    tracing::error!("state writer task panicked: {:?}", e);
                    pending_flushes.clear();
                }
            }
        }
    });
    StateWriter {
        handle: StateHandle { sender: Some(tx) },
        join_handle: Some(join),
    }
}
