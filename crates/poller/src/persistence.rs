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

/// Another process holds the state lock (#441, #442). Returned (inside an
/// `anyhow::Error`) by [`acquire_state_lock`] so callers can tell "already
/// running" apart from I/O failures and report the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLockHeld {
    /// The lock file.
    pub lock_path: PathBuf,
    /// PID recorded by the owner, when it could be read.
    pub pid: Option<u32>,
}

impl std::fmt::Display for StateLockHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(
                f,
                "another TxWatch instance (pid {}) holds the state lock '{}'",
                pid,
                self.lock_path.display()
            ),
            None => write!(
                f,
                "another TxWatch instance holds the state lock '{}'",
                self.lock_path.display()
            ),
        }
    }
}

impl std::error::Error for StateLockHeld {}

/// An exclusive OS advisory lock on `<state path>.lock`, held for as long as
/// this value lives (#441). The lock is released by the OS when the handle is
/// closed — including when the process is killed — so a crash never leaves a
/// stale lock behind (#442). The file itself is never deleted: removing it
/// would let a new instance lock a fresh file while the old one still runs.
#[derive(Debug)]
pub struct StateLock {
    file: Option<fs::File>,
    path: Option<PathBuf>,
}

impl StateLock {
    /// The lock file, or `None` when no state path is configured.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Whether a lock is actually held (a state path is configured).
    pub fn is_held(&self) -> bool {
        self.file.is_some()
    }
}

/// Lock file for a state path: `<state path>.lock`.
pub fn state_lock_path(state_path: &str) -> PathBuf {
    PathBuf::from(format!("{}.lock", state_path))
}

fn read_lock_pid(lock_path: &Path) -> Option<u32> {
    fs::read_to_string(lock_path).ok()?.trim().parse().ok()
}

/// Take the instance lock for `state_path` (see [`AppConfig::state_path`]),
/// failing fast with [`StateLockHeld`] when another process holds it (#441).
/// The owning PID is written into the lock file for diagnostics (#442).
pub fn acquire_state_lock(state_path: Option<&str>) -> Result<StateLock> {
    use std::io::{Seek, SeekFrom, Write};

    let Some(state_path) = state_path else {
        return Ok(StateLock {
            file: None,
            path: None,
        });
    };
    let lock_path = state_lock_path(state_path);
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    // Do not truncate before locking: the file may belong to a running owner.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open lock file '{}'", lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            let pid = read_lock_pid(&lock_path);
            return Err(anyhow::Error::new(StateLockHeld { lock_path, pid }));
        }
        Err(fs::TryLockError::Error(e)) => {
            return Err(e).with_context(|| format!("failed to lock '{}'", lock_path.display()));
        }
    }
    file.set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| writeln!(file, "{}", std::process::id()))
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to record pid in '{}'", lock_path.display()))?;
    Ok(StateLock {
        file: Some(file),
        path: Some(lock_path),
    })
}

pub fn load_state(cfg: &AppConfig) -> StateDocument {
    let path = cfg.state_path();
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
    let path = cfg.state_path();
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

#[derive(Clone)]
pub struct StateHandle {
    sender: Option<tokio::sync::mpsc::UnboundedSender<StateUpdate>>,
}

impl StateHandle {
    pub fn send(&self, update: StateUpdate) {
        if let Some(s) = &self.sender {
            let _ = s.send(update);
        }
    }

    pub async fn flush(&self) {
        tokio::task::yield_now().await;
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
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StateUpdate>();
    let join = tokio::spawn(async move {
        let mut current_doc = StateDocument::default();
        while let Some(update) = rx.recv().await {
            current_doc.cursors.insert(update.cursor_key.clone(), update.cursor);
            current_doc.cooldowns.insert(update.cursor_key.clone(), update.cooldowns);
            current_doc.no_activity.insert(update.cursor_key, update.no_activity);
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
    use std::collections::HashMap;

    fn temp_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "txwatch_persist_{}_{}_{}",
            name,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(state_lock_path(path.to_str().unwrap()));
        path
    }

    fn cfg_with(cursor_file: Option<&Path>, state_file: Option<&Path>) -> AppConfig {
        AppConfig {
            cursor_file: cursor_file.map(|p| p.display().to_string()),
            state_file: state_file.map(|p| p.display().to_string()),
            ..AppConfig::default()
        }
    }

    fn doc_with_cursor(key: &str, cursor: &str) -> StateDocument {
        StateDocument::from_cursors(HashMap::from([(key.to_string(), cursor.to_string())]))
    }

    // ── #440: one state path for loading, saving, writing and locking ─────────

    #[test]
    fn state_path_prefers_state_file_and_falls_back_to_cursor_file() {
        let cursor = Path::new("/tmp/cursors.json");
        let state = Path::new("/tmp/state.json");
        assert_eq!(cfg_with(None, None).state_path(), None);
        assert_eq!(
            cfg_with(Some(cursor), None).state_path(),
            Some("/tmp/cursors.json")
        );
        assert_eq!(
            cfg_with(None, Some(state)).state_path(),
            Some("/tmp/state.json")
        );
        assert_eq!(
            cfg_with(Some(cursor), Some(state)).state_path(),
            Some("/tmp/state.json")
        );
    }

    #[tokio::test]
    async fn writer_and_loader_agree_for_every_setting_combination() {
        for (name, use_cursor, use_state) in [
            ("cursor_only", true, false),
            ("state_only", false, true),
            ("both", true, true),
        ] {
            let cursor_file = temp_path(&format!("{name}_cursor"));
            let state_file = temp_path(&format!("{name}_state"));
            let cfg = cfg_with(
                use_cursor.then_some(cursor_file.as_path()),
                use_state.then_some(state_file.as_path()),
            );
            let expected_file = if use_state { &state_file } else { &cursor_file };

            // What the writer task persists is what the next start loads.
            let writer = spawn_state_writer(cfg.state_path());
            writer.handle().send(StateUpdate {
                cursor_key: "testnet:C1".into(),
                cursor: "4242".into(),
                cooldowns: Default::default(),
                no_activity: Default::default(),
            });
            writer.shutdown().await;

            assert!(
                expected_file.exists(),
                "{name}: state written to the wrong file"
            );
            if use_state && use_cursor {
                assert!(
                    !cursor_file.exists(),
                    "{name}: wrote to cursor_file instead of state_file"
                );
            }
            assert_eq!(
                load_state(&cfg)
                    .cursors
                    .get("testnet:C1")
                    .map(String::as_str),
                Some("4242"),
                "{name}: state written but not restored"
            );

            // save_state and the lock use the same path too.
            save_state(&cfg, &doc_with_cursor("testnet:C1", "5000")).unwrap();
            assert_eq!(
                load_state(&cfg)
                    .cursors
                    .get("testnet:C1")
                    .map(String::as_str),
                Some("5000")
            );
            let lock = acquire_state_lock(cfg.state_path()).unwrap();
            assert_eq!(
                lock.path(),
                Some(state_lock_path(expected_file.to_str().unwrap()).as_path())
            );
            drop(lock);

            for p in [&cursor_file, &state_file] {
                let _ = fs::remove_file(p);
                let _ = fs::remove_file(state_lock_path(p.to_str().unwrap()));
            }
        }
    }

    #[test]
    fn no_state_path_means_no_lock_and_no_file() {
        let lock = acquire_state_lock(None).unwrap();
        assert!(!lock.is_held());
        assert_eq!(lock.path(), None);
    }

    // ── #441: the lock is a real OS lock ──────────────────────────────────────

    #[test]
    fn second_acquire_fails_fast_while_the_lock_is_held() {
        let state = temp_path("held");
        let first = acquire_state_lock(state.to_str()).unwrap();
        assert!(first.is_held());

        let err = acquire_state_lock(state.to_str()).unwrap_err();
        let held = err
            .downcast_ref::<StateLockHeld>()
            .expect("a held lock is reported as StateLockHeld");
        assert_eq!(held.lock_path, state_lock_path(state.to_str().unwrap()));
        assert!(err.to_string().contains("holds the state lock"));

        drop(first);
        // Released on drop: the next instance gets it.
        let again = acquire_state_lock(state.to_str()).unwrap();
        assert!(again.is_held());
        drop(again);
        let _ = fs::remove_file(state_lock_path(state.to_str().unwrap()));
    }

    #[test]
    fn dropping_the_lock_does_not_delete_the_lock_file() {
        let state = temp_path("keep_file");
        let lock_file = state_lock_path(state.to_str().unwrap());
        drop(acquire_state_lock(state.to_str()).unwrap());
        assert!(
            lock_file.exists(),
            "deleting the lock file lets a new instance lock a fresh file while another runs"
        );
        let _ = fs::remove_file(lock_file);
    }

    // ── #442: owner PID and stale lock files ──────────────────────────────────

    #[test]
    fn owner_pid_is_written_to_the_lock_file() {
        let state = temp_path("pid");
        let lock = acquire_state_lock(state.to_str()).unwrap();
        // Windows locks block reads through other handles, so read it back
        // only where the advisory lock allows it.
        #[cfg(unix)]
        {
            let raw = fs::read_to_string(lock.path().unwrap()).unwrap();
            assert_eq!(raw.trim(), std::process::id().to_string());
            let err = acquire_state_lock(state.to_str()).unwrap_err();
            let held = err.downcast_ref::<StateLockHeld>().unwrap();
            assert_eq!(held.pid, Some(std::process::id()));
            assert!(err
                .to_string()
                .contains(&format!("pid {}", std::process::id())));
        }
        drop(lock);
        #[cfg(not(unix))]
        {
            let raw = fs::read_to_string(state_lock_path(state.to_str().unwrap())).unwrap();
            assert_eq!(raw.trim(), std::process::id().to_string());
        }
        let _ = fs::remove_file(state_lock_path(state.to_str().unwrap()));
    }

    #[test]
    fn a_stale_lock_file_left_by_a_crash_does_not_block() {
        let state = temp_path("stale");
        let lock_file = state_lock_path(state.to_str().unwrap());
        // A crashed instance leaves its file (with its PID) but no OS lock.
        fs::write(&lock_file, "999999\n").unwrap();

        let lock = acquire_state_lock(state.to_str()).expect("stale lock file must not block");
        assert!(lock.is_held());
        drop(lock);
        let raw = fs::read_to_string(&lock_file).unwrap();
        assert_eq!(
            raw.trim(),
            std::process::id().to_string(),
            "pid is replaced by the new owner"
        );
        let _ = fs::remove_file(lock_file);
    }
}
