use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use tempfile::tempdir;

fn write_file(path: &PathBuf, contents: &str) {
    fs::write(path, contents).unwrap();
}

#[test]
fn prune_cursors_keeps_custom_network_cursors() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("txwatch.toml");
    let cursor_path = dir.path().join("cursors.json");

    // Custom network: cursor key is custom@<horizon_url>:<contract_id>
    let contract_id = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
    let toml = format!(
        r#"
poll_interval_seconds = 10
cursor_file = "{}"

[[contracts]]
label = "CustomOne"
contract_id = "{}"
network = {{ horizon_url = "http://localhost:8000" }}

[[contracts.rules]]
type = "AnyTransaction"
"#,
        cursor_path.display().to_string().replace('\\', "\\\\"),
        contract_id
    );
    write_file(&cfg_path, &toml);

    // Write cursors file with a custom-network key
    let custom_key = format!("custom@http://localhost:8000:{}", contract_id);
    let cursors_json = format!(r#"{{"{}":"12345678"}}"#, custom_key);
    write_file(&cursor_path, &cursors_json);

    let mut cmd = Command::cargo_bin("txwatch").unwrap();
    cmd.args(["--config", cfg_path.to_str().unwrap(), "prune-cursors"])
        .assert()
        .success();

    // Cursor should still exist (not pruned)
    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cursor_path).unwrap()).unwrap();
    assert!(after.get(&custom_key).is_some(), "custom cursor pruned: {}", after);
}
