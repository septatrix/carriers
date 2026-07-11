//! Tests for global configuration loading.

use carriers_core::config::Config;

fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

const MINIMAL: &str = r#"
hostname = "mx.lists.example.org"
listen = "127.0.0.1:2400"
db_path = "carriers.db"
lists_dir = "lists"

[smarthost]
host = "127.0.0.1"
"#;

#[test]
fn global_policy_file_defaults_to_a_sibling_named_global_sieve() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(dir.path(), "carriers.toml", MINIMAL);
    let global_path = write(dir.path(), "global.sieve", "discard;\n");

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.global_policy_file, Some(global_path));
}

#[test]
fn global_policy_file_is_unset_without_a_sibling_or_explicit_path() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(dir.path(), "carriers.toml", MINIMAL);

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.global_policy_file, None);
}

#[test]
fn explicit_global_policy_file_overrides_the_sibling_default() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "global.sieve", "discard;\n");
    let elsewhere = write(dir.path(), "elsewhere.sieve", "discard;\n");
    // `global_policy_file` must precede the `[smarthost]` table, or TOML would attribute it to
    // that table instead of the document root.
    let config_path = write(
        dir.path(),
        "carriers.toml",
        &format!(
            "global_policy_file = \"{}\"\n{MINIMAL}",
            elsewhere.display()
        ),
    );

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.global_policy_file, Some(elsewhere));
}
