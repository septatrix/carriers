//! Tests for global configuration loading.

use carriers_core::config::Config;

fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

/// Create a `.d` drop-in directory named `name` under `dir` (with one script inside so it isn't
/// empty), returning its path.
fn dropin_dir(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("10-x.sieve"), "keep;\n").unwrap();
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
fn global_before_and_after_default_to_sibling_dropin_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(dir.path(), "carriers.toml", MINIMAL);
    let before_path = dropin_dir(dir.path(), "global-before.d");
    let after_path = dropin_dir(dir.path(), "global-after.d");

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.global_policy.before, Some(before_path));
    assert_eq!(config.global_policy.after, Some(after_path));
}

#[test]
fn global_before_and_after_are_unset_without_a_sibling_or_explicit_path() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(dir.path(), "carriers.toml", MINIMAL);

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.global_policy.before, None);
    assert_eq!(config.global_policy.after, None);
    assert!(config.global_policy.domains.is_empty());
}

#[test]
fn explicit_global_policy_overrides_the_sibling_defaults() {
    let dir = tempfile::tempdir().unwrap();
    dropin_dir(dir.path(), "global-before.d");
    dropin_dir(dir.path(), "global-after.d");
    let before = dropin_dir(dir.path(), "elsewhere-before.d");
    let after = dropin_dir(dir.path(), "elsewhere-after.d");
    // A `[table]` must come after all of `MINIMAL`'s bare top-level keys (and its own
    // `[smarthost]` table), or TOML would attribute those bare keys to whichever table
    // immediately precedes them instead of the document root.
    let config_path = write(
        dir.path(),
        "carriers.toml",
        &format!(
            "{MINIMAL}\n[global_policy]\nbefore = \"{}\"\nafter = \"{}\"\n",
            before.display(),
            after.display()
        ),
    );

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.global_policy.before, Some(before));
    assert_eq!(config.global_policy.after, Some(after));
}

#[test]
fn per_domain_scripts_are_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let before = dropin_dir(dir.path(), "domain-before.d");
    let after = dropin_dir(dir.path(), "domain-after.d");
    let config_path = write(
        dir.path(),
        "carriers.toml",
        &format!(
            "{MINIMAL}\n[global_policy.domains.\"lists.example.com\"]\nbefore = \"{}\"\nafter = \"{}\"\n",
            before.display(),
            after.display()
        ),
    );

    let config = Config::load(&config_path).unwrap();
    let scoped = config
        .global_policy
        .domains
        .get("lists.example.com")
        .unwrap();
    assert_eq!(scoped.before, Some(before));
    assert_eq!(scoped.after, Some(after));
}
