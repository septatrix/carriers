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
fn sieve_scripts_defaults_to_a_sibling_directory() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(dir.path(), "carriers.toml", MINIMAL);
    let sieve_scripts = dir.path().join("sieve_scripts");
    std::fs::create_dir_all(&sieve_scripts).unwrap();

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.sieve_scripts, Some(sieve_scripts));
}

#[test]
fn sieve_scripts_is_unset_without_a_sibling_or_explicit_path() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(dir.path(), "carriers.toml", MINIMAL);

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.sieve_scripts, None);
}

#[test]
fn an_explicit_sieve_scripts_path_overrides_the_sibling_default() {
    let dir = tempfile::tempdir().unwrap();
    // A sibling `sieve_scripts` dir exists, but an explicit path must win over it.
    std::fs::create_dir_all(dir.path().join("sieve_scripts")).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    // `sieve_scripts` is a top-level key, so it must appear before any `[table]` header (a bare
    // key after `[smarthost]` would be attributed to that table).
    let toml = format!(
        "hostname = \"mx.lists.example.org\"\n\
         listen = \"127.0.0.1:2400\"\n\
         db_path = \"carriers.db\"\n\
         lists_dir = \"lists\"\n\
         sieve_scripts = \"{}\"\n\
         \n\
         [smarthost]\n\
         host = \"127.0.0.1\"\n",
        elsewhere.display()
    );
    let config_path = write(dir.path(), "carriers.toml", &toml);

    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.sieve_scripts, Some(elsewhere));
}
