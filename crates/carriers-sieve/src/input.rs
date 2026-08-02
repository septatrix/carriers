//! Turning the command-line file arguments into a flat list of raw RFC 5322 messages to run the
//! policy against. An argument may be a single `.eml` file, a directory of them, or an **mbox**
//! file holding many messages (the format Thunderbird uses for its local folders) — see
//! [`expand`].

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// One message to evaluate, with a human-readable label for output. `label` is the file path for a
/// single-message file, or `path#N` for the N-th message inside an mbox.
pub struct Message {
    pub label: String,
    pub raw: Vec<u8>,
}

/// How to interpret a file argument.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// `.mbox` extension (or a leading `From ` postmark) is treated as mbox, everything else as a
    /// single `.eml` message.
    #[default]
    Auto,
    /// Always a single RFC 5322 message.
    Eml,
    /// Always an mbox holding zero or more messages (mboxrd, as written by Thunderbird).
    Mbox,
}

/// Expand every input path into the messages it contains, in argument order. A path may be:
///
/// - a single `.eml`/message file — one message, labelled by its path;
/// - an mbox file — each contained message, labelled `path#N`;
/// - a directory — each `*.eml` and `*.mbox` file directly inside it (non-recursively, in filename
///   order), other files ignored.
///
/// `format` forces the interpretation of file arguments; directory entries are always
/// auto-detected.
pub fn expand(inputs: &[PathBuf], format: Format) -> Result<Vec<Message>> {
    let mut out = Vec::new();
    for path in inputs {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("reading input {}", path.display()))?;
        if meta.is_dir() {
            expand_dir(path, &mut out)?;
        } else {
            expand_file(path, format, &mut out)?;
        }
    }
    Ok(out)
}

/// Each `*.eml`/`*.mbox` file directly inside `dir`, in filename order (like carriers' own
/// `.d` drop-in directories). Nested directories and other files are ignored. Directory entries
/// are auto-detected regardless of the caller's `--format`.
fn expand_dir(dir: &Path, out: &mut Vec<Message>) -> Result<()> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("eml") | Some("mbox")
                )
        })
        .collect();
    // Filenames share the parent, so sorting the full paths orders them by name.
    paths.sort();
    for path in paths {
        expand_file(&path, Format::Auto, out)?;
    }
    Ok(())
}

fn expand_file(path: &Path, format: Format, out: &mut Vec<Message>) -> Result<()> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let as_mbox = match format {
        Format::Eml => false,
        Format::Mbox => true,
        Format::Auto => is_mbox(path, &data),
    };

    if as_mbox {
        let messages = split_mbox(&data);
        if messages.is_empty() {
            // Declared/looked like mbox but held no postmark — fall back to treating the whole
            // file as a single message rather than silently dropping it.
            out.push(Message {
                label: path.display().to_string(),
                raw: data,
            });
        } else {
            for (i, raw) in messages.into_iter().enumerate() {
                out.push(Message {
                    label: format!("{}#{i}", path.display()),
                    raw,
                });
            }
        }
    } else {
        out.push(Message {
            label: path.display().to_string(),
            raw: data,
        });
    }
    Ok(())
}

/// Auto-detect: a `.mbox` extension, or content beginning with a `From ` postmark, is mbox.
fn is_mbox(path: &Path, data: &[u8]) -> bool {
    if path.extension().and_then(|e| e.to_str()) == Some("mbox") {
        return true;
    }
    if path.extension().and_then(|e| e.to_str()) == Some("eml") {
        return false;
    }
    data.starts_with(b"From ")
}

/// Split an mboxrd file into its constituent raw messages. A message starts at a `From ` postmark
/// line (one not escaped with a leading `>`), and mboxrd body-line escaping (`>From ` → `From `,
/// `>>From ` → `>From `, …) is undone. The postmark lines themselves are dropped.
fn split_mbox(data: &[u8]) -> Vec<Vec<u8>> {
    let mut messages: Vec<Vec<u8>> = Vec::new();
    let mut current: Option<Vec<u8>> = None;

    for line in lines_with_endings(data) {
        if is_postmark(line) {
            if let Some(msg) = current.take() {
                messages.push(trim_trailing_blank(msg));
            }
            current = Some(Vec::new());
        } else if let Some(buf) = current.as_mut() {
            buf.extend_from_slice(unescape_mboxrd(line));
        }
        // Any content before the first postmark is not part of a message and is ignored.
    }
    if let Some(msg) = current.take() {
        messages.push(trim_trailing_blank(msg));
    }
    messages
}

/// Iterate the lines of `data`, each slice including its trailing `\n` (the final line may have
/// none). A `\r` before a `\n` stays part of the line, so CRLF messages round-trip unchanged.
fn lines_with_endings(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut start = 0;
    std::iter::from_fn(move || {
        if start >= data.len() {
            return None;
        }
        let rel = data[start..].iter().position(|&b| b == b'\n');
        let end = match rel {
            Some(i) => start + i + 1, // include the '\n'
            None => data.len(),
        };
        let line = &data[start..end];
        start = end;
        Some(line)
    })
}

/// Whether `line` is an mbox postmark: it begins with `From ` and is not an escaped body line
/// (those begin with `>`). Header lines like `From:` don't match — the required character at
/// index 4 is a space, not a colon.
fn is_postmark(line: &[u8]) -> bool {
    line.starts_with(b"From ")
}

/// Undo one level of mboxrd escaping: a line of the form `>+From ` loses a single leading `>`.
/// Other lines are returned unchanged.
fn unescape_mboxrd(line: &[u8]) -> &[u8] {
    let gts = line.iter().take_while(|&&b| b == b'>').count();
    if gts > 0 && line[gts..].starts_with(b"From ") {
        &line[1..]
    } else {
        line
    }
}

/// Drop the single blank separator line mbox writers place at the end of each message, so the
/// reconstructed message ends at its real last line.
fn trim_trailing_blank(mut msg: Vec<u8>) -> Vec<u8> {
    if msg.ends_with(b"\n") {
        msg.pop();
        if msg.ends_with(b"\r") {
            msg.pop();
        }
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_mbox_and_unescapes() {
        let mbox = b"From alice@example.com Mon Jan  1 00:00:00 2024\r\n\
From: alice@example.com\r\n\
Subject: one\r\n\
\r\n\
>From the desk of alice\r\n\
\r\n\
From bob@example.com Mon Jan  1 00:01:00 2024\r\n\
From: bob@example.com\r\n\
Subject: two\r\n\
\r\n\
body two\r\n";
        let msgs = split_mbox(mbox);
        assert_eq!(msgs.len(), 2);
        let first = String::from_utf8(msgs[0].clone()).unwrap();
        assert!(first.contains("Subject: one"));
        // The escaped body line is unescaped back to a literal "From ".
        assert!(first.contains("From the desk of alice"));
        assert!(!first.contains(">From the desk"));
        let second = String::from_utf8(msgs[1].clone()).unwrap();
        assert!(second.contains("Subject: two"));
        assert!(second.contains("body two"));
    }

    #[test]
    fn header_from_is_not_a_postmark() {
        // A message whose header starts with "From:" must not be split at that header.
        let mbox = b"From env@example.com Mon Jan  1 00:00:00 2024\n\
From: someone@example.com\n\
Subject: hi\n\
\n\
body\n";
        let msgs = split_mbox(mbox);
        assert_eq!(msgs.len(), 1);
        assert!(String::from_utf8(msgs[0].clone()).unwrap().starts_with("From: someone"));
    }
}
