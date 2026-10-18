//! Session recordings in asciicast v2 format
//! (<https://docs.asciinema.org/manual/asciicast/v2/>).
//!
//! Input is recorded as `"i"` events, output as `"o"`, resizes as `"r"`.
//! Writes are flushed per event; a write error is returned to the caller,
//! which must end the session (fail closed).
//!
//! * asciicast stores text. Terminal data is decoded as UTF-8; a sequence
//!   split across two chunks is carried over to the next event so it is
//!   not mangled, invalid bytes become U+FFFD. The recording is therefore
//!   faithful for playback but not a byte-exact copy of binary output.
//! * The SHA-256 is computed incrementally while writing, so finishing a
//!   large recording does not read it back into memory.
//! * Each recording has a size limit ([`DEFAULT_MAX_RECORDING`] unless set
//!   otherwise). Hitting it is a write error ([`is_limit_error`]): the
//!   session must be ended, because recording is mandatory.
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha256};

/// Default size limit of one recording file.
pub const DEFAULT_MAX_RECORDING: u64 = 512 * 1024 * 1024;

const LIMIT_MSG: &str = "recording size limit reached";

pub struct Recorder {
    path: PathBuf,
    w: BufWriter<File>,
    sha: Sha256,
    start: Instant,
    bytes: u64,
    limit: u64,
    /// Incomplete trailing UTF-8 sequences of the input / output streams.
    pending_in: Vec<u8>,
    pending_out: Vec<u8>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder").field("path", &self.path).finish()
    }
}

/// True when `e` was returned because the recording reached its limit.
pub fn is_limit_error(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::Other && e.to_string().contains(LIMIT_MSG)
}

/// Split `buf` into the longest valid-or-invalid prefix that can be
/// decoded now and an incomplete UTF-8 tail (at most 3 bytes) to keep.
fn split_utf8_tail(buf: &[u8]) -> usize {
    match std::str::from_utf8(buf) {
        Ok(_) => buf.len(),
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        Err(_) => {
            // Invalid bytes somewhere; only hold back a trailing incomplete
            // sequence (a lead byte followed by too few continuation bytes).
            let n = buf.len();
            for back in 1..=3.min(n) {
                let b = buf[n - back];
                if b & 0xC0 == 0x80 {
                    continue; // continuation byte, look further back
                }
                let need = if b & 0xE0 == 0xC0 {
                    2
                } else if b & 0xF0 == 0xE0 {
                    3
                } else if b & 0xF8 == 0xF0 {
                    4
                } else {
                    return n;
                };
                return if back < need { n - back } else { n };
            }
            n
        }
    }
}

impl Recorder {
    pub fn create(path: &Path, cols: u16, rows: u16, title: &str) -> std::io::Result<Self> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let f = File::create(path)?;
        let mut r = Self {
            path: path.to_path_buf(),
            w: BufWriter::new(f),
            sha: Sha256::new(),
            start: Instant::now(),
            bytes: 0,
            limit: DEFAULT_MAX_RECORDING,
            pending_in: Vec::new(),
            pending_out: Vec::new(),
        };
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": crate::now_ms() / 1000,
            "title": title,
            "env": {"TERM": "xterm-256color"},
        });
        r.line(&header.to_string())?;
        Ok(r)
    }

    /// Set the size limit (bytes of the whole file, header included).
    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }

    fn line(&mut self, line: &str) -> std::io::Result<()> {
        let n = line.len() as u64 + 1;
        if self.bytes + n > self.limit {
            return Err(std::io::Error::other(format!(
                "{LIMIT_MSG} ({} bytes)",
                self.limit
            )));
        }
        self.w.write_all(line.as_bytes())?;
        self.w.write_all(b"\n")?;
        self.w.flush()?;
        self.sha.update(line.as_bytes());
        self.sha.update(b"\n");
        self.bytes += n;
        Ok(())
    }

    fn event(&mut self, code: &str, data: &str) -> std::io::Result<()> {
        let t = self.start.elapsed().as_secs_f64();
        let line = serde_json::to_string(&serde_json::json!([t, code, data]))?;
        self.line(&line)
    }

    fn text(&mut self, code: &str, input: bool, b: &[u8]) -> std::io::Result<()> {
        let pending = if input {
            &mut self.pending_in
        } else {
            &mut self.pending_out
        };
        let mut buf = std::mem::take(pending);
        buf.extend_from_slice(b);
        let cut = split_utf8_tail(&buf);
        let tail = buf.split_off(cut);
        if input {
            self.pending_in = tail;
        } else {
            self.pending_out = tail;
        }
        if buf.is_empty() {
            return Ok(());
        }
        self.event(code, &String::from_utf8_lossy(&buf))
    }

    pub fn output(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.text("o", false, b)
    }

    pub fn input(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.text("i", true, b)
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> std::io::Result<()> {
        self.event("r", &format!("{cols}x{rows}"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes written so far.
    pub fn size(&self) -> u64 {
        self.bytes
    }

    /// Flush and return (path, size, sha256 hex) for the audit record.
    pub fn finish(mut self) -> std::io::Result<(PathBuf, u64, String)> {
        // Whatever incomplete sequence is left is written (lossily).
        for (code, input) in [("i", true), ("o", false)] {
            let rest = std::mem::take(if input {
                &mut self.pending_in
            } else {
                &mut self.pending_out
            });
            if !rest.is_empty() {
                // Best effort: the limit may refuse it; the hash stays exact
                // for what was written.
                let _ = self.event(code, &String::from_utf8_lossy(&rest));
            }
        }
        self.w.flush()?;
        self.w.get_ref().sync_all()?;
        let sha = hex::encode(self.sha.finalize());
        Ok((self.path, self.bytes, sha))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_asciicast() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.cast");
        let mut r = Recorder::create(&p, 80, 24, "t").unwrap();
        r.input(b"ls\r").unwrap();
        r.output(b"a b c\r\n").unwrap();
        r.resize(100, 30).unwrap();
        let (_, size, sha) = r.finish().unwrap();
        let data = std::fs::read(&p).unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(sha, hex::encode(Sha256::digest(&data)), "incremental hash");
        let text = String::from_utf8(data).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        let h: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(h["version"], 2);
        let e: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(e[1], "o");
    }

    #[test]
    fn split_utf8_is_not_mangled() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.cast");
        let mut r = Recorder::create(&p, 80, 24, "t").unwrap();
        let s = "héllo €".as_bytes();
        // Split inside the 3-byte euro sign and inside é.
        r.output(&s[..2]).unwrap();
        r.output(&s[2..8]).unwrap();
        r.output(&s[8..]).unwrap();
        r.output(b"\xff!").unwrap();
        let (_, _, sha) = r.finish().unwrap();
        let data = std::fs::read(&p).unwrap();
        assert_eq!(sha, hex::encode(Sha256::digest(&data)));
        let mut out = String::new();
        for l in String::from_utf8(data).unwrap().lines().skip(1) {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            out.push_str(v[2].as_str().unwrap());
        }
        assert_eq!(out, "héllo €\u{fffd}!");
    }

    #[test]
    fn size_limit_is_enforced() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.cast");
        let mut r = Recorder::create(&p, 80, 24, "t").unwrap().with_limit(4096);
        let chunk = vec![b'x'; 1000];
        let mut err = None;
        for _ in 0..10 {
            if let Err(e) = r.output(&chunk) {
                err = Some(e);
                break;
            }
        }
        let e = err.expect("limit must be hit");
        assert!(is_limit_error(&e), "{e}");
        let (_, size, sha) = r.finish().unwrap();
        assert!(size <= 4096);
        let data = std::fs::read(&p).unwrap();
        assert_eq!(data.len() as u64, size);
        assert_eq!(sha, hex::encode(Sha256::digest(&data)));
    }
}
