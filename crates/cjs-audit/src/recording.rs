//! Session recordings in asciicast v2 format
//! (<https://docs.asciinema.org/manual/asciicast/v2/>).
//!
//! Input is recorded as `"i"` events, output as `"o"`, resizes as `"r"`.
//! Writes are flushed per event; a write error is returned to the caller,
//! which must end the session (fail closed).
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha256};

pub struct Recorder {
    path: PathBuf,
    w: BufWriter<File>,
    start: Instant,
    bytes: u64,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder").field("path", &self.path).finish()
    }
}

impl Recorder {
    pub fn create(path: &Path, cols: u16, rows: u16, title: &str) -> std::io::Result<Self> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let f = File::create(path)?;
        let mut w = BufWriter::new(f);
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": crate::now_ms() / 1000,
            "title": title,
            "env": {"TERM": "xterm-256color"},
        });
        writeln!(w, "{header}")?;
        w.flush()?;
        Ok(Self {
            path: path.to_path_buf(),
            w,
            start: Instant::now(),
            bytes: 0,
        })
    }

    fn event(&mut self, code: &str, data: &str) -> std::io::Result<()> {
        let t = self.start.elapsed().as_secs_f64();
        let line = serde_json::to_string(&serde_json::json!([t, code, data]))?;
        self.bytes += line.len() as u64 + 1;
        writeln!(self.w, "{line}")?;
        self.w.flush()
    }

    pub fn output(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.event("o", &String::from_utf8_lossy(b))
    }

    pub fn input(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.event("i", &String::from_utf8_lossy(b))
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> std::io::Result<()> {
        self.event("r", &format!("{cols}x{rows}"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush and return (path, size, sha256 hex) for the audit record.
    pub fn finish(mut self) -> std::io::Result<(PathBuf, u64, String)> {
        self.w.flush()?;
        self.w.get_ref().sync_all()?;
        let data = std::fs::read(&self.path)?;
        let sha = hex::encode(Sha256::digest(&data));
        Ok((self.path, data.len() as u64, sha))
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
        assert!(size > 0 && sha.len() == 64);
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        let h: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(h["version"], 2);
        let e: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(e[1], "o");
    }
}
