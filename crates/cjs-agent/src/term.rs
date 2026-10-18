//! Interactive terminal client.
use std::io::{Read, Write};
use std::time::Duration;

use cjs_mux::{read_msg, write_msg};
use cjs_proto::{ErrorCode, OpenRequest, ProtoError, PtyIn, PtyOut, MAX_DATA_CHUNK};
use tokio::sync::mpsc;

use crate::local::Opener;

/// Drops OSC 52 ("set clipboard") sequences from terminal output: a
/// compromised device must not be able to plant commands in the user's
/// clipboard. Everything else passes through unchanged. State carries over
/// chunk boundaries.
///
/// Both the 7-bit introducer (`ESC ]`) and the C1 one (`0x9d`, raw or
/// UTF-8 encoded as `C2 9D`) are recognized, and the numeric parameter is
/// compared as a number, so `ESC]052;` is caught too. Dropped sequences end
/// at BEL, `ESC \`, or C1 ST (`0x9c` / `C2 9C`).
#[derive(Debug, Default)]
pub struct OutputFilter {
    st: St,
}

#[derive(Debug, Default)]
enum St {
    #[default]
    Normal,
    Esc,
    /// Saw 0xC2 (possible UTF-8 encoded C1 control).
    C2,
    /// Inside an OSC numeric parameter: bytes seen so far (for replay).
    OscNum(Vec<u8>),
    Drop,
    DropEsc,
    DropC2,
}

/// Longest numeric OSC parameter we buffer before passing it through.
const MAX_OSC_NUM: usize = 16;

fn osc_is_52(buf: &[u8], intro_len: usize) -> bool {
    let digits = &buf[intro_len..];
    !digits.is_empty()
        && digits.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(digits)
            .ok()
            .and_then(|d| d.trim_start_matches('0').parse::<u32>().ok())
            == Some(52)
}

impl OutputFilter {
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &b in input {
            self.st = self.step(b, out);
        }
    }

    fn step(&mut self, b: u8, out: &mut Vec<u8>) -> St {
        match std::mem::take(&mut self.st) {
            St::Normal => self.normal(b, out),
            St::Esc => match b {
                b']' => St::OscNum(vec![0x1b, b']']),
                0x1b => {
                    out.push(0x1b);
                    St::Esc
                }
                _ => {
                    out.extend_from_slice(&[0x1b, b]);
                    St::Normal
                }
            },
            St::C2 => {
                if b == 0x9d {
                    St::OscNum(vec![0xc2, 0x9d])
                } else {
                    out.push(0xc2);
                    self.normal(b, out)
                }
            }
            St::OscNum(mut buf) => {
                let intro = if buf[0] == 0x1b || buf[0] == 0xc2 { 2 } else { 1 };
                if b.is_ascii_digit() && buf.len() < intro + MAX_OSC_NUM {
                    buf.push(b);
                    St::OscNum(buf)
                } else if b == b';' && osc_is_52(&buf, intro) {
                    St::Drop
                } else {
                    out.extend_from_slice(&buf);
                    self.normal(b, out)
                }
            }
            St::Drop => match b {
                0x07 | 0x9c => St::Normal,
                0x1b => St::DropEsc,
                0xc2 => St::DropC2,
                _ => St::Drop,
            },
            St::DropEsc => match b {
                b'\\' => St::Normal,
                0x1b => St::DropEsc,
                _ => St::Drop,
            },
            St::DropC2 => match b {
                0x9c => St::Normal,
                0xc2 => St::DropC2,
                0x1b => St::DropEsc,
                _ => St::Drop,
            },
        }
    }

    fn normal(&mut self, b: u8, out: &mut Vec<u8>) -> St {
        match b {
            0x1b => St::Esc,
            0x9d => St::OscNum(vec![0x9d]),
            0xc2 => St::C2,
            _ => {
                out.push(b);
                St::Normal
            }
        }
    }

    /// Flush bytes held back while looking for a sequence (at end of output).
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        match std::mem::take(&mut self.st) {
            St::Esc => out.push(0x1b),
            St::C2 => out.push(0xc2),
            St::OscNum(buf) => out.extend_from_slice(&buf),
            _ => {}
        }
    }
}

struct RawGuard(bool);

impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.0 {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Terminal size, with a sane default when it is unknown (some ptys
/// report 0x0) and clamped to what the server accepts.
fn size() -> (u16, u16) {
    let (c, r) = crossterm::terminal::size().unwrap_or((80, 24));
    let fix = |v: u16, d: u16| if v == 0 { d } else { v.min(cjs_proto::MAX_TERM_DIM) };
    (fix(c, 80), fix(r, 24))
}

pub fn term_name() -> String {
    std::env::var("TERM")
        .ok()
        .filter(|t| cjs_proto::check_term(t).is_ok())
        .unwrap_or_else(|| "xterm-256color".into())
}

/// Run an interactive session. Returns the remote exit code.
pub async fn shell(
    op: &Opener,
    device: String,
    cwd: Option<String>,
    command: Option<Vec<String>>,
) -> Result<Option<i32>, ProtoError> {
    use std::io::IsTerminal;
    let (cols, rows) = size();
    let req = OpenRequest::Pty {
        device,
        cols,
        rows,
        term: term_name(),
        command,
        cwd,
    };
    let (s, opened) = op.open(&req).await?;
    tracing::debug!(session = %opened.session, "terminal session started");
    let tty = std::io::stdin().is_terminal();
    let _raw = RawGuard(tty && crossterm::terminal::enable_raw_mode().is_ok());
    let (mut r, mut w) = tokio::io::split(s);
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = vec![0u8; MAX_DATA_CHUNK];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if in_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let writer = tokio::spawn(async move {
        let mut last = (cols, rows);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                b = in_rx.recv() => match b {
                    Some(b) => {
                        if write_msg(&mut w, &PtyIn::Input(b)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = tick.tick() => {
                    let now = size();
                    if now != last {
                        last = now;
                        if write_msg(&mut w, &PtyIn::Resize { cols: now.0, rows: now.1 }).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        use tokio::io::AsyncWriteExt;
        let _ = w.shutdown().await;
    });
    let mut filter = OutputFilter::default();
    let mut stdout = std::io::stdout();
    let mut out = Vec::new();
    let code = loop {
        match read_msg::<_, PtyOut>(&mut r).await {
            Ok(Some(PtyOut::Output(b))) => {
                out.clear();
                filter.feed(&b, &mut out);
                let _ = stdout.write_all(&out);
                let _ = stdout.flush();
            }
            Ok(Some(PtyOut::Exit { code })) => break Ok(code),
            Ok(None) => break Err(ProtoError::new(ErrorCode::Io, "session ended unexpectedly")),
            Err(e) => break Err(e),
        }
    };
    writer.abort();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&[u8]]) -> Vec<u8> {
        let mut f = OutputFilter::default();
        let mut out = Vec::new();
        for c in chunks {
            f.feed(c, &mut out);
        }
        out
    }

    #[test]
    fn drops_clipboard_writes_only() {
        assert_eq!(run(&[b"a\x1b]52;c;ZWNobyBoaQ==\x07b"]), b"ab");
        assert_eq!(run(&[b"a\x1b]5", b"2;c;Zm9v\x1b", b"\\b"]), b"ab");
        // Titles and colors pass through.
        assert_eq!(run(&[b"\x1b]0;title\x07x"]), b"\x1b]0;title\x07x");
        assert_eq!(run(&[b"\x1b[31mred\x1b[0m"]), b"\x1b[31mred\x1b[0m");
        assert_eq!(run(&[b"\x1b]521;x\x07"]), b"\x1b]521;x\x07");
    }

    #[test]
    fn catches_variant_encodings() {
        // Leading zeros.
        assert_eq!(run(&[b"a\x1b]052;c;Zm9v\x07b"]), b"ab");
        assert_eq!(run(&[b"a\x1b]0052;c;Zm9v\x1b\\b"]), b"ab");
        // Raw C1 OSC and C1 ST.
        assert_eq!(run(&[b"a\x9d52;c;Zm9v\x9cb"]), b"ab");
        // UTF-8 encoded C1 OSC / ST, split across chunks.
        assert_eq!(run(&[b"a\xc2", b"\x9d52;c;Zm9v\xc2", b"\x9cb"]), b"ab");
        // Ordinary UTF-8 using a C2 lead byte passes through.
        assert_eq!(run(&["x\u{a2}y".as_bytes()]), "x\u{a2}y".as_bytes());
        // OSC 0 via C1 passes.
        assert_eq!(run(&[b"\x9d0;t\x07"]), b"\x9d0;t\x07");
        // Held-back bytes are flushed at the end.
        let mut f = OutputFilter::default();
        let mut out = Vec::new();
        f.feed(b"z\x1b]5", &mut out);
        f.finish(&mut out);
        assert_eq!(out, b"z\x1b]5");
    }
}
