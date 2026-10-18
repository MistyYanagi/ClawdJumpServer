//! Tamper-evident audit log.
//!
//! * Every event is stored as the exact JSON body that was hashed:
//!   `hash_n = BLAKE3(hash_{n-1} || body_n)`, with `hash_0 = 0^32`.
//! * Every [`CHECKPOINT_EVERY`] events (and on demand) the current head is
//!   signed with an Ed25519 key, so truncation and rewriting of the whole
//!   tail is detectable too.
//! * Appends are synchronous and durable (`synchronous=FULL`). Callers must
//!   treat an append error as a reason to refuse the audited operation
//!   (fail closed).
#![forbid(unsafe_code)]

pub mod recording;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const CHECKPOINT_EVERY: u64 = 100;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit storage error: {0}")]
    Storage(String),
    #[error("audit log is unavailable (fail-closed)")]
    Unavailable,
}

impl From<rusqlite::Error> for AuditError {
    fn from(e: rusqlite::Error) -> Self {
        AuditError::Storage(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Denied,
    Failure,
    Info,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Denied => "denied",
            Outcome::Failure => "failure",
            Outcome::Info => "info",
        }
    }
}

/// An event to append.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Dotted kind, e.g. `auth.login`, `session.start`, `policy.decision`.
    pub kind: String,
    /// Principal id (or `system`, or `anonymous`).
    pub actor: String,
    /// Object of the action (device id, user id, `host:port`, ...).
    pub target: String,
    pub outcome: Outcome,
    pub session: Option<String>,
    /// Source address, when known.
    pub ip: Option<String>,
    pub data: serde_json::Value,
    /// Marks events that reviewers must look at (full-access use, etc).
    pub highlight: bool,
}

impl Event {
    pub fn new(kind: &str, actor: &str, target: &str, outcome: Outcome) -> Self {
        Self {
            kind: kind.into(),
            actor: actor.into(),
            target: target.into(),
            outcome,
            session: None,
            ip: None,
            data: serde_json::Value::Null,
            highlight: false,
        }
    }

    pub fn session(mut self, s: impl Into<String>) -> Self {
        self.session = Some(s.into());
        self
    }

    pub fn ip(mut self, ip: Option<String>) -> Self {
        self.ip = ip;
        self
    }

    pub fn data(mut self, d: serde_json::Value) -> Self {
        self.data = d;
        self
    }

    pub fn highlight(mut self, h: bool) -> Self {
        self.highlight = h;
        self
    }
}

/// What is hashed and stored. Field order is fixed by the struct; `data`
/// maps serialize with sorted keys, so the encoding is deterministic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub seq: u64,
    /// Unix milliseconds.
    pub ts: i64,
    #[serde(flatten)]
    pub event: Event,
}

impl PartialEq for Event {
    fn eq(&self, o: &Self) -> bool {
        serde_json::to_value(self).ok() == serde_json::to_value(o).ok()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredRecord {
    #[serde(flatten)]
    pub record: Record,
    pub hash: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Query {
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub session: Option<String>,
    pub target: Option<String>,
    pub outcome: Option<String>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub after_seq: Option<u64>,
    pub highlight: Option<bool>,
    /// Free text match on the stored body.
    pub text: Option<String>,
    pub limit: Option<u32>,
    /// Newest first when true (default).
    pub desc: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerifyReport {
    pub ok: bool,
    pub events: u64,
    pub checkpoints: u64,
    pub head: String,
    /// First problem found.
    pub error: Option<String>,
    /// Events after the last checkpoint (not yet covered by a signature).
    pub unsigned_tail: u64,
}

pub struct AuditLog {
    conn: Mutex<Connection>,
    key: SigningKey,
    fail: AtomicBool,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditLog")
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn chain(prev: &[u8; 32], body: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prev);
    h.update(body.as_bytes());
    *h.finalize().as_bytes()
}

fn checkpoint_msg(seq: u64, head: &str) -> Vec<u8> {
    format!("cjs-audit-checkpoint-v1:{seq}:{head}").into_bytes()
}

impl AuditLog {
    /// Open (or create) the log at `path`. `key` signs checkpoints.
    pub fn open(path: &Path, key: SigningKey) -> Result<Self, AuditError> {
        let conn = Connection::open(path)?;
        Self::init(conn, key)
    }

    pub fn open_in_memory(key: SigningKey) -> Result<Self, AuditError> {
        Self::init(Connection::open_in_memory()?, key)
    }

    fn init(conn: Connection, key: SigningKey) -> Result<Self, AuditError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                kind TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT NOT NULL,
                outcome TEXT NOT NULL,
                session TEXT,
                highlight INTEGER NOT NULL,
                body TEXT NOT NULL,
                hash TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS events_kind ON events(kind);
             CREATE INDEX IF NOT EXISTS events_actor ON events(actor);
             CREATE INDEX IF NOT EXISTS events_session ON events(session);
             CREATE TABLE IF NOT EXISTS checkpoints (
                seq INTEGER PRIMARY KEY,
                hash TEXT NOT NULL,
                ts INTEGER NOT NULL,
                pubkey TEXT NOT NULL,
                sig TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            key,
            fail: AtomicBool::new(false),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Simulate (or clear) a storage outage. Used by the conformance suite
    /// to prove that operations fail closed.
    pub fn inject_failure(&self, on: bool) {
        self.fail.store(on, Ordering::SeqCst);
    }

    /// Append an event. Returns its sequence number.
    pub fn append(&self, ev: Event) -> Result<u64, AuditError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuditError::Unavailable);
        }
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction()?;
        let (prev_seq, prev_hash): (u64, [u8; 32]) = tx
            .query_row(
                "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(s, h)| (s, decode32(&h)))
            .unwrap_or((0, [0u8; 32]));
        let seq = prev_seq + 1;
        let rec = Record {
            seq,
            ts: now_ms(),
            event: ev,
        };
        let body = serde_json::to_string(&rec).map_err(|e| AuditError::Storage(e.to_string()))?;
        let hash = hex::encode(chain(&prev_hash, &body));
        tx.execute(
            "INSERT INTO events (seq, ts, kind, actor, target, outcome, session, highlight, body, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                seq as i64,
                rec.ts,
                rec.event.kind,
                rec.event.actor,
                rec.event.target,
                rec.event.outcome.as_str(),
                rec.event.session,
                rec.event.highlight as i64,
                body,
                hash
            ],
        )?;
        if seq % CHECKPOINT_EVERY == 0 {
            Self::write_checkpoint(&tx, &self.key, seq, &hash)?;
        }
        tx.commit()?;
        Ok(seq)
    }

    fn write_checkpoint(tx: &Connection, key: &SigningKey, seq: u64, hash: &str) -> Result<(), AuditError> {
        let sig = key.sign(&checkpoint_msg(seq, hash));
        tx.execute(
            "INSERT OR REPLACE INTO checkpoints (seq, hash, ts, pubkey, sig) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                seq as i64,
                hash,
                now_ms(),
                hex::encode(key.verifying_key().as_bytes()),
                hex::encode(sig.to_bytes())
            ],
        )?;
        Ok(())
    }

    /// Sequence number of the newest event (0 when empty).
    pub fn head_seq(&self) -> Result<u64, AuditError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let seq: Option<i64> = conn
            .query_row("SELECT MAX(seq) FROM events", [], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Sequence number of the newest signed checkpoint (0 when none).
    pub fn last_checkpoint(&self) -> Result<u64, AuditError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let seq: Option<i64> = conn
            .query_row("SELECT MAX(seq) FROM checkpoints", [], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Sign the current head now (e.g. at shutdown or before export).
    pub fn checkpoint(&self) -> Result<Option<u64>, AuditError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuditError::Unavailable);
        }
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let head: Option<(i64, String)> = conn
            .query_row(
                "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match head {
            Some((seq, hash)) => {
                Self::write_checkpoint(&conn, &self.key, seq as u64, &hash)?;
                Ok(Some(seq as u64))
            }
            None => Ok(None),
        }
    }

    pub fn query(&self, q: &Query) -> Result<Vec<StoredRecord>, AuditError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut sql = String::from("SELECT body, hash FROM events WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut add = |cond: &str, v: Box<dyn rusqlite::ToSql>| {
            args.push(v);
            sql.push_str(&format!(" AND {cond} ?{}", args.len()));
        };
        if let Some(v) = &q.kind {
            if let Some(prefix) = v.strip_suffix('*') {
                add("kind LIKE", Box::new(format!("{prefix}%")));
            } else {
                add("kind =", Box::new(v.clone()));
            }
        }
        if let Some(v) = &q.actor {
            add("actor =", Box::new(v.clone()));
        }
        if let Some(v) = &q.session {
            add("session =", Box::new(v.clone()));
        }
        if let Some(v) = &q.target {
            add("target =", Box::new(v.clone()));
        }
        if let Some(v) = &q.outcome {
            add("outcome =", Box::new(v.clone()));
        }
        if let Some(v) = q.since_ms {
            add("ts >=", Box::new(v));
        }
        if let Some(v) = q.until_ms {
            add("ts <", Box::new(v));
        }
        if let Some(v) = q.after_seq {
            add("seq >", Box::new(v as i64));
        }
        if let Some(v) = q.highlight {
            add("highlight =", Box::new(v as i64));
        }
        if let Some(v) = &q.text {
            add("body LIKE", Box::new(format!("%{}%", v.replace('%', ""))));
        }
        let desc = q.desc.unwrap_or(true);
        sql.push_str(if desc {
            " ORDER BY seq DESC"
        } else {
            " ORDER BY seq ASC"
        });
        sql.push_str(&format!(" LIMIT {}", q.limit.unwrap_or(200).min(10_000)));
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter().map(|b| b.as_ref())), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (body, hash) = row?;
            let record: Record =
                serde_json::from_str(&body).map_err(|e| AuditError::Storage(e.to_string()))?;
            out.push(StoredRecord { record, hash });
        }
        Ok(out)
    }

    /// Recompute the whole chain and check every checkpoint signature
    /// against `trusted` (defaults to this log's own key).
    pub fn verify(&self, trusted: Option<&VerifyingKey>) -> Result<VerifyReport, AuditError> {
        let trusted = trusted.copied().unwrap_or_else(|| self.key.verifying_key());
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        verify_conn(&conn, &trusted)
    }

    /// Export events (oldest first) as JSON lines including hashes, plus the
    /// checkpoints, so a third party can verify offline.
    pub fn export_jsonl(&self, w: &mut dyn std::io::Write) -> Result<u64, AuditError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut st = conn.prepare("SELECT body, hash FROM events ORDER BY seq ASC")?;
        let mut rows = st.query([])?;
        let mut n = 0;
        let io = |e: std::io::Error| AuditError::Storage(e.to_string());
        while let Some(r) = rows.next()? {
            let body: String = r.get(0)?;
            let hash: String = r.get(1)?;
            writeln!(
                w,
                "{{\"type\":\"event\",\"hash\":\"{hash}\",\"body\":{}}}",
                serde_json::to_string(&body).unwrap_or_default()
            )
            .map_err(io)?;
            n += 1;
        }
        let mut st = conn.prepare("SELECT seq, hash, pubkey, sig FROM checkpoints ORDER BY seq ASC")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            let hash: String = r.get(1)?;
            let pk: String = r.get(2)?;
            let sig: String = r.get(3)?;
            writeln!(w, "{{\"type\":\"checkpoint\",\"seq\":{seq},\"hash\":\"{hash}\",\"pubkey\":\"{pk}\",\"sig\":\"{sig}\"}}").map_err(io)?;
        }
        Ok(n)
    }

    /// Raw connection access for tamper tests and maintenance tooling.
    pub fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        f(&conn)
    }
}

fn decode32(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(b) = hex::decode(h) {
        if b.len() == 32 {
            out.copy_from_slice(&b);
        }
    }
    out
}

/// Verify an audit database file without opening it for writing.
pub fn verify_file(path: &Path, trusted: &VerifyingKey) -> Result<VerifyReport, AuditError> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    verify_conn(&conn, trusted)
}

/// Index columns stored next to the body. Queries filter on them, so
/// verification checks that each one matches the hashed body.
struct Columns {
    ts: i64,
    kind: String,
    actor: String,
    target: String,
    outcome: String,
    session: Option<String>,
    highlight: i64,
}

impl Columns {
    /// Name of the first column that disagrees with the record.
    fn mismatch(&self, r: &Record) -> Option<&'static str> {
        let e = &r.event;
        if self.ts != r.ts {
            Some("ts")
        } else if self.kind != e.kind {
            Some("kind")
        } else if self.actor != e.actor {
            Some("actor")
        } else if self.target != e.target {
            Some("target")
        } else if self.outcome != e.outcome.as_str() {
            Some("outcome")
        } else if self.session != e.session {
            Some("session")
        } else if self.highlight != e.highlight as i64 {
            Some("highlight")
        } else {
            None
        }
    }
}

/// One stored event as read back for verification.
struct StoredEvent {
    /// Position (database `seq` column, or line order of an export).
    seq: u64,
    body: String,
    hash: String,
    columns: Option<Columns>,
}

/// (hash, pubkey hex, signature hex) of a checkpoint, by sequence number.
type Checkpoints = std::collections::BTreeMap<u64, (String, String, String)>;

fn verify_events(
    checkpoints: &Checkpoints,
    trusted: &VerifyingKey,
    events: &mut dyn Iterator<Item = Result<StoredEvent, AuditError>>,
) -> Result<VerifyReport, AuditError> {
    let mut report = VerifyReport {
        ok: true,
        events: 0,
        checkpoints: checkpoints.len() as u64,
        head: hex::encode([0u8; 32]),
        error: None,
        unsigned_tail: 0,
    };
    let fail = |r: &mut VerifyReport, m: String| {
        if r.error.is_none() {
            r.error = Some(m);
        }
        r.ok = false;
    };
    // Every checkpoint signature must verify with the trusted key.
    for (seq, (h, pk, sig)) in checkpoints {
        let sig_ok = hex::decode(sig)
            .ok()
            .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
            .map(|s| trusted.verify_strict(&checkpoint_msg(*seq, h), &s).is_ok())
            .unwrap_or(false);
        if !sig_ok {
            fail(&mut report, format!("checkpoint {seq}: bad signature"));
        }
        if pk != &hex::encode(trusted.as_bytes()) {
            fail(&mut report, format!("checkpoint {seq}: signed by untrusted key"));
        }
    }
    let mut prev = [0u8; 32];
    let mut expect = 1u64;
    let mut last_cp = 0u64;
    for ev in events {
        let StoredEvent {
            seq,
            body,
            hash,
            columns,
        } = ev?;
        if seq != expect {
            fail(&mut report, format!("event {expect}: missing (found {seq})"));
        }
        match serde_json::from_str::<Record>(&body) {
            Ok(rec) if rec.seq == seq => {
                if let Some(col) = columns.as_ref().and_then(|c| c.mismatch(&rec)) {
                    fail(
                        &mut report,
                        format!("event {seq}: indexed column {col} does not match the body"),
                    );
                }
            }
            _ => fail(
                &mut report,
                format!("event {seq}: body does not match its sequence number"),
            ),
        }
        let h = chain(&prev, &body);
        if hex::encode(h) != hash {
            fail(
                &mut report,
                format!("event {seq}: hash mismatch (content altered)"),
            );
        }
        if let Some((cph, _, _)) = checkpoints.get(&seq) {
            if cph != &hex::encode(h) {
                fail(
                    &mut report,
                    format!("event {seq}: does not match signed checkpoint"),
                );
            }
            last_cp = seq;
        }
        prev = h;
        report.events += 1;
        expect = seq + 1;
    }
    if let Some((&max_cp, _)) = checkpoints.iter().next_back() {
        if max_cp > report.events {
            let n = report.events;
            fail(
                &mut report,
                format!("log truncated: checkpoint {max_cp} beyond last event {n}"),
            );
        }
    }
    report.head = hex::encode(prev);
    report.unsigned_tail = report.events - last_cp.min(report.events);
    Ok(report)
}

fn verify_conn(conn: &Connection, trusted: &VerifyingKey) -> Result<VerifyReport, AuditError> {
    let mut checkpoints = Checkpoints::new();
    {
        let mut st = conn.prepare("SELECT seq, hash, pubkey, sig FROM checkpoints ORDER BY seq")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (s, h, pk, sig) = row?;
            checkpoints.insert(s, (h, pk, sig));
        }
    }
    let mut st = conn.prepare(
        "SELECT seq, body, hash, ts, kind, actor, target, outcome, session, highlight
         FROM events ORDER BY seq",
    )?;
    let rows = st.query_map([], |r| {
        Ok(StoredEvent {
            seq: r.get::<_, i64>(0)? as u64,
            body: r.get(1)?,
            hash: r.get(2)?,
            columns: Some(Columns {
                ts: r.get(3)?,
                kind: r.get(4)?,
                actor: r.get(5)?,
                target: r.get(6)?,
                outcome: r.get(7)?,
                session: r.get(8)?,
                highlight: r.get(9)?,
            }),
        })
    })?;
    let mut it = rows.map(|r| r.map_err(AuditError::from));
    verify_events(&checkpoints, trusted, &mut it)
}

/// Verify an export produced by [`AuditLog::export_jsonl`] offline, against
/// an explicitly supplied (out-of-band pinned) public key. Nothing in the
/// file itself is trusted: the `pubkey` recorded in each checkpoint must
/// equal `trusted`, every signature must verify with it, and the chain is
/// recomputed from the bodies.
pub fn verify_export(
    r: &mut dyn std::io::BufRead,
    trusted: &VerifyingKey,
) -> Result<VerifyReport, AuditError> {
    #[derive(Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Line {
        Event {
            hash: String,
            body: String,
        },
        Checkpoint {
            seq: u64,
            hash: String,
            pubkey: String,
            sig: String,
        },
    }
    let mut events = Vec::new();
    let mut checkpoints = Checkpoints::new();
    let mut line = String::new();
    let mut n = 0u64;
    loop {
        line.clear();
        if r.read_line(&mut line)
            .map_err(|e| AuditError::Storage(e.to_string()))?
            == 0
        {
            break;
        }
        n += 1;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Line>(&line)
            .map_err(|e| AuditError::Storage(format!("line {n}: {e}")))?
        {
            Line::Event { hash, body } => {
                if !checkpoints.is_empty() {
                    return Err(AuditError::Storage(format!("line {n}: event after checkpoints")));
                }
                events.push((hash, body));
            }
            Line::Checkpoint {
                seq,
                hash,
                pubkey,
                sig,
            } => {
                if checkpoints.insert(seq, (hash, pubkey, sig)).is_some() {
                    return Err(AuditError::Storage(format!(
                        "line {n}: duplicate checkpoint {seq}"
                    )));
                }
            }
        }
    }
    // Position in the file is the sequence number the body must carry.
    let mut it = events.into_iter().enumerate().map(|(i, (hash, body))| {
        Ok(StoredEvent {
            seq: i as u64 + 1,
            body,
            hash,
            columns: None,
        })
    });
    verify_events(&checkpoints, trusted, &mut it)
}

/// Parse a hex-encoded Ed25519 public key (as printed by the server).
pub fn parse_public_key(hex_key: &str) -> Result<VerifyingKey, AuditError> {
    let b = hex::decode(hex_key.trim()).map_err(|_| AuditError::Storage("public key is not hex".into()))?;
    let b: [u8; 32] = b
        .try_into()
        .map_err(|_| AuditError::Storage("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&b).map_err(|e| AuditError::Storage(format!("bad public key: {e}")))
}

/// Short fingerprint of an audit public key for out-of-band pinning:
/// the first 16 bytes of SHA-256 over the key, in hex.
pub fn key_fingerprint(key: &VerifyingKey) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(key.as_bytes())[..16])
}

pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> AuditLog {
        AuditLog::open_in_memory(generate_key()).unwrap()
    }

    fn fill(l: &AuditLog, n: usize) {
        for i in 0..n {
            l.append(
                Event::new("test.event", "u1", "d1", Outcome::Success)
                    .data(serde_json::json!({"i": i, "z": 1, "a": 2})),
            )
            .unwrap();
        }
    }

    #[test]
    fn chain_verifies() {
        let l = log();
        fill(&l, 250);
        l.checkpoint().unwrap();
        let r = l.verify(None).unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!(r.events, 250);
        assert_eq!(r.checkpoints, 3);
        assert_eq!(r.unsigned_tail, 0);
    }

    #[test]
    fn modified_body_detected() {
        let l = log();
        fill(&l, 20);
        l.with_conn(|c| {
            c.execute(
                "UPDATE events SET body = replace(body, '\"i\":5', '\"i\":6') WHERE seq = 6",
                [],
            )
            .unwrap();
        });
        let r = l.verify(None).unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("event 6"));
    }

    #[test]
    fn rehashed_rewrite_detected_by_checkpoint() {
        // An attacker who edits an event and recomputes every later hash
        // still cannot forge the checkpoint signature.
        let l = log();
        fill(&l, 120);
        l.with_conn(|c| {
            c.execute(
                "UPDATE events SET body = replace(body, 'u1', 'u2') WHERE seq = 10",
                [],
            )
            .unwrap();
            let mut prev = [0u8; 32];
            let rows: Vec<(i64, String)> = c
                .prepare("SELECT seq, body FROM events ORDER BY seq")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            for (seq, body) in rows {
                prev = chain(&prev, &body);
                c.execute(
                    "UPDATE events SET hash = ?1 WHERE seq = ?2",
                    params![hex::encode(prev), seq],
                )
                .unwrap();
            }
        });
        let r = l.verify(None).unwrap();
        assert!(!r.ok, "{r:?}");
    }

    #[test]
    fn deletion_and_truncation_detected() {
        let l = log();
        fill(&l, 150);
        l.with_conn(|c| c.execute("DELETE FROM events WHERE seq = 50", []).unwrap());
        assert!(!l.verify(None).unwrap().ok);
        let l = log();
        fill(&l, 150);
        l.with_conn(|c| c.execute("DELETE FROM events WHERE seq > 90", []).unwrap());
        let r = l.verify(None).unwrap();
        assert!(!r.ok, "{r:?}");
    }

    #[test]
    fn index_column_tampering_detected() {
        // Queries filter on the index columns; rewriting one (to hide an
        // event from a filtered query) must fail verification even though
        // body and hash are untouched.
        for (col, val) in [
            ("kind", "'other.kind'"),
            ("actor", "'u2'"),
            ("target", "'d2'"),
            ("outcome", "'denied'"),
            ("session", "'s9'"),
            ("highlight", "1"),
            ("ts", "ts + 1"),
        ] {
            let l = log();
            fill(&l, 10);
            l.with_conn(|c| {
                c.execute(&format!("UPDATE events SET {col} = {val} WHERE seq = 4"), [])
                    .unwrap()
            });
            let r = l.verify(None).unwrap();
            assert!(!r.ok, "{col}: {r:?}");
            let e = r.error.unwrap();
            assert!(e.contains("event 4") && e.contains(col), "{col}: {e}");
        }
    }

    fn export(l: &AuditLog) -> String {
        let mut out = Vec::new();
        l.export_jsonl(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn export_verifies_offline_with_pinned_key() {
        let l = log();
        fill(&l, 150);
        l.checkpoint().unwrap();
        let text = export(&l);
        let pk = parse_public_key(&hex::encode(l.verifying_key().as_bytes())).unwrap();
        let r = verify_export(&mut text.as_bytes(), &pk).unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!((r.events, r.checkpoints, r.unsigned_tail), (150, 2, 0));
        assert_eq!(r.head, l.verify(None).unwrap().head);
        // A different (attacker's) key is not accepted, even though the
        // file names its own signer.
        let other = generate_key().verifying_key();
        assert!(!verify_export(&mut text.as_bytes(), &other).unwrap().ok);
    }

    #[test]
    fn export_tampering_detected() {
        let l = log();
        fill(&l, 120);
        l.checkpoint().unwrap();
        let text = export(&l);
        let pk = l.verifying_key();
        // Altered body.
        let t = text.replacen("\\\"i\\\":7", "\\\"i\\\":8", 1);
        assert_ne!(t, text);
        assert!(!verify_export(&mut t.as_bytes(), &pk).unwrap().ok);
        // Dropped event line.
        let t: Vec<&str> = text.lines().collect();
        let t = [&t[..5], &t[6..]].concat().join("\n");
        assert!(!verify_export(&mut t.as_bytes(), &pk).unwrap().ok);
        // Truncated tail (checkpoints kept).
        let (ev, cp): (Vec<&str>, Vec<&str>) = text.lines().partition(|l| l.contains("\"type\":\"event\""));
        let t = [&ev[..90], &cp[..]].concat().join("\n");
        assert!(!verify_export(&mut t.as_bytes(), &pk).unwrap().ok);
    }

    #[test]
    fn tampered_checkpoint_signature_detected() {
        let l = log();
        fill(&l, 100);
        let text = export(&l);
        let pk = l.verifying_key();
        let cp = text
            .lines()
            .find(|l| l.contains("\"type\":\"checkpoint\""))
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(cp).unwrap();
        let sig = v["sig"].as_str().unwrap();
        // Flip one bit of the signature.
        let mut b = hex::decode(sig).unwrap();
        b[10] ^= 1;
        let t = text.replace(sig, &hex::encode(b));
        let r = verify_export(&mut t.as_bytes(), &pk).unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("bad signature"));
        // Same in the database.
        l.with_conn(|c| {
            c.execute("UPDATE checkpoints SET sig = ?1", params![hex::encode([7u8; 64])])
                .unwrap()
        });
        assert!(!l.verify(None).unwrap().ok);
        // A checkpoint re-signed by another key is rejected as well.
        let other = generate_key();
        let head = l.verify(None).unwrap().head;
        let forged = format!(
            "{{\"type\":\"checkpoint\",\"seq\":100,\"hash\":\"{head}\",\"pubkey\":\"{}\",\"sig\":\"{}\"}}",
            hex::encode(other.verifying_key().as_bytes()),
            hex::encode(other.sign(&checkpoint_msg(100, &head)).to_bytes())
        );
        let ev: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("\"type\":\"event\""))
            .collect();
        let t = format!("{}\n{forged}\n", ev.join("\n"));
        assert!(!verify_export(&mut t.as_bytes(), &pk).unwrap().ok);
    }

    #[test]
    fn untrusted_key_detected() {
        let l = log();
        fill(&l, 100);
        let other = generate_key().verifying_key();
        assert!(!l.verify(Some(&other)).unwrap().ok);
    }

    #[test]
    fn fail_closed_on_outage() {
        let l = log();
        l.inject_failure(true);
        assert!(matches!(
            l.append(Event::new("x", "a", "b", Outcome::Info)),
            Err(AuditError::Unavailable)
        ));
        l.inject_failure(false);
        assert_eq!(l.append(Event::new("x", "a", "b", Outcome::Info)).unwrap(), 1);
    }

    #[test]
    fn query_filters() {
        let l = log();
        fill(&l, 5);
        l.append(Event::new("auth.login", "u9", "web", Outcome::Denied).session("s1"))
            .unwrap();
        let r = l
            .query(&Query {
                kind: Some("auth.*".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].record.event.actor, "u9");
        let r = l
            .query(&Query {
                session: Some("s1".into()),
                outcome: Some("denied".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.len(), 1);
        let mut out = Vec::new();
        assert_eq!(l.export_jsonl(&mut out).unwrap(), 6);
    }
}
