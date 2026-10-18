use std::collections::BTreeSet;

use cjs_proto::Action;
use serde::{Deserialize, Serialize};

use crate::net::{NetRule, PortRange};

/// Administrative roles (separation of duties).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Accounts and assets.
    Sysadmin,
    /// Grants and approvals.
    Secadmin,
    /// Read-only audit access.
    Auditor,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Sysadmin => "sysadmin",
            Role::Secadmin => "secadmin",
            Role::Auditor => "auditor",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "sysadmin" => Some(Role::Sysadmin),
            "secadmin" => Some(Role::Secadmin),
            "auditor" => Some(Role::Auditor),
            _ => None,
        }
    }
}

/// Enforce separation of duties: whoever controls authorization must not
/// also be the one reviewing the audit trail.
pub fn validate_roles(roles: &[Role]) -> Result<(), String> {
    if roles.contains(&Role::Secadmin) && roles.contains(&Role::Auditor) {
        return Err("separation of duties: secadmin and auditor cannot be held by the same account".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum Subject {
    /// A user or agent id.
    Principal(String),
    /// A user or agent group id.
    Group(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum Target {
    Device(String),
    DeviceGroup(String),
    /// Egress through the server itself (no device).
    Server,
}

/// Weekly time window, evaluated at `utc_offset_minutes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// 0 = Monday .. 6 = Sunday. Empty = every day.
    #[serde(default)]
    pub days: Vec<u8>,
    /// Minutes since midnight, inclusive.
    pub start_min: u16,
    /// Minutes since midnight, exclusive. May be < start (overnight).
    pub end_min: u16,
    #[serde(default)]
    pub utc_offset_minutes: i32,
}

impl Schedule {
    pub fn contains(&self, now_unix: i64) -> bool {
        use chrono::{Datelike, Timelike};
        let t = now_unix + self.utc_offset_minutes as i64 * 60;
        let Some(dt) = chrono::DateTime::from_timestamp(t, 0) else {
            return false;
        };
        let day = dt.weekday().num_days_from_monday() as u8;
        let minute = (dt.hour() * 60 + dt.minute()) as u16;
        let in_time = if self.start_min <= self.end_min {
            minute >= self.start_min && minute < self.end_min
        } else {
            minute >= self.start_min || minute < self.end_min
        };
        let in_day = self.days.is_empty() || self.days.contains(&day);
        in_time && in_day
    }
}

/// A grant: subject may perform `actions` on `target` within constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub subject: Subject,
    pub target: Target,
    pub actions: BTreeSet<Action>,
    /// Project directories on the device. Required for every device action.
    #[serde(default)]
    pub project_roots: Vec<String>,
    #[serde(default)]
    pub schedule: Option<Schedule>,
    #[serde(default)]
    pub not_before: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Destinations (as seen from the device) allowed for `forward_local`.
    #[serde(default)]
    pub forward_targets: Vec<NetRule>,
    /// Device ports allowed for `forward_remote` listeners.
    #[serde(default)]
    pub remote_ports: Vec<PortRange>,
    /// Destinations allowed for `egress`.
    #[serde(default)]
    pub egress: Vec<NetRule>,
    /// Max concurrent streams of the granted actions for this subject.
    #[serde(default)]
    pub max_sessions: Option<u32>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

impl Grant {
    /// Structural validation before a grant is stored.
    pub fn validate(&self) -> Result<(), String> {
        if self.actions.is_empty() {
            return Err("grant has no actions".into());
        }
        let device_actions = self.actions.iter().any(|a| *a != Action::Egress);
        match &self.target {
            Target::Server => {
                if device_actions {
                    return Err("target `server` only supports the egress action".into());
                }
            }
            _ => {
                if device_actions && self.project_roots.is_empty() {
                    return Err("project_roots is required for device actions".into());
                }
            }
        }
        for r in &self.project_roots {
            if r.trim().is_empty() {
                return Err("empty project root".into());
            }
            if !(r.starts_with('/') || is_windows_abs(r)) {
                return Err(format!("project root must be an absolute path: {r}"));
            }
        }
        if self.actions.contains(&Action::ForwardLocal) && self.forward_targets.is_empty() {
            return Err("forward_local requires forward_targets".into());
        }
        if self.actions.contains(&Action::ForwardRemote) && self.remote_ports.is_empty() {
            return Err("forward_remote requires remote_ports".into());
        }
        if self.actions.contains(&Action::Egress) && self.egress.is_empty() {
            return Err("egress requires egress rules".into());
        }
        for r in self.forward_targets.iter().chain(&self.egress) {
            r.validate()?;
        }
        if let Some(s) = &self.schedule {
            s.validate()?;
        }
        Ok(())
    }
}

impl Schedule {
    /// Reject windows that would silently mean something else (for example
    /// `end_min = 2000` matching the whole day).
    pub fn validate(&self) -> Result<(), String> {
        if self.start_min >= 1440 || self.end_min > 1440 {
            return Err("schedule minutes must be within 0..1440".into());
        }
        if self.start_min == self.end_min {
            return Err("schedule window is empty".into());
        }
        if self.days.iter().any(|d| *d > 6) {
            return Err("schedule days are 0 (Monday) .. 6 (Sunday)".into());
        }
        if self.utc_offset_minutes.abs() > 14 * 60 {
            return Err("utc_offset_minutes must be within ±14 hours".into());
        }
        Ok(())
    }
}

fn is_windows_abs(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Revoked,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Rejected => "rejected",
            ApprovalStatus::Revoked => "revoked",
            ApprovalStatus::Expired => "expired",
        }
    }
}

/// Longest full-access window that can be approved.
pub const MAX_FULL_ACCESS_SECS: i64 = 8 * 3600;

/// A full-access request must be decided within this time; older pending
/// requests can no longer be approved (the need is likely stale).
pub const FULL_ACCESS_PENDING_TTL_SECS: i64 = 24 * 3600;

/// Request to lift the project-root jail and the sandbox for one principal
/// on one device. Needs a second secadmin's approval and always expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullAccess {
    pub id: String,
    pub principal: String,
    pub device: String,
    pub reason: String,
    pub requested_by: String,
    pub duration_secs: i64,
    pub status: ApprovalStatus,
    pub approved_by: Option<String>,
    pub decided_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

impl FullAccess {
    pub fn is_active(&self, now: i64) -> bool {
        self.status == ApprovalStatus::Approved && self.expires_at.map(|e| now < e).unwrap_or(false)
    }

    /// Two-person rule. `principal_owner` is the responsible user when the
    /// principal is an agent.
    pub fn approve(
        &mut self,
        approver: &str,
        approver_roles: &[Role],
        principal_owner: Option<&str>,
        now: i64,
    ) -> Result<(), String> {
        if self.status != ApprovalStatus::Pending {
            return Err(format!("request is {}", self.status.as_str()));
        }
        if now - self.created_at > FULL_ACCESS_PENDING_TTL_SECS {
            return Err("request is older than 24 hours; submit a new one".into());
        }
        if !approver_roles.contains(&Role::Secadmin) {
            return Err("only a secadmin can approve full access".into());
        }
        if approver == self.requested_by {
            return Err("two-person rule: the requester cannot approve their own request".into());
        }
        if approver == self.principal || Some(approver) == principal_owner {
            return Err("two-person rule: the beneficiary cannot approve".into());
        }
        if self.duration_secs <= 0 || self.duration_secs > MAX_FULL_ACCESS_SECS {
            return Err(format!("duration must be between 1s and {MAX_FULL_ACCESS_SECS}s"));
        }
        self.status = ApprovalStatus::Approved;
        self.approved_by = Some(approver.into());
        self.decided_at = Some(now);
        self.expires_at = Some(now + self.duration_secs);
        Ok(())
    }
}

/// Every administrative role is privileged: granting one through the API
/// needs a second person.
pub const PRIVILEGED_ROLES: [Role; 3] = [Role::Sysadmin, Role::Secadmin, Role::Auditor];

/// Roles that must always keep at least one active holder (otherwise
/// approvals or audit review become impossible).
pub const LAST_HOLDER_ROLES: [Role; 2] = [Role::Secadmin, Role::Auditor];

/// Roles in `to` that are not in `from` (what a change would grant).
pub fn added_roles(from: &[Role], to: &[Role]) -> Vec<Role> {
    let mut v: Vec<Role> = to.iter().copied().filter(|r| !from.contains(r)).collect();
    v.sort();
    v.dedup();
    v
}

/// A pending change of a user's roles that grants a privileged role. It
/// takes effect only when a secadmin other than the requester and the
/// target approves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleChange {
    pub id: String,
    pub user_id: String,
    pub user_name: String,
    /// Roles of the user when the change was requested; approval fails if
    /// they changed in the meantime.
    pub from_roles: Vec<Role>,
    /// The complete new role set.
    pub roles: Vec<Role>,
    pub requested_by: String,
    pub status: ApprovalStatus,
    pub decided_by: Option<String>,
    pub decided_at: Option<i64>,
    pub created_at: i64,
}

impl RoleChange {
    /// Two-person rule for privileged roles.
    pub fn approve(&mut self, approver: &str, approver_roles: &[Role], now: i64) -> Result<(), String> {
        if self.status != ApprovalStatus::Pending {
            return Err(format!("request is {}", self.status.as_str()));
        }
        if !approver_roles.contains(&Role::Secadmin) {
            return Err("only a secadmin can approve role changes".into());
        }
        if approver == self.requested_by {
            return Err("two-person rule: the requester cannot approve their own request".into());
        }
        if approver == self.user_id {
            return Err("two-person rule: you cannot approve a change of your own roles".into());
        }
        validate_roles(&self.roles)?;
        self.status = ApprovalStatus::Approved;
        self.decided_by = Some(approver.into());
        self.decided_at = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod role_change_tests {
    use super::*;

    fn rc() -> RoleChange {
        RoleChange {
            id: "rc1".into(),
            user_id: "u_target".into(),
            user_name: "t".into(),
            from_roles: vec![],
            roles: vec![Role::Auditor],
            requested_by: "u_sys".into(),
            status: ApprovalStatus::Pending,
            decided_by: None,
            decided_at: None,
            created_at: 0,
        }
    }

    #[test]
    fn two_person_rule_for_roles() {
        assert!(rc()
            .approve("u_sys", &[Role::Sysadmin, Role::Secadmin], 1)
            .is_err());
        assert!(rc().approve("u_target", &[Role::Secadmin], 1).is_err());
        assert!(rc().approve("u_other", &[Role::Sysadmin], 1).is_err());
        let mut r = rc();
        r.approve("u_sec", &[Role::Secadmin], 5).unwrap();
        assert_eq!(r.status, ApprovalStatus::Approved);
        assert_eq!(r.decided_by.as_deref(), Some("u_sec"));
        assert!(r.approve("u_sec2", &[Role::Secadmin], 6).is_err(), "only once");
        let mut bad = rc();
        bad.roles = vec![Role::Secadmin, Role::Auditor];
        assert!(bad.approve("u_sec", &[Role::Secadmin], 1).is_err());
    }

    #[test]
    fn added_roles_detects_escalation() {
        assert!(added_roles(&[Role::Sysadmin], &[]).is_empty());
        assert_eq!(
            added_roles(&[Role::Sysadmin], &[Role::Sysadmin, Role::Auditor]),
            vec![Role::Auditor]
        );
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn schedules_are_range_checked() {
        let ok = Schedule {
            days: vec![0, 6],
            start_min: 22 * 60,
            end_min: 6 * 60,
            utc_offset_minutes: 480,
        };
        assert!(ok.validate().is_ok());
        for bad in [
            Schedule {
                end_min: 2000,
                ..ok.clone()
            },
            Schedule {
                start_min: 1440,
                ..ok.clone()
            },
            Schedule {
                days: vec![7],
                ..ok.clone()
            },
            Schedule {
                start_min: 60,
                end_min: 60,
                ..ok.clone()
            },
            Schedule {
                utc_offset_minutes: 15 * 60,
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn stale_full_access_requests_cannot_be_approved() {
        let mut f = FullAccess {
            id: "f1".into(),
            principal: "a1".into(),
            device: "d1".into(),
            reason: "r".into(),
            requested_by: "u1".into(),
            duration_secs: 3600,
            status: ApprovalStatus::Pending,
            approved_by: None,
            decided_at: None,
            expires_at: None,
            created_at: 1000,
        };
        let late = 1000 + FULL_ACCESS_PENDING_TTL_SECS + 1;
        assert!(f.clone().approve("u2", &[Role::Secadmin], None, late).is_err());
        assert!(f.approve("u2", &[Role::Secadmin], None, 2000).is_ok());
    }
}
