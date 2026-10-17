//! Policy decision point. Default deny.
use cjs_proto::{Action, ErrorCode};

use crate::model::{FullAccess, Grant, Subject, Target};
use crate::net;

#[derive(Clone)]
pub struct AccessRequest<'a> {
    pub principal: &'a str,
    /// Groups of the principal (user or agent groups).
    pub principal_groups: &'a [String],
    /// `None` for egress through the server.
    pub device: Option<&'a str>,
    pub device_groups: &'a [String],
    pub action: Action,
    /// Destination for forward_local / egress, bind for forward_remote.
    pub net: Option<(&'a str, u16)>,
    /// Currently open streams of this principal per grant id.
    pub active: &'a dyn Fn(&str) -> u32,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allow: bool,
    pub code: Option<ErrorCode>,
    pub reason: String,
    pub grant_ids: Vec<String>,
    pub roots: Vec<String>,
    pub full_access: Option<String>,
    /// Egress rules of the matching grants, for the post-DNS IP check.
    pub egress_rules: Vec<net::NetRule>,
}

impl Decision {
    fn deny(code: ErrorCode, reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            code: Some(code),
            reason: reason.into(),
            grant_ids: vec![],
            roots: vec![],
            full_access: None,
            egress_rules: vec![],
        }
    }
}

fn subject_matches(s: &Subject, req: &AccessRequest) -> bool {
    match s {
        Subject::Principal(p) => p == req.principal,
        Subject::Group(g) => req.principal_groups.iter().any(|x| x == g),
    }
}

fn target_matches(t: &Target, req: &AccessRequest) -> bool {
    match (t, req.device) {
        (Target::Device(d), Some(dev)) => d == dev,
        (Target::DeviceGroup(g), Some(_)) => req.device_groups.iter().any(|x| x == g),
        (Target::Server, None) => true,
        _ => false,
    }
}

fn is_loopback_name(h: &str) -> bool {
    let h = h.trim_matches(|c| c == '[' || c == ']');
    h == "localhost"
        || h.parse::<std::net::IpAddr>()
            .map(|i| i.is_loopback())
            .unwrap_or(false)
}

/// Decide a request against all grants and full-access approvals.
pub fn decide(req: &AccessRequest, grants: &[Grant], full: &[FullAccess]) -> Decision {
    let target_desc = req.device.unwrap_or("server");
    let applicable: Vec<&Grant> = grants
        .iter()
        .filter(|g| g.enabled)
        .filter(|g| subject_matches(&g.subject, req))
        .filter(|g| target_matches(&g.target, req))
        .filter(|g| g.actions.contains(&req.action))
        .collect();
    if applicable.is_empty() {
        return Decision::deny(
            ErrorCode::Forbidden,
            format!("no grant allows {} on {target_desc}", req.action),
        );
    }
    let in_time: Vec<&Grant> = applicable
        .into_iter()
        .filter(|g| g.not_before.map(|t| req.now >= t).unwrap_or(true))
        .filter(|g| g.expires_at.map(|t| req.now < t).unwrap_or(true))
        .filter(|g| g.schedule.as_ref().map(|s| s.contains(req.now)).unwrap_or(true))
        .collect();
    if in_time.is_empty() {
        return Decision::deny(ErrorCode::Expired, "grant expired or outside its time window");
    }

    let full_access = req.device.and_then(|d| {
        full.iter()
            .find(|f| f.principal == req.principal && f.device == d && f.is_active(req.now))
            .map(|f| f.id.clone())
    });

    // Network constraints narrow the set further.
    let matching: Vec<&Grant> = in_time
        .into_iter()
        .filter(|g| match (req.action, req.net) {
            (Action::ForwardLocal, Some((h, p))) => net::name_allowed(&g.forward_targets, h, p),
            (Action::ForwardRemote, Some((h, p))) => {
                g.remote_ports.iter().any(|r| r.contains(p)) && (full_access.is_some() || is_loopback_name(h))
            }
            (Action::Egress, Some((h, p))) => net::name_allowed(&g.egress, h, p),
            (Action::ForwardLocal | Action::ForwardRemote | Action::Egress, None) => false,
            _ => true,
        })
        .collect();
    if matching.is_empty() {
        let (h, p) = req.net.unwrap_or(("?", 0));
        return Decision::deny(
            ErrorCode::Forbidden,
            format!("{} to {h}:{p} is not allowed by any grant", req.action),
        );
    }

    // Concurrency limits: allowed if at least one grant still has room.
    let with_room: Vec<&Grant> = matching
        .iter()
        .copied()
        .filter(|g| g.max_sessions.map(|m| (req.active)(&g.id) < m).unwrap_or(true))
        .collect();
    if with_room.is_empty() {
        return Decision::deny(ErrorCode::LimitExceeded, "concurrent session limit reached");
    }

    let mut roots: Vec<String> = Vec::new();
    for g in &with_room {
        for r in &g.project_roots {
            if !roots.contains(r) {
                roots.push(r.clone());
            }
        }
    }
    if req.device.is_some() && roots.is_empty() && full_access.is_none() {
        return Decision::deny(ErrorCode::Forbidden, "grant has no project roots");
    }
    Decision {
        allow: true,
        code: None,
        reason: format!(
            "allowed by {}",
            with_room
                .iter()
                .map(|g| g.id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
        grant_ids: with_room.iter().map(|g| g.id.clone()).collect(),
        roots,
        full_access,
        egress_rules: with_room.iter().flat_map(|g| g.egress.clone()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ApprovalStatus, Role, Schedule};
    use crate::net::NetRule;

    fn grant(actions: &[Action]) -> Grant {
        Grant {
            id: "g1".into(),
            name: String::new(),
            subject: Subject::Principal("a1".into()),
            target: Target::Device("d1".into()),
            actions: actions.iter().copied().collect(),
            project_roots: vec!["/work".into()],
            schedule: None,
            not_before: None,
            expires_at: None,
            forward_targets: vec![NetRule::allow("127.0.0.1", &["8080"])],
            remote_ports: vec!["9000-9010".parse().unwrap()],
            egress: vec![],
            max_sessions: None,
            enabled: true,
        }
    }

    fn req(action: Action) -> AccessRequest<'static> {
        AccessRequest {
            principal: "a1",
            principal_groups: &[],
            device: Some("d1"),
            device_groups: &[],
            action,
            net: None,
            active: &|_| 0,
            now: 1_700_000_000,
        }
    }

    #[test]
    fn default_deny() {
        let d = decide(&req(Action::Shell), &[], &[]);
        assert!(!d.allow);
        assert_eq!(d.code, Some(ErrorCode::Forbidden));
        let d = decide(&req(Action::Exec), &[grant(&[Action::Shell])], &[]);
        assert!(!d.allow);
    }

    #[test]
    fn allow_and_roots() {
        let d = decide(&req(Action::Shell), &[grant(&[Action::Shell])], &[]);
        assert!(d.allow);
        assert_eq!(d.roots, vec!["/work".to_string()]);
        assert!(d.full_access.is_none());
    }

    #[test]
    fn other_subject_or_device_denied() {
        let mut r = req(Action::Shell);
        r.principal = "a2";
        assert!(!decide(&r, &[grant(&[Action::Shell])], &[]).allow);
        let mut r = req(Action::Shell);
        r.device = Some("d2");
        assert!(!decide(&r, &[grant(&[Action::Shell])], &[]).allow);
    }

    #[test]
    fn groups() {
        let mut g = grant(&[Action::Exec]);
        g.subject = Subject::Group("ops".into());
        g.target = Target::DeviceGroup("linux".into());
        let pg = vec!["ops".to_string()];
        let dg = vec!["linux".to_string()];
        let mut r = req(Action::Exec);
        r.principal_groups = &pg;
        r.device_groups = &dg;
        assert!(decide(&r, &[g.clone()], &[]).allow);
        r.device_groups = &[];
        assert!(!decide(&r, &[g], &[]).allow);
    }

    #[test]
    fn expiry_and_schedule() {
        let mut g = grant(&[Action::Shell]);
        g.expires_at = Some(1_600_000_000);
        let d = decide(&req(Action::Shell), &[g], &[]);
        assert_eq!(d.code, Some(ErrorCode::Expired));
        let mut g = grant(&[Action::Shell]);
        // 1_700_000_000 = Tue 2023-11-14 22:13 UTC.
        g.schedule = Some(Schedule {
            days: vec![0, 1, 2, 3, 4],
            start_min: 9 * 60,
            end_min: 18 * 60,
            utc_offset_minutes: 0,
        });
        assert!(!decide(&req(Action::Shell), &[g.clone()], &[]).allow);
        g.schedule.as_mut().unwrap().utc_offset_minutes = -10 * 60; // 12:13 local
        assert!(decide(&req(Action::Shell), &[g], &[]).allow);
    }

    #[test]
    fn forward_constraints() {
        let g = grant(&[Action::ForwardLocal, Action::ForwardRemote]);
        let mut r = req(Action::ForwardLocal);
        r.net = Some(("127.0.0.1", 8080));
        assert!(decide(&r, &[g.clone()], &[]).allow);
        r.net = Some(("127.0.0.1", 22));
        assert!(!decide(&r, &[g.clone()], &[]).allow);
        let mut r = req(Action::ForwardRemote);
        r.net = Some(("127.0.0.1", 9005));
        assert!(decide(&r, &[g.clone()], &[]).allow);
        r.net = Some(("0.0.0.0", 9005));
        assert!(
            !decide(&r, &[g.clone()], &[]).allow,
            "non-loopback bind needs full access"
        );
        r.net = Some(("127.0.0.1", 9100));
        assert!(!decide(&r, &[g], &[]).allow);
    }

    #[test]
    fn session_limit() {
        let mut g = grant(&[Action::Shell]);
        g.max_sessions = Some(2);
        let mut r = req(Action::Shell);
        let two = |_: &str| 2u32;
        r.active = &two;
        assert_eq!(decide(&r, &[g], &[]).code, Some(ErrorCode::LimitExceeded));
    }

    #[test]
    fn full_access_lifecycle() {
        let mut fa = FullAccess {
            id: "f1".into(),
            principal: "a1".into(),
            device: "d1".into(),
            reason: "debug".into(),
            requested_by: "alice".into(),
            duration_secs: 3600,
            status: ApprovalStatus::Pending,
            approved_by: None,
            decided_at: None,
            expires_at: None,
            created_at: 0,
        };
        let now = 1_700_000_000;
        assert!(
            fa.approve("alice", &[Role::Secadmin], Some("carol"), now)
                .is_err(),
            "self approval"
        );
        assert!(
            fa.approve("carol", &[Role::Secadmin], Some("carol"), now)
                .is_err(),
            "owner approval"
        );
        assert!(
            fa.approve("bob", &[Role::Sysadmin], Some("carol"), now).is_err(),
            "role"
        );
        fa.approve("bob", &[Role::Secadmin], Some("carol"), now).unwrap();
        let g = grant(&[Action::Shell]);
        let d = decide(&req(Action::Shell), &[g.clone()], &[fa.clone()]);
        assert_eq!(d.full_access.as_deref(), Some("f1"));
        let mut r = req(Action::Shell);
        r.now = now + 3601;
        assert!(decide(&r, &[g], &[fa]).full_access.is_none(), "expired");
    }

    #[test]
    fn grant_validation() {
        let mut g = grant(&[Action::Shell]);
        g.project_roots.clear();
        assert!(g.validate().is_err());
        let mut g = grant(&[Action::Shell]);
        g.project_roots = vec!["relative".into()];
        assert!(g.validate().is_err());
        assert!(grant(&[Action::Shell]).validate().is_ok());
        assert!(crate::model::validate_roles(&[Role::Secadmin, Role::Auditor]).is_err());
        assert!(crate::model::validate_roles(&[Role::Sysadmin, Role::Secadmin]).is_ok());
    }
}
