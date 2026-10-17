//! Windows: AppContainer + Job Object launcher.
//!
//! The helper process (still running with the device's token) creates or
//! opens the AppContainer profile `cjs.sandbox`, grants the container SID
//! full access to each writable directory (inherited ACE), then starts the
//! command with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and no
//! capabilities (so: no network, no access to the user profile). The child
//! inherits the helper's console (ConPTY) and standard handles. A Job Object
//! with KILL_ON_JOB_CLOSE ties the child's lifetime to the helper.
use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess, InitializeProcThreadAttributeList,
    ResumeThread, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
};

use crate::HelperArgs;

const PROFILE: &str = "cjs.sandbox";
const GENERIC_ALL: u32 = 0x1000_0000;
const E_ALREADY_EXISTS: i32 = 0x800700B7_u32 as i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn fail(msg: &str) -> ! {
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    eprintln!("cjs-sandbox: {msg} (error {code})");
    std::process::exit(126);
}

struct Sid(PSID);

impl Drop for Sid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the SID was allocated by the AppContainer APIs and is
            // released exactly once.
            unsafe { FreeSid(self.0) };
        }
    }
}

fn container_sid() -> Sid {
    let name = wide(PROFILE);
    let display = wide("ClawdJumpServer sandbox");
    let mut sid: PSID = null_mut();
    // SAFETY: valid NUL-terminated strings, out-pointer to a local.
    let hr = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            display.as_ptr(),
            null(),
            0,
            &mut sid,
        )
    };
    if hr == E_ALREADY_EXISTS {
        // SAFETY: as above.
        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if hr != 0 {
            fail("DeriveAppContainerSidFromAppContainerName failed");
        }
    } else if hr != 0 {
        fail("CreateAppContainerProfile failed");
    }
    Sid(sid)
}

/// Add an inheritable GENERIC_ALL ACE for `sid` to the DACL of `path`.
fn grant(path: &Path, sid: &Sid) {
    let p = wide(&path.to_string_lossy());
    let mut old: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: out-pointers to locals; `sd` is freed with LocalFree below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut old,
            null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        eprintln!("cjs-sandbox: cannot read ACL of {} (error {rc})", path.display());
        std::process::exit(126);
    }
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.0 as *mut u16,
        },
    };
    let mut new: *mut ACL = null_mut();
    // SAFETY: one valid EXPLICIT_ACCESS_W entry; `new` freed with LocalFree.
    let rc = unsafe { SetEntriesInAclW(1, &ea, old, &mut new) };
    if rc != 0 {
        eprintln!("cjs-sandbox: SetEntriesInAcl failed (error {rc})");
        std::process::exit(126);
    }
    // SAFETY: `new` is a valid ACL produced above.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            p.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new,
            null(),
        )
    };
    // SAFETY: both were allocated by the system with LocalAlloc.
    unsafe {
        LocalFree(new as *mut c_void);
        LocalFree(sd);
    }
    if rc != 0 {
        eprintln!(
            "cjs-sandbox: cannot grant sandbox access to {} (error {rc})",
            path.display()
        );
        std::process::exit(126);
    }
}

fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    let mut s = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                s.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                s.push('"');
                backslashes = 0;
            }
            _ => {
                s.extend(std::iter::repeat_n('\\', backslashes));
                s.push(c);
                backslashes = 0;
            }
        }
    }
    s.extend(std::iter::repeat_n('\\', backslashes * 2));
    s.push('"');
    s
}

pub(crate) fn run(a: &HelperArgs) -> ! {
    let sid = container_sid();
    for w in &a.write {
        grant(w, &sid);
    }
    let mut caps = SECURITY_CAPABILITIES {
        AppContainerSid: sid.0,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    // Attribute list with one entry.
    let mut size: usize = 0;
    // SAFETY: size query call; the first call is expected to fail.
    unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
    let mut buf = vec![0u8; size];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: `buf` has the size requested above and outlives the list.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        fail("InitializeProcThreadAttributeList failed");
    }
    // SAFETY: `caps` outlives CreateProcessW.
    if unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &mut caps as *mut _ as *mut c_void,
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        fail("UpdateProcThreadAttribute failed");
    }
    // SAFETY: zero-initialised plain-old-data structs.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = list;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let cmdline: String = a.argv.iter().map(|s| quote_arg(s)).collect::<Vec<_>>().join(" ");
    let mut cmd = wide(&cmdline);
    // SAFETY: all pointers are valid for the duration of the call; the
    // command line buffer is mutable as CreateProcessW requires.
    let ok = unsafe {
        CreateProcessW(
            null(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            null(),
            null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // SAFETY: list was initialised above.
    unsafe { DeleteProcThreadAttributeList(list) };
    if ok == 0 {
        fail("CreateProcessW in AppContainer failed");
    }
    // SAFETY: plain Win32 handle manipulation on handles we own.
    unsafe {
        let job: HANDLE = CreateJobObjectW(null(), null());
        if job.is_null() {
            fail("CreateJobObject failed");
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) == 0
            || AssignProcessToJobObject(job, pi.hProcess) == 0
        {
            fail("cannot place sandboxed process in a job object");
        }
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        let mut code: u32 = 1;
        if WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0 {
            GetExitCodeProcess(pi.hProcess, &mut code);
        }
        CloseHandle(pi.hProcess);
        drop(sid);
        std::process::exit(code as i32);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn quoting() {
        assert_eq!(super::quote_arg("a"), "a");
        assert_eq!(super::quote_arg("a b"), "\"a b\"");
        assert_eq!(super::quote_arg("a\"b"), "\"a\\\"b\"");
    }
}
