//! Process facts from libproc and sysctl. Works for same-uid processes without
//! privileges. Observation only: nothing here is on an enforcement path.

use super::ProcessFacts;
use std::ffi::CStr;

pub fn list_pids() -> Vec<i32> {
    // SAFETY: a null buffer asks for the required count; the second call fills
    // at most `cap` pids and returns how many it wrote.
    unsafe {
        let n = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if n <= 0 {
            return vec![];
        }
        let cap = (n as usize) + 64;
        let mut buf = vec![0i32; cap];
        let got = libc::proc_listallpids(buf.as_mut_ptr().cast(), (cap * std::mem::size_of::<i32>()) as i32);
        if got <= 0 {
            return vec![];
        }
        buf.truncate(got as usize);
        buf.retain(|p| *p > 0);
        buf
    }
}

fn bsdinfo(pid: i32) -> Option<libc::proc_bsdinfo> {
    // SAFETY: proc_bsdinfo is plain data; proc_pidinfo writes at most `size` bytes.
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let r = libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size);
        (r == size).then_some(info)
    }
}

pub fn exe_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4 * 1024];
    // SAFETY: buffer is PROC_PIDPATHINFO_MAXSIZE bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// argv via `sysctl(KERN_PROCARGS2)`: `int argc`, exec path, NUL padding, argv…
pub fn argv(pid: i32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: first call sizes the buffer, second fills it; both bounded by `size`.
    unsafe {
        if libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) != 0 || size < 4 {
            return None;
        }
        let mut buf = vec![0u8; size];
        if libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        buf.truncate(size);
        parse_procargs2(&buf)
    }
}

pub fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    let mut i = 4;
    // skip exec path
    while i < buf.len() && buf[i] != 0 {
        i += 1;
    }
    // skip NUL padding
    while i < buf.len() && buf[i] == 0 {
        i += 1;
    }
    let mut out = Vec::with_capacity(argc);
    while out.len() < argc && i < buf.len() {
        let start = i;
        while i < buf.len() && buf[i] != 0 {
            i += 1;
        }
        out.push(String::from_utf8_lossy(&buf[start..i]).into_owned());
        i += 1;
    }
    Some(out)
}

pub fn facts(pid: i32) -> Option<ProcessFacts> {
    let info = bsdinfo(pid)?;
    // SAFETY: pbi_name/pbi_comm are NUL-terminated fixed arrays (zeroed first).
    let name = unsafe {
        let n = CStr::from_ptr(info.pbi_name.as_ptr()).to_string_lossy().into_owned();
        if n.is_empty() {
            CStr::from_ptr(info.pbi_comm.as_ptr()).to_string_lossy().into_owned()
        } else {
            n
        }
    };
    Some(ProcessFacts {
        pid,
        ppid: info.pbi_ppid as i32,
        pgid: info.pbi_pgid as i32,
        uid: info.pbi_uid,
        start_time_us: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
        exe: exe_path(pid),
        argv: argv(pid).unwrap_or_default(),
        name,
    })
}

/// Current working directory of a same-uid process (PROC_PIDVNODEPATHINFO).
pub fn cwd(pid: i32) -> Option<String> {
    // SAFETY: proc_vnodepathinfo is plain data; proc_pidinfo writes at most `size` bytes.
    unsafe {
        let mut info: libc::proc_vnodepathinfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as i32;
        let r = libc::proc_pidinfo(pid, libc::PROC_PIDVNODEPATHINFO, 0, (&mut info as *mut libc::proc_vnodepathinfo).cast(), size);
        if r != size {
            return None;
        }
        let p = CStr::from_ptr(info.pvi_cdir.vip_path.as_ptr().cast()).to_string_lossy().into_owned();
        (!p.is_empty()).then_some(p)
    }
}

pub fn snapshot() -> Vec<ProcessFacts> {
    list_pids().into_iter().filter_map(facts).collect()
}

/// All pids whose session id is `sid` (end-of-session cleanup).
pub fn session_members(sid: i32) -> Vec<i32> {
    list_pids()
        .into_iter()
        // SAFETY: getsid has no memory effects.
        .filter(|p| unsafe { libc::getsid(*p) } == sid)
        .collect()
}

/// `pid` and its ancestors (closest first), for pids the tree has not seen.
pub fn resolve_ancestry(pid: i32) -> Vec<ProcessFacts> {
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..64 {
        let Some(f) = facts(cur) else { break };
        let next = f.ppid;
        out.push(f);
        if next <= 1 || next == cur {
            break;
        }
        cur = next;
    }
    out
}
