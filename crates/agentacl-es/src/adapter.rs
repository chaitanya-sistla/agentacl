//! Endpoint Security messages in, engine answers out.
//!
//! This is the only code that touches the framework. It needs the
//! `com.apple.developer.endpoint-security.client` entitlement, root and Full
//! Disk Access to run (or, for development, a Mac with SIP and AMFI off).

use crate::engine::{Engine, PolicyProvider};
use crate::model::{Msg, Op, Proc, ProcKey, Verdict};
use endpoint_sec::sys::{es_auth_result_t, es_event_type_t};
use endpoint_sec::{Event, EventCopyFile, EventCreateDestinationFile, EventRenameDestinationFile, File, Message, Process};
use std::ffi::OsStr;
use std::path::Path;

/// Everything the engine needs. AUTH events wait for our answer; NOTIFY
/// events only update which processes belong to an agent.
pub const EVENTS: &[es_event_type_t] = &[
    es_event_type_t::ES_EVENT_TYPE_AUTH_EXEC,
    es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN,
    es_event_type_t::ES_EVENT_TYPE_AUTH_CREATE,
    es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME,
    es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
    es_event_type_t::ES_EVENT_TYPE_AUTH_LINK,
    es_event_type_t::ES_EVENT_TYPE_AUTH_TRUNCATE,
    es_event_type_t::ES_EVENT_TYPE_AUTH_CLONE,
    es_event_type_t::ES_EVENT_TYPE_AUTH_COPYFILE,
    es_event_type_t::ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
    es_event_type_t::ES_EVENT_TYPE_AUTH_SETMODE,
    es_event_type_t::ES_EVENT_TYPE_AUTH_SETOWNER,
    es_event_type_t::ES_EVENT_TYPE_AUTH_SETFLAGS,
    es_event_type_t::ES_EVENT_TYPE_AUTH_SETEXTATTR,
    es_event_type_t::ES_EVENT_TYPE_AUTH_DELETEEXTATTR,
    es_event_type_t::ES_EVENT_TYPE_AUTH_SETACL,
    es_event_type_t::ES_EVENT_TYPE_AUTH_UTIMES,
    es_event_type_t::ES_EVENT_TYPE_AUTH_SETATTRLIST,
    es_event_type_t::ES_EVENT_TYPE_AUTH_SIGNAL,
    es_event_type_t::ES_EVENT_TYPE_AUTH_GET_TASK,
    es_event_type_t::ES_EVENT_TYPE_AUTH_GET_TASK_READ,
    es_event_type_t::ES_EVENT_TYPE_AUTH_UIPC_CONNECT,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
];

/// `fflag` bits of an open (`<sys/fcntl.h>`).
const FREAD: i32 = 0x1;
const FWRITE: i32 = 0x2;
const O_TRUNC: i32 = 0x400;

fn lossy(s: &OsStr) -> String {
    s.to_string_lossy().into_owned()
}

/// A file's path; "" if ES truncated it, which no rule allows, so an
/// agent's request for it is refused rather than matched by a prefix.
fn path(f: &File<'_>) -> String {
    if f.path_truncated() {
        String::new()
    } else {
        lossy(f.path())
    }
}

fn join(dir: &File<'_>, name: &OsStr) -> String {
    if dir.path_truncated() {
        return String::new();
    }
    Path::new(dir.path()).join(name).to_string_lossy().into_owned()
}

fn proc_of(p: &Process<'_>, msg_version: u32) -> Proc {
    let t = p.audit_token();
    let parent = if msg_version >= 4 { p.parent_audit_token().map(|a| ProcKey { pid: a.pid(), version: a.pidversion() }) } else { None };
    Proc {
        key: Some(ProcKey { pid: t.pid(), version: t.pidversion() }),
        parent,
        ppid: p.ppid(),
        uid: t.ruid(),
        exe: path(&p.executable()),
        signing_id: lossy(p.signing_id()),
        team_id: lossy(p.team_id()),
        platform_binary: p.is_platform_binary(),
        cs_flags: p.codesigning_flags(),
    }
}

/// The engine's view of an ES message; `None` for events it doesn't handle
/// (they're allowed).
pub fn to_msg(m: &Message) -> Option<Msg> {
    let v = m.version();
    let proc = proc_of(&m.process(), v);
    let exec = |e: &endpoint_sec::EventExec<'_>| {
        let target = proc_of(&e.target(), v);
        let setuid = e.target().executable().stat().st_mode as u32 & 0o6000 != 0;
        Op::Exec { target, argv: e.args().map(lossy).collect(), cwd: e.cwd().map(|f| path(&f)), setuid }
    };
    let (op, auth) = match m.event()? {
        Event::AuthExec(e) => (exec(&e), true),
        Event::NotifyExec(e) => (exec(&e), false),
        Event::AuthOpen(e) => {
            let f = e.fflag();
            (Op::Open { path: path(&e.file()), read: f & FREAD != 0, write: f & (FWRITE | O_TRUNC) != 0 }, true)
        }
        Event::AuthCreate(e) => {
            // An unknown destination becomes "": refused for an agent (no
            // rule allows it), irrelevant for anything else.
            let path = match e.destination() {
                Some(EventCreateDestinationFile::ExistingFile { file, .. }) => path(&file),
                Some(EventCreateDestinationFile::NewPath { directory, filename, .. }) => join(&directory, filename),
                _ => String::new(),
            };
            (Op::Create { path }, true)
        }
        Event::AuthRename(e) => {
            let destination = match e.destination() {
                Some(EventRenameDestinationFile::ExistingFile { file, .. }) => path(&file),
                Some(EventRenameDestinationFile::NewPath { directory, filename, .. }) => join(&directory, filename),
                _ => String::new(),
            };
            (Op::Rename { source: path(&e.source()), destination }, true)
        }
        Event::AuthUnlink(e) => (Op::Unlink { path: path(&e.target()) }, true),
        Event::AuthLink(e) => (Op::Link { source: path(&e.source()), destination: join(&e.target_dir(), e.target_filename()) }, true),
        Event::AuthTruncate(e) => (Op::Truncate { path: path(&e.target()) }, true),
        Event::AuthClone(e) => (Op::Clone { source: path(&e.source()), destination: join(&e.target_dir(), e.target_name()) }, true),
        Event::AuthCopyFile(e) => (Op::CopyFile { source: path(&e.source()), destination: copy_destination(&e) }, true),
        Event::AuthExchangeData(e) => (Op::Exchange { a: path(&e.file1()), b: path(&e.file2()) }, true),
        Event::AuthSetMode(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthSetOwner(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthSetFlags(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthSetExtAttr(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthDeleteExtAttr(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthSetAcl(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthUTimes(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthSetAttrlist(e) => (Op::Meta { path: path(&e.target()) }, true),
        Event::AuthSignal(e) => (Op::Signal { target: proc_of(&e.target(), v), signal: e.sig() }, true),
        Event::AuthGetTask(e) => (Op::GetTask { target: proc_of(&e.target(), v) }, true),
        Event::AuthGetTaskRead(e) => (Op::GetTask { target: proc_of(&e.target(), v) }, true),
        Event::AuthUipcConnect(e) => (Op::UnixConnect { path: path(&e.file()) }, true),
        Event::NotifyFork(e) => (Op::Fork { child: proc_of(&e.child(), v) }, false),
        Event::NotifyExit(_) => (Op::Exit, false),
        _ => return None,
    };
    Some(Msg { proc, op, auth })
}

fn copy_destination(e: &EventCopyFile<'_>) -> String {
    match e.target_file() {
        Some(f) => path(&f),
        None => join(&e.target_dir(), e.target_name()),
    }
}

/// `AGENTACL_ESD_DEBUG=1`: log every decision but opens, forks and exits
/// (development only; it is a lot).
fn debug() -> bool {
    static DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DEBUG.get_or_init(|| std::env::var_os("AGENTACL_ESD_DEBUG").is_some_and(|v| v == "1"))
}

/// Decides and answers one message. Every AUTH message gets an answer, even
/// if deciding panics (ES would otherwise stall the request and then kill
/// the daemon): a bug must never wedge the Mac, so the answer is then allow.
pub fn handle<P: PolicyProvider>(client: &mut endpoint_sec::Client<'_>, m: Message, engine: &std::sync::Mutex<Engine<P>>, journal: &std::sync::mpsc::Sender<agentacl_core::es_journal::EsRecord>) {
    let decided = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let msg = to_msg(&m)?;
        let mut e = engine.lock().unwrap_or_else(|p| p.into_inner());
        let v = e.decide(&msg);
        for r in e.out.drain(..) {
            let _ = journal.send(r);
        }
        Some(v)
    }));
    if debug() {
        if let Ok(Some(_)) = &decided {
            if let Some(msg) = to_msg(&m).filter(|x| !matches!(x.op, Op::Open { .. } | Op::Fork { .. } | Op::Exit)) {
                eprintln!("agentacl-esd: {} {:?} -> {:?}", msg.proc.exe, msg.op, decided);
            }
        }
    }
    let verdict = match decided {
        Ok(Some(v)) => v,
        Ok(None) => Verdict::ALLOW,
        Err(_) => {
            eprintln!("agentacl-esd: a decision panicked; allowed");
            Verdict::ALLOW
        }
    };
    match m.event() {
        Some(Event::AuthOpen(e)) => {
            let flags = if verdict.allow { e.fflag() as u32 } else { 0 };
            let _ = client.respond_flags_result(&m, flags, verdict.cache);
        }
        Some(ev) if ev.expected_response_type().is_some() => {
            let r = if verdict.allow { es_auth_result_t::ES_AUTH_RESULT_ALLOW } else { es_auth_result_t::ES_AUTH_RESULT_DENY };
            let _ = client.respond_auth_result(&m, r, verdict.cache);
        }
        _ => {} // NOTIFY: no answer
    }
}
