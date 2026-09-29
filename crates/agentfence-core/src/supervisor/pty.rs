//! The agent runs on a supervisor-owned pseudo-terminal, never on the human's
//! TTY (threat T15c): keystroke injection into the human's terminal is
//! impossible, and the agent is a session leader we can clean up (T20).

use anyhow::{bail, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct Pty {
    pub master: OwnedFd,
    slave: Option<OwnedFd>,
    pub slave_path: String,
}

fn set_cloexec(fd: RawFd) {
    // SAFETY: fcntl on an fd we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }
}

impl Pty {
    /// Opens a pty. If the human's stdin is a terminal, the pty copies its
    /// settings and size; otherwise it is raw so output passes through unchanged.
    pub fn open() -> Result<Pty> {
        let (mut m, mut s) = (0, 0);
        // SAFETY: openpty writes two fds; ptsname returns a static buffer copied immediately.
        let slave_path = unsafe {
            if libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
                bail!("openpty failed: {}", std::io::Error::last_os_error());
            }
            std::ffi::CStr::from_ptr(libc::ptsname(m)).to_string_lossy().into_owned()
        };
        set_cloexec(m);
        set_cloexec(s);
        // SAFETY: fds just returned by openpty; ownership transferred here.
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
        let pty = Pty { master, slave: Some(slave), slave_path };
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::isatty(0) == 1 && libc::tcgetattr(0, &mut t) == 0 {
                libc::tcsetattr(pty.slave_fd(), libc::TCSANOW, &t);
                pty.sync_winsize();
            } else if libc::tcgetattr(pty.slave_fd(), &mut t) == 0 {
                libc::cfmakeraw(&mut t);
                libc::tcsetattr(pty.slave_fd(), libc::TCSANOW, &t);
            }
        }
        Ok(pty)
    }

    fn slave_fd(&self) -> RawFd {
        self.slave.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1)
    }

    /// Closes the supervisor's copy of the slave (after the agent is spawned).
    pub fn close_slave(&mut self) {
        self.slave = None;
    }

    pub fn sync_winsize(&self) {
        // SAFETY: ioctl with a properly sized winsize struct.
        unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 {
                libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws);
            }
        }
    }

    /// Configures `cmd` to run as a session leader with this pty as its
    /// controlling terminal and stdio.
    pub fn attach(&self, cmd: &mut Command) -> Result<()> {
        let Some(slave) = self.slave.as_ref() else { bail!("pty slave already closed") };
        let dup = |fd: &OwnedFd| -> Result<Stdio> { Ok(Stdio::from(File::from(fd.try_clone()?))) };
        cmd.stdin(dup(slave)?).stdout(dup(slave)?).stderr(dup(slave)?);
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

/// Restores the human's terminal on drop.
pub struct RawGuard {
    saved: Option<libc::termios>,
}

impl RawGuard {
    pub fn enter() -> RawGuard {
        // SAFETY: termios calls on fd 0 with a zeroed struct.
        unsafe {
            if libc::isatty(0) != 1 {
                return RawGuard { saved: None };
            }
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return RawGuard { saved: None };
            }
            let saved = t;
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(0, libc::TCSANOW, &t);
            RawGuard { saved: Some(saved) }
        }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        if let Some(t) = self.saved {
            // SAFETY: restoring settings captured in enter().
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &t);
            }
        }
    }
}

/// Copies human stdin → pty and pty → human stdout until the pty closes.
/// Returns a handle whose `join` waits for the output side to drain.
pub struct Relay {
    output: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl Relay {
    pub fn start(pty: &Pty) -> Result<Relay> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut from_master = File::from(pty.master.try_clone()?);
        let output = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut out = std::io::stdout();
            loop {
                match from_master.read(&mut buf) {
                    Ok(0) | Err(_) => break, // EIO once every slave fd is closed
                    Ok(n) => {
                        if out.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = out.flush();
                    }
                }
            }
        });
        let mut to_master = File::from(pty.master.try_clone()?);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut input = std::io::stdin();
            while let Ok(n) = input.read(&mut buf) {
                if n == 0 || to_master.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        });
        // Window-size follower (polling avoids signal handlers).
        let master_fd = pty.master.try_clone()?;
        let stop2 = stop.clone();
        std::thread::spawn(move || {
            let mut last: (u16, u16) = (0, 0);
            while !stop2.load(Ordering::SeqCst) {
                // SAFETY: ioctl with a properly sized winsize struct.
                unsafe {
                    let mut ws: libc::winsize = std::mem::zeroed();
                    if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && (ws.ws_row, ws.ws_col) != last {
                        last = (ws.ws_row, ws.ws_col);
                        libc::ioctl(master_fd.as_raw_fd(), libc::TIOCSWINSZ, &ws);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        });
        Ok(Relay { output: Some(output), stop })
    }

    /// Waits (bounded) for remaining agent output to be copied.
    pub fn finish(mut self, timeout: std::time::Duration) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.output.take() {
            let deadline = std::time::Instant::now() + timeout;
            while !h.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }
}
