//! The Windows side of the helper: install and uninstall, the service and its
//! pipe, and the client that `Device::open` falls back to.

use super::{open_partition, serve_client, sid_ok, Action, Refusal, Session};
use anyhow::{bail, Context, Result};
use std::convert::Infallible;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_WRITE_DATA, PIPE_ACCESS_DUPLEX,
    SECURITY_IDENTIFICATION,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, RegisterServiceCtrlHandlerExW,
    SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW, SC_HANDLE, SC_MANAGER_ALL_ACCESS,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS,
    SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SERVICE: &str = "btrfs-peek";
pub const PIPE: &str = r"\\.\pipe\btrfs-peek";
/// The allowed account's rights on the pipe: enough to send requests and read
/// replies, but not FILE_CREATE_PIPE_INSTANCE, so it cannot add instances of
/// the service's pipe and answer other clients itself.
const CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;
/// How long install and uninstall wait for the service manager.
const WAIT: Duration = Duration::from_secs(10);

pub fn run(action: &Action, json: bool) -> Result<()> {
    match action {
        Action::Install { sid } => install(sid.as_deref()),
        Action::Uninstall => uninstall(),
        Action::Status => status(json),
        Action::Serve { sid } => serve(sid),
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn is(e: &io::Error, code: u32) -> bool {
    e.raw_os_error() == Some(code as i32)
}

/// Polls `done` every 100 ms until it holds or `limit` has passed.
fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Retries `f` for a few seconds: a file the old service ran stays locked
/// for a moment after it stops.
fn retry<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match f() {
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            r => return r,
        }
    }
}

struct Sc(SC_HANDLE);
impl Drop for Sc {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Memory the OS allocated with LocalAlloc.
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn open_scm(access: u32) -> io::Result<Sc> {
    let h = unsafe { OpenSCManagerW(null(), null(), access) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Sc(h))
}

fn open_service(scm: &Sc, access: u32) -> io::Result<Sc> {
    let name = wide(SERVICE);
    let h = unsafe { OpenServiceW(scm.0, name.as_ptr(), access) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Sc(h))
}

fn query(svc: &Sc) -> io::Result<SERVICE_STATUS_PROCESS> {
    let mut st = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            (&mut st as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// The running service's pid; None if it is not installed or not running.
fn service_pid() -> io::Result<Option<u32>> {
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let svc = match open_service(&scm, SERVICE_QUERY_STATUS) {
        Err(e) if is(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(None),
        r => r?,
    };
    let st = query(&svc)?;
    Ok((st.dwCurrentState == SERVICE_RUNNING).then_some(st.dwProcessId))
}

/// The SID of the account this process runs as, as `S-1-...`.
fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut len = 0u32;
    // The first call only reports the size, and fails doing so.
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut len) };
    // u64s, not u8s: TOKEN_USER holds a pointer and must be aligned for it.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    let size = (buf.len() * 8) as u32;
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            size,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut s: PWSTR = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut s) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free = Local(s.cast());
    let text = unsafe {
        let n = (0..).take_while(|&i| *s.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(s, n))
    };
    Ok(text)
}

/// Program Files, from HKLM rather than %ProgramFiles%: the environment is the
/// user's to change, and the service must never run a file the user can write.
fn program_files() -> PathBuf {
    let key = wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion");
    let value = wide("ProgramFilesDir");
    let mut buf = [0u16; 512];
    let mut size = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
    if r != ERROR_SUCCESS || n == 0 {
        return PathBuf::from(r"C:\Program Files");
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..n]))
}

fn install_dir() -> PathBuf {
    program_files().join("btrfs-peek")
}

fn needs_elevation(e: io::Error, msg: &'static str) -> anyhow::Error {
    if is(&e, ERROR_ACCESS_DENIED) {
        return anyhow::Error::new(crate::AccessDenied).context(msg);
    }
    anyhow::Error::new(e).context("opening the service manager")
}

/// Stops and deletes the service if it exists; true if it did.
fn remove_service(scm: &Sc) -> Result<bool> {
    let svc = match open_service(scm, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE) {
        Err(e) if is(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(false),
        r => r.context("opening the btrfs-peek service")?,
    };
    let mut st = SERVICE_STATUS::default();
    if unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st) } == 0 {
        let e = io::Error::last_os_error();
        // Not running, or starting or stopping already: the wait below covers both.
        if !is(&e, ERROR_SERVICE_NOT_ACTIVE) && !is(&e, ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
            return Err(e).context("stopping the btrfs-peek service");
        }
    }
    wait_until(WAIT, || {
        query(&svc).is_ok_and(|s| s.dwCurrentState == SERVICE_STOPPED)
    });
    if unsafe { DeleteService(svc.0) } == 0 {
        let e = io::Error::last_os_error();
        if !is(&e, ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Err(e).context("deleting the btrfs-peek service");
        }
    }
    // The service manager deletes it only once every handle to it is closed.
    drop(svc);
    let gone = wait_until(
        WAIT,
        || matches!(open_service(scm, SERVICE_QUERY_STATUS), Err(e) if is(&e, ERROR_SERVICE_DOES_NOT_EXIST)),
    );
    if !gone {
        bail!("the old service is still marked for deletion; close the Services window and retry");
    }
    Ok(true)
}

/// Copies this exe where only administrators can write, which is what the service runs.
fn copy_exe() -> Result<PathBuf> {
    let src = std::env::current_exe().context("finding this program")?;
    let dir = install_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let dest = dir.join("btrfs-peek.exe");
    if same_file(&src, &dest) {
        return Ok(dest);
    }
    retry(|| std::fs::copy(&src, &dest))
        .with_context(|| format!("copying {} to {}", src.display(), dest.display()))?;
    Ok(dest)
}

fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

fn create_service(scm: &Sc, exe: &Path, sid: &str) -> Result<Sc> {
    let name = wide(SERVICE);
    let display = wide("btrfs-peek helper");
    // Quoted: an unquoted path with spaces lets Windows try `C:\Program.exe` first.
    let bin = wide(&format!("\"{}\" helper serve --sid {sid}", exe.display()));
    let h = unsafe {
        CreateServiceW(
            scm.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            bin.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(), // LocalSystem
            null(),
        )
    };
    if h.is_null() {
        return Err(io::Error::last_os_error()).context("creating the btrfs-peek service");
    }
    let svc = Sc(h);
    if let Err(e) = configure(&svc, sid) {
        // Half a service is worse than none.
        unsafe { DeleteService(svc.0) };
        return Err(e);
    }
    Ok(svc)
}

fn configure(svc: &Sc, sid: &str) -> Result<()> {
    let mut text = wide(&format!(
        "Lets {sid} read btrfs partitions with btrfs-peek without an elevated terminal. Read-only; btrfs partitions only."
    ));
    let desc = SERVICE_DESCRIPTIONW {
        lpDescription: text.as_mut_ptr(),
    };
    let ok = unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&desc as *const SERVICE_DESCRIPTIONW).cast(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error()).context("describing the btrfs-peek service");
    }
    // Drops every other privilege from the LocalSystem token. Reading a raw
    // disk needs none: the device's ACL grants SYSTEM read access.
    let mut privs: Vec<u16> = "SeChangeNotifyPrivilege"
        .encode_utf16()
        .chain([0, 0])
        .collect();
    let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: privs.as_mut_ptr(),
    };
    let ok = unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&info as *const SERVICE_REQUIRED_PRIVILEGES_INFOW).cast(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error())
            .context("limiting the btrfs-peek service's privileges");
    }
    Ok(())
}

fn install(sid: Option<&str>) -> Result<()> {
    let sid = match sid {
        Some(s) => s.to_string(),
        None => current_user_sid().context("finding this account's SID")?,
    };
    if !sid_ok(&sid) {
        bail!("{sid}: not a SID (expected S-1-...)");
    }
    // First, so an unelevated run changes nothing.
    let scm = open_scm(SC_MANAGER_ALL_ACCESS).map_err(|e| {
        needs_elevation(
            e,
            "installing the helper needs an elevated (Administrator) terminal, once",
        )
    })?;
    remove_service(&scm)?;
    let exe = copy_exe()?;
    let svc = create_service(&scm, &exe, &sid)?;
    if unsafe { StartServiceW(svc.0, 0, null()) } == 0 {
        return Err(io::Error::last_os_error()).context("starting the btrfs-peek service");
    }
    let mut last = None;
    let up = wait_until(WAIT, || match probe() {
        Ok(_) => true,
        Err(e) => {
            last = Some(e);
            false
        }
    });
    if !up {
        let why = last.map_or_else(String::new, |e| format!(": {e}"));
        bail!("the service was installed and started but does not answer{why}");
    }
    println!(
        "installed the btrfs-peek helper {}: the service runs {} and lets {sid} read btrfs partitions",
        super::VERSION,
        exe.display()
    );
    Ok(())
}

fn uninstall() -> Result<()> {
    let scm = open_scm(SC_MANAGER_ALL_ACCESS).map_err(|e| {
        needs_elevation(
            e,
            "uninstalling the helper needs an elevated (Administrator) terminal",
        )
    })?;
    let had_service = remove_service(&scm)?;
    let dir = install_dir();
    let had_dir = dir.exists();
    if had_dir {
        retry(|| std::fs::remove_dir_all(&dir))
            .with_context(|| format!("removing {}", dir.display()))?;
    }
    if had_service || had_dir {
        println!(
            "removed the btrfs-peek helper service and {}",
            dir.display()
        );
    } else {
        println!("the helper is not installed");
    }
    Ok(())
}

#[derive(Default, serde::Serialize)]
struct State {
    installed: bool,
    running: bool,
    pid: Option<u32>,
    version: Option<String>,
}

/// Connects and handshakes; the server's version.
fn probe() -> io::Result<String> {
    let Some(pipe) = connect_to(PIPE, true)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{PIPE} does not exist"),
        ));
    };
    Ok(Session::start(pipe)?.1)
}

/// Fills in `st`; the reason the helper is not usable, if it is not.
fn check(st: &mut State) -> std::result::Result<(), String> {
    let scm =
        open_scm(SC_MANAGER_CONNECT).map_err(|e| format!("opening the service manager: {e}"))?;
    let svc = match open_service(&scm, SERVICE_QUERY_STATUS) {
        Err(e) if is(&e, ERROR_SERVICE_DOES_NOT_EXIST) => {
            return Err("the helper is not installed; install it once from an elevated (Administrator) terminal: `btrfs-peek helper install`".into());
        }
        r => r.map_err(|e| format!("opening the btrfs-peek service: {e}"))?,
    };
    st.installed = true;
    let s = query(&svc).map_err(|e| format!("querying the btrfs-peek service: {e}"))?;
    if s.dwCurrentState != SERVICE_RUNNING {
        return Err("the helper is installed but not running; start it with `sc start btrfs-peek` from an elevated terminal, or reinstall it".into());
    }
    st.running = true;
    st.pid = Some(s.dwProcessId);
    let version = probe().map_err(|e| format!("the helper is running but not answering: {e}"))?;
    st.version = Some(version);
    Ok(())
}

fn status(json: bool) -> Result<()> {
    let mut st = State::default();
    let problem = check(&mut st).err();
    if json {
        println!("{}", serde_json::to_string_pretty(&st)?);
    } else if problem.is_none() {
        println!(
            "the btrfs-peek helper {} is running (pid {}) and answering on {PIPE}",
            st.version.as_deref().unwrap_or("?"),
            st.pid.unwrap_or(0)
        );
    }
    if let Some(p) = problem {
        bail!(p);
    }
    Ok(())
}

// --- The service ---

static SID: OnceLock<String> = OnceLock::new();
static STATUS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

fn serve(sid: &str) -> Result<()> {
    if !sid_ok(sid) {
        bail!("{sid}: not a SID (expected S-1-...)");
    }
    let _ = SID.set(sid.to_string());
    let mut name = wide(SERVICE);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // Returns once the service has stopped.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        let e = io::Error::last_os_error();
        if is(&e, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            bail!("`helper serve` is run by the Windows service manager; use `btrfs-peek helper install`");
        }
        return Err(e).context("connecting to the service manager");
    }
    Ok(())
}

fn report(state: u32, exit_code: u32) {
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    unsafe { SetServiceStatus(STATUS.load(Ordering::SeqCst), &st) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name = wide(SERVICE);
    let h = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null()) };
    if h.is_null() {
        return;
    }
    STATUS.store(h, Ordering::SeqCst);
    report(SERVICE_RUNNING, NO_ERROR);
    let sid = SID.get().map_or("", String::as_str);
    let Err(e) = listen(PIPE, sid, open_partition);
    report(SERVICE_STOPPED, e.raw_os_error().map_or(1, |c| c as u32));
}

unsafe extern "system" fn control(
    code: u32,
    _event: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // Clients' sessions are reads; ending them mid-read loses nothing.
            report(SERVICE_STOPPED, NO_ERROR);
            std::process::exit(0)
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// The pipe's security: network logons denied, SYSTEM (the service) full
/// access, and the one allowed account CLIENT_ACCESS. Protected, so nothing
/// is inherited.
fn pipe_sddl(sid: &str) -> String {
    format!("D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;{CLIENT_ACCESS:#x};;;{sid})")
}

/// Makes instances of one pipe name under one security descriptor.
struct PipeServer {
    name: Vec<u16>,
    sa: SECURITY_ATTRIBUTES,
    _sd: Local,
}

impl PipeServer {
    fn new(name: &str, sddl: &str) -> io::Result<PipeServer> {
        let text = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PipeServer {
            name: wide(name),
            sa: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            },
            _sd: Local(sd),
        })
    }

    /// A new instance, waiting for a client. The first must be new: if
    /// someone else already owns the name, fail loudly rather than share it.
    fn create(&self, first: bool) -> io::Result<File> {
        let first = if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                PIPE_ACCESS_DUPLEX | first,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 << 10,
                64 << 10,
                0,
                &self.sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(h) })
    }
}

/// Serves `name` until something fails: one thread per client, `open`
/// deciding what each may read. Only `sid` (and SYSTEM) may connect.
pub fn listen(
    name: &str,
    sid: &str,
    open: fn(&str) -> std::result::Result<File, Refusal>,
) -> io::Result<Infallible> {
    if !sid_ok(sid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{sid}: not a SID"),
        ));
    }
    serve_pipe(&PipeServer::new(name, &pipe_sddl(sid))?, open)
}

fn serve_pipe(
    server: &PipeServer,
    open: fn(&str) -> std::result::Result<File, Refusal>,
) -> io::Result<Infallible> {
    let mut next = server.create(true)?;
    loop {
        let pipe = next;
        let connected = if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), null_mut()) } != 0 {
            Ok(())
        } else {
            let e = io::Error::last_os_error();
            if is(&e, ERROR_PIPE_CONNECTED) {
                Ok(())
            } else {
                Err(e)
            }
        };
        // The next instance exists before this one can close, so the name
        // never lapses for another process to take.
        next = server.create(false)?;
        match connected {
            Ok(()) => {
                std::thread::spawn(move || serve_client(pipe, open));
            }
            // The client left before we saw it.
            Err(e) if is(&e, ERROR_NO_DATA) => {}
            Err(e) => return Err(e),
        }
    }
}

// --- The client ---

/// Opens `name`; None if it does not exist. With `verify`, the server must be
/// the installed service: a process that took the name first gets nothing.
pub fn connect_to(name: &str, verify: bool) -> io::Result<Option<File>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let pipe = loop {
        // Identification only: the server may learn who we are, never act as us.
        let r = OpenOptions::new()
            .access_mode(CLIENT_ACCESS)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name);
        match r {
            Ok(f) => break f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            // Every instance is taken; the service makes another as soon as it can.
            Err(e) if is(&e, ERROR_PIPE_BUSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) => return Err(e),
        }
    };
    if verify {
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Other, not PermissionDenied: `open_error` would turn that into "run elevated".
        if service_pid().ok().flatten() != Some(pid) {
            return Err(io::Error::other(format!(
                "{PIPE} is not served by the installed btrfs-peek helper; refusing to trust it"
            )));
        }
    }
    Ok(Some(pipe))
}

/// A partition opened through the helper.
pub struct Remote(Mutex<Session<File>>);

impl Remote {
    /// None when no helper is installed (the pipe does not exist).
    pub fn open(path: &str) -> io::Result<Option<Remote>> {
        let Some(pipe) = connect_to(PIPE, true)? else {
            return Ok(None);
        };
        let (mut s, _version) = Session::start(pipe)?;
        s.open(path)?;
        Ok(Some(Remote(Mutex::new(s))))
    }

    pub fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.read_at(buf, off)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{exercise, test_open};
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;

    fn unique_pipe() -> String {
        static N: AtomicUsize = AtomicUsize::new(0);
        format!(
            r"\\.\pipe\btrfs-peek-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// A test server runs as the same account as its client, and must be
    /// able to make more instances, which the real SDDL denies that account
    /// (it takes read and write: FILE_GENERIC_WRITE includes
    /// FILE_CREATE_PIPE_INSTANCE). The client still asks for CLIENT_ACCESS only.
    fn test_server(name: &str, sid: &str) -> io::Result<Infallible> {
        let sddl = pipe_sddl(sid).replace(
            &format!("{CLIENT_ACCESS:#x}"),
            &format!("{:#x}", FILE_GENERIC_READ | FILE_GENERIC_WRITE),
        );
        serve_pipe(&PipeServer::new(name, &sddl)?, test_open)
    }

    fn spawn_test_server() -> (String, String) {
        let name = unique_pipe();
        let sid = current_user_sid().unwrap();
        let (n, s) = (name.clone(), sid.clone());
        std::thread::spawn(move || test_server(&n, &s));
        (name, sid)
    }

    fn connect(name: &str) -> File {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match connect_to(name, false).unwrap() {
                Some(f) => return f,
                None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                None => panic!("{name} never appeared"),
            }
        }
    }

    #[test]
    fn program_files_comes_from_the_registry() {
        let p = program_files();
        assert!(p.is_absolute(), "{}", p.display());
        assert!(p.ends_with("Program Files"), "{}", p.display());
    }

    #[test]
    fn protocol_round_trip_over_a_named_pipe() {
        let (name, _) = spawn_test_server();
        exercise(|| connect(&name), "pipe");
    }

    /// The real SDDL: the allowed account gets CLIENT_ACCESS, and cannot add
    /// instances of the pipe to answer other clients itself.
    #[test]
    fn the_allowed_account_may_connect_but_not_serve() {
        let name = unique_pipe();
        let sid = current_user_sid().unwrap();
        assert!(sid_ok(&sid), "{sid}");
        let server = PipeServer::new(&name, &pipe_sddl(&sid)).unwrap();
        let _first = server.create(true).unwrap();
        let e = server.create(false).unwrap_err();
        assert!(is(&e, ERROR_ACCESS_DENIED), "{e}");
        assert!(connect_to(&name, false).unwrap().is_some());
    }

    #[test]
    fn a_second_server_cannot_take_the_name() {
        let (name, sid) = spawn_test_server();
        drop(connect(&name));
        let Err(e) = test_server(&name, &sid);
        assert!(is(&e, ERROR_ACCESS_DENIED), "{e}");
    }

    #[test]
    fn an_unverified_server_is_refused() {
        let (name, _) = spawn_test_server();
        drop(connect(&name));
        let e = connect_to(&name, true).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Other);
        assert!(e.to_string().contains("refusing to trust it"), "{e}");
    }
}
