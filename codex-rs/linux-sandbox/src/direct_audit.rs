use codex_sandbox_audit::FS_RECORD_SCHEMA_VERSION;
use codex_sandbox_audit::STRACE_RAW_FILE;
use codex_sandbox_audit::SandboxAuditEventMetadata;
use codex_sandbox_audit::SandboxAuditExecConfig;
use codex_sandbox_audit::finalize_strace_log;
use codex_sandbox_audit::now_unix_ms;
use codex_sandbox_audit::path_has_output_component;
use codex_sandbox_audit::prepare_event_dir;
use codex_sandbox_audit::write_event_metadata;
use std::path::Path;

pub(crate) fn run_direct_audit(
    config: SandboxAuditExecConfig,
    command: Vec<String>,
    command_cwd: &Path,
) -> ! {
    let event_dir = prepare_event_dir(&config)
        .unwrap_or_else(|err| panic!("failed to prepare sandbox audit event: {err}"));
    write_event_metadata(
        &event_dir,
        &SandboxAuditEventMetadata {
            schema_version: FS_RECORD_SCHEMA_VERSION,
            event_id: config.event_id.clone(),
            tool_name: config.tool_name.clone(),
            call_id: config.call_id.clone(),
            command: command.clone(),
            cwd: command_cwd.to_path_buf(),
            sandbox: "linux-direct-ptrace".to_string(),
            started_at_unix_ms: now_unix_ms(),
        },
    )
    .unwrap_or_else(|err| panic!("failed to write sandbox audit event metadata: {err}"));

    let raw_log_path = event_dir.join(STRACE_RAW_FILE);
    let exit_code = match imp::trace_command(&command, command_cwd, &raw_log_path) {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("sandbox audit direct tracer failed: {err}");
            1
        }
    };

    if let Err(err) = finalize_strace_log(&config.event_id, &event_dir) {
        eprintln!("sandbox audit failed to finalize syscall records: {err}");
    }
    std::process::exit(exit_code);
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs;
    use std::fs::File;
    use std::io;
    use std::io::BufWriter;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    const MAX_TRACE_STRING_BYTES: usize = 4096;

    #[derive(Debug)]
    struct ProcessState {
        entering_syscall: bool,
        pending: Option<SyscallEntry>,
    }

    #[derive(Debug)]
    struct SyscallEntry {
        name: &'static str,
        paths: Vec<String>,
        rendered_args: String,
        deny_with_eperm: bool,
    }

    pub(super) fn trace_command(
        command: &[String],
        command_cwd: &Path,
        raw_log_path: &Path,
    ) -> io::Result<i32> {
        if command.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct audit command is empty",
            ));
        }
        let command_cstrings = command
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "direct audit command contains an interior NUL byte",
                )
            })?;
        let cwd_cstring = CString::new(command_cwd.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct audit cwd contains an interior NUL byte",
            )
        })?;

        let mut raw_log = BufWriter::new(File::create(raw_log_path)?);
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(io::Error::last_os_error());
        }
        if child == 0 {
            child_exec_traced(&command_cstrings, &cwd_cstring);
        }

        wait_for_initial_stop(child)?;
        set_trace_options(child)?;
        let mut states = BTreeMap::from([(
            child,
            ProcessState {
                entering_syscall: false,
                pending: None,
            },
        )]);
        resume_syscall(child, /*signal*/ 0)?;

        let mut root_status = None;
        while !states.is_empty() {
            let (pid, status) = wait_for_trace_event()?;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                states.remove(&pid);
                if pid == child {
                    root_status = Some(status);
                }
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                resume_syscall(pid, /*signal*/ 0)?;
                continue;
            }

            let signal = libc::WSTOPSIG(status);
            if signal == (libc::SIGTRAP | 0x80) {
                handle_syscall_stop(pid, &mut states, &mut raw_log)?;
                resume_syscall(pid, /*signal*/ 0)?;
                continue;
            }

            if signal == libc::SIGTRAP {
                handle_ptrace_event(pid, status, &mut states)?;
                resume_syscall(pid, /*signal*/ 0)?;
                continue;
            }

            let delivered_signal = if signal == libc::SIGSTOP { 0 } else { signal };
            resume_syscall(pid, delivered_signal)?;
        }
        raw_log.flush()?;

        Ok(root_status.map(wait_status_exit_code).unwrap_or(1))
    }

    fn child_exec_traced(command: &[CString], cwd: &CString) -> ! {
        if unsafe { libc::chdir(cwd.as_ptr()) } < 0 {
            let err = io::Error::last_os_error();
            eprintln!("direct audit child failed to chdir: {err}");
            unsafe { libc::_exit(127) };
        }
        if unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        } < 0
        {
            let err = io::Error::last_os_error();
            eprintln!("direct audit child failed to enable ptrace: {err}");
            unsafe { libc::_exit(127) };
        }
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        let mut argv = command
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>();
        unsafe {
            libc::execvp(command[0].as_ptr(), argv.as_mut_ptr());
        }
        let err = io::Error::last_os_error();
        eprintln!("direct audit child failed to exec: {err}");
        unsafe { libc::_exit(127) };
    }

    fn wait_for_initial_stop(pid: libc::pid_t) -> io::Result<()> {
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if libc::WIFSTOPPED(status) {
                return Ok(());
            }
            return Err(io::Error::other("direct audit child exited before tracing"));
        }
    }

    fn wait_for_trace_event() -> io::Result<(libc::pid_t, libc::c_int)> {
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
            if pid >= 0 {
                return Ok((pid, status));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }

    fn set_trace_options(pid: libc::pid_t) -> io::Result<()> {
        let options = libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_EXITKILL;
        ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut(),
            options as usize as *mut libc::c_void,
        )?;
        Ok(())
    }

    fn handle_ptrace_event(
        pid: libc::pid_t,
        status: libc::c_int,
        states: &mut BTreeMap<libc::pid_t, ProcessState>,
    ) -> io::Result<()> {
        let event = status >> 16;
        if event == libc::PTRACE_EVENT_EXEC {
            if let Some(state) = states.get_mut(&pid) {
                state.entering_syscall = false;
                state.pending = None;
            }
            return Ok(());
        }
        if !matches!(
            event,
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE
        ) {
            return Ok(());
        }

        let mut event_msg = 0_usize;
        ptrace(
            libc::PTRACE_GETEVENTMSG,
            pid,
            std::ptr::null_mut(),
            (&mut event_msg as *mut usize).cast(),
        )?;
        let new_pid = event_msg as libc::pid_t;
        if new_pid > 0 {
            let _ = set_trace_options(new_pid);
            states.insert(
                new_pid,
                ProcessState {
                    entering_syscall: false,
                    pending: None,
                },
            );
        }
        Ok(())
    }

    fn handle_syscall_stop(
        pid: libc::pid_t,
        states: &mut BTreeMap<libc::pid_t, ProcessState>,
        raw_log: &mut BufWriter<File>,
    ) -> io::Result<()> {
        let entering_syscall = states
            .get(&pid)
            .map(|state| state.entering_syscall)
            .unwrap_or(true);
        if entering_syscall {
            let mut regs = get_regs(pid)?;
            let entry = syscall_entry(pid, &regs);
            if let Some(entry) = &entry
                && entry.deny_with_eperm
            {
                regs.orig_rax = u64::MAX;
                set_regs(pid, &regs)?;
            }
            let state = states.entry(pid).or_insert(ProcessState {
                entering_syscall: false,
                pending: None,
            });
            state.pending = entry;
            state.entering_syscall = false;
            return Ok(());
        }

        let mut regs = get_regs(pid)?;
        let mut result = regs.rax as i64;
        let pending = states.get_mut(&pid).and_then(|state| {
            state.entering_syscall = true;
            state.pending.take()
        });
        if let Some(entry) = pending {
            if entry.deny_with_eperm {
                result = -(libc::EPERM as i64);
                regs.rax = result as u64;
                set_regs(pid, &regs)?;
            }
            write_raw_syscall(raw_log, pid, &entry, result)?;
        }
        Ok(())
    }

    fn syscall_entry(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Option<SyscallEntry> {
        let syscall = regs.orig_rax as libc::c_long;
        let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        match syscall {
            libc::SYS_open => path_syscall(pid, "open", None, args[0], &[args[1]]),
            libc::SYS_creat => path_syscall(pid, "creat", None, args[0], &[args[1]]),
            libc::SYS_openat => path_syscall(
                pid,
                "openat",
                Some(args[0] as i64),
                args[1],
                &[args[0], args[2]],
            ),
            libc::SYS_openat2 => {
                path_syscall(pid, "openat2", Some(args[0] as i64), args[1], &[args[0]])
            }
            libc::SYS_mkdir => path_syscall(pid, "mkdir", None, args[0], &[args[1]]),
            libc::SYS_mkdirat => path_syscall(
                pid,
                "mkdirat",
                Some(args[0] as i64),
                args[1],
                &[args[0], args[2]],
            ),
            libc::SYS_mknod => path_syscall(pid, "mknod", None, args[0], &[args[1], args[2]]),
            libc::SYS_mknodat => path_syscall(
                pid,
                "mknodat",
                Some(args[0] as i64),
                args[1],
                &[args[0], args[2], args[3]],
            ),
            libc::SYS_truncate => path_syscall(pid, "truncate", None, args[0], &[args[1]]),
            libc::SYS_chmod => path_syscall(pid, "chmod", None, args[0], &[args[1]]),
            libc::SYS_chown => path_syscall(pid, "chown", None, args[0], &[args[1], args[2]]),
            libc::SYS_fchmodat => path_syscall(
                pid,
                "fchmodat",
                Some(args[0] as i64),
                args[1],
                &[args[0], args[2]],
            ),
            libc::SYS_fchownat => path_syscall(
                pid,
                "fchownat",
                Some(args[0] as i64),
                args[1],
                &[args[0], args[2], args[3], args[4]],
            ),
            libc::SYS_utime => path_syscall(pid, "utime", None, args[0], &[args[1]]),
            libc::SYS_utimes => path_syscall(pid, "utimes", None, args[0], &[args[1]]),
            libc::SYS_utimensat => path_syscall(
                pid,
                "utimensat",
                Some(args[0] as i64),
                args[1],
                &[args[0], args[2], args[3]],
            ),
            libc::SYS_setxattr => path_syscall(pid, "setxattr", None, args[0], &[args[1]]),
            libc::SYS_lsetxattr => path_syscall(pid, "lsetxattr", None, args[0], &[args[1]]),
            libc::SYS_unlink => guarded_path_syscall(pid, "unlink", None, args[0], &[]),
            libc::SYS_unlinkat => guarded_path_syscall(
                pid,
                "unlinkat",
                Some(args[0] as i64),
                args[1],
                &[args[0], args[2]],
            ),
            libc::SYS_rmdir => guarded_path_syscall(pid, "rmdir", None, args[0], &[]),
            libc::SYS_rename => {
                guarded_two_path_syscall(pid, "rename", None, args[0], None, args[1], &[])
            }
            libc::SYS_renameat => guarded_two_path_syscall(
                pid,
                "renameat",
                Some(args[0] as i64),
                args[1],
                Some(args[2] as i64),
                args[3],
                &[args[0], args[2]],
            ),
            libc::SYS_renameat2 => guarded_two_path_syscall(
                pid,
                "renameat2",
                Some(args[0] as i64),
                args[1],
                Some(args[2] as i64),
                args[3],
                &[args[0], args[2], args[4]],
            ),
            libc::SYS_link => two_path_syscall(pid, "link", None, args[0], None, args[1], &[]),
            libc::SYS_linkat => two_path_syscall(
                pid,
                "linkat",
                Some(args[0] as i64),
                args[1],
                Some(args[2] as i64),
                args[3],
                &[args[0], args[2], args[4]],
            ),
            libc::SYS_symlink => {
                two_path_syscall(pid, "symlink", None, args[0], None, args[1], &[])
            }
            libc::SYS_symlinkat => two_path_syscall(
                pid,
                "symlinkat",
                None,
                args[0],
                Some(args[1] as i64),
                args[2],
                &[args[1]],
            ),
            libc::SYS_stat
            | libc::SYS_lstat
            | libc::SYS_access
            | libc::SYS_readlink
            | libc::SYS_getxattr
            | libc::SYS_lgetxattr
            | libc::SYS_listxattr
            | libc::SYS_llistxattr => path_syscall(pid, syscall_name(syscall)?, None, args[0], &[]),
            libc::SYS_newfstatat | libc::SYS_statx | libc::SYS_faccessat | libc::SYS_readlinkat => {
                path_syscall(
                    pid,
                    syscall_name(syscall)?,
                    Some(args[0] as i64),
                    args[1],
                    &[args[0]],
                )
            }
            _ => None,
        }
    }

    fn syscall_name(syscall: libc::c_long) -> Option<&'static str> {
        match syscall {
            libc::SYS_stat => Some("stat"),
            libc::SYS_lstat => Some("lstat"),
            libc::SYS_access => Some("access"),
            libc::SYS_readlink => Some("readlink"),
            libc::SYS_getxattr => Some("getxattr"),
            libc::SYS_lgetxattr => Some("lgetxattr"),
            libc::SYS_listxattr => Some("listxattr"),
            libc::SYS_llistxattr => Some("llistxattr"),
            libc::SYS_newfstatat => Some("newfstatat"),
            libc::SYS_statx => Some("statx"),
            libc::SYS_faccessat => Some("faccessat"),
            libc::SYS_readlinkat => Some("readlinkat"),
            _ => None,
        }
    }

    fn guarded_path_syscall(
        pid: libc::pid_t,
        name: &'static str,
        dirfd: Option<i64>,
        path_ptr: u64,
        extra_args: &[u64],
    ) -> Option<SyscallEntry> {
        let mut entry = path_syscall(pid, name, dirfd, path_ptr, extra_args)?;
        entry.deny_with_eperm = entry
            .paths
            .iter()
            .any(|path| tracee_path_targets_output(pid, dirfd, path));
        Some(entry)
    }

    fn guarded_two_path_syscall(
        pid: libc::pid_t,
        name: &'static str,
        first_dirfd: Option<i64>,
        first_path_ptr: u64,
        second_dirfd: Option<i64>,
        second_path_ptr: u64,
        extra_args: &[u64],
    ) -> Option<SyscallEntry> {
        let mut entry = two_path_syscall(
            pid,
            name,
            first_dirfd,
            first_path_ptr,
            second_dirfd,
            second_path_ptr,
            extra_args,
        )?;
        entry.deny_with_eperm = entry.paths.iter().enumerate().any(|(index, path)| {
            let dirfd = if index == 0 {
                first_dirfd
            } else {
                second_dirfd
            };
            tracee_path_targets_output(pid, dirfd, path)
        });
        Some(entry)
    }

    fn path_syscall(
        pid: libc::pid_t,
        name: &'static str,
        dirfd: Option<i64>,
        path_ptr: u64,
        extra_args: &[u64],
    ) -> Option<SyscallEntry> {
        let path = read_tracee_string(pid, path_ptr)?;
        let mut rendered_args = Vec::new();
        if let Some(dirfd) = dirfd {
            rendered_args.push(format_dirfd(dirfd));
        }
        rendered_args.push(quote_path(&path));
        rendered_args.extend(extra_args.iter().map(std::string::ToString::to_string));
        Some(SyscallEntry {
            name,
            paths: vec![path],
            rendered_args: rendered_args.join(", "),
            deny_with_eperm: false,
        })
    }

    fn two_path_syscall(
        pid: libc::pid_t,
        name: &'static str,
        first_dirfd: Option<i64>,
        first_path_ptr: u64,
        second_dirfd: Option<i64>,
        second_path_ptr: u64,
        extra_args: &[u64],
    ) -> Option<SyscallEntry> {
        let first = read_tracee_string(pid, first_path_ptr)?;
        let second = read_tracee_string(pid, second_path_ptr)?;
        let mut rendered_args = Vec::new();
        if let Some(dirfd) = first_dirfd {
            rendered_args.push(format_dirfd(dirfd));
        }
        rendered_args.push(quote_path(&first));
        if let Some(dirfd) = second_dirfd {
            rendered_args.push(format_dirfd(dirfd));
        }
        rendered_args.push(quote_path(&second));
        rendered_args.extend(extra_args.iter().map(std::string::ToString::to_string));
        Some(SyscallEntry {
            name,
            paths: vec![first, second],
            rendered_args: rendered_args.join(", "),
            deny_with_eperm: false,
        })
    }

    fn tracee_path_targets_output(pid: libc::pid_t, dirfd: Option<i64>, path: &str) -> bool {
        path_has_output_component(&resolve_tracee_path(pid, dirfd, path))
    }

    fn resolve_tracee_path(pid: libc::pid_t, dirfd: Option<i64>, path: &str) -> PathBuf {
        let path = Path::new(path);
        if path.is_absolute() {
            return path.to_path_buf();
        }
        let base = dirfd
            .filter(|fd| *fd != libc::AT_FDCWD as i64)
            .and_then(|fd| fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok())
            .or_else(|| fs::read_link(format!("/proc/{pid}/cwd")).ok())
            .unwrap_or_else(|| PathBuf::from("/"));
        base.join(path)
    }

    fn read_tracee_string(pid: libc::pid_t, addr: u64) -> Option<String> {
        if addr == 0 {
            return None;
        }
        let mut bytes = Vec::new();
        let word_size = std::mem::size_of::<libc::c_long>();
        while bytes.len() < MAX_TRACE_STRING_BYTES {
            let word = peek_data(pid, addr + bytes.len() as u64).ok()?;
            let word_bytes = word.to_ne_bytes();
            for byte in word_bytes {
                if byte == 0 {
                    return String::from_utf8(bytes).ok();
                }
                bytes.push(byte);
                if bytes.len() >= MAX_TRACE_STRING_BYTES {
                    break;
                }
            }
            if word_size == 0 {
                break;
            }
        }
        String::from_utf8(bytes).ok()
    }

    fn peek_data(pid: libc::pid_t, addr: u64) -> io::Result<libc::c_long> {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let value = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                pid,
                addr as usize as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        let errno = unsafe { *libc::__errno_location() };
        if value == -1 && errno != 0 {
            Err(io::Error::from_raw_os_error(errno))
        } else {
            Ok(value)
        }
    }

    fn get_regs(pid: libc::pid_t) -> io::Result<libc::user_regs_struct> {
        let mut regs = unsafe { std::mem::zeroed::<libc::user_regs_struct>() };
        ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut(),
            (&mut regs as *mut libc::user_regs_struct).cast(),
        )?;
        Ok(regs)
    }

    fn set_regs(pid: libc::pid_t, regs: &libc::user_regs_struct) -> io::Result<()> {
        ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut(),
            (regs as *const libc::user_regs_struct).cast_mut().cast(),
        )?;
        Ok(())
    }

    fn resume_syscall(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
        ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut(),
            signal as usize as *mut libc::c_void,
        )?;
        Ok(())
    }

    fn ptrace(
        request: libc::c_uint,
        pid: libc::pid_t,
        addr: *mut libc::c_void,
        data: *mut libc::c_void,
    ) -> io::Result<libc::c_long> {
        let result = unsafe { libc::ptrace(request, pid, addr, data) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    fn write_raw_syscall(
        raw_log: &mut BufWriter<File>,
        pid: libc::pid_t,
        entry: &SyscallEntry,
        result: i64,
    ) -> io::Result<()> {
        writeln!(
            raw_log,
            "{} {}({}) = {}",
            pid,
            entry.name,
            entry.rendered_args,
            format_syscall_result(result)
        )
    }

    fn format_syscall_result(result: i64) -> String {
        if (-4095..0).contains(&result) {
            let errno = -result as i32;
            return format!("-1 {} ({})", errno_name(errno), errno_description(errno));
        }
        result.to_string()
    }

    fn errno_name(errno: i32) -> &'static str {
        match errno {
            libc::EPERM => "EPERM",
            libc::ENOENT => "ENOENT",
            libc::EACCES => "EACCES",
            libc::EEXIST => "EEXIST",
            libc::ENOTDIR => "ENOTDIR",
            libc::EISDIR => "EISDIR",
            libc::EINVAL => "EINVAL",
            libc::ENOSYS => "ENOSYS",
            _ => "ERRNO",
        }
    }

    fn errno_description(errno: i32) -> String {
        io::Error::from_raw_os_error(errno).to_string()
    }

    fn quote_path(path: &str) -> String {
        format!("\"{}\"", escape_path(path))
    }

    fn escape_path(path: &str) -> String {
        path.chars()
            .flat_map(|ch| match ch {
                '\\' => "\\\\".chars().collect::<Vec<_>>(),
                '"' => "\\\"".chars().collect::<Vec<_>>(),
                '\n' => "\\n".chars().collect::<Vec<_>>(),
                '\r' => "\\r".chars().collect::<Vec<_>>(),
                '\t' => "\\t".chars().collect::<Vec<_>>(),
                other => vec![other],
            })
            .collect()
    }

    fn format_dirfd(dirfd: i64) -> String {
        if dirfd == libc::AT_FDCWD as i64 {
            "AT_FDCWD".to_string()
        } else {
            dirfd.to_string()
        }
    }

    fn wait_status_exit_code(status: libc::c_int) -> i32 {
        if libc::WIFEXITED(status) {
            return libc::WEXITSTATUS(status);
        }
        if libc::WIFSIGNALED(status) {
            return 128 + libc::WTERMSIG(status);
        }
        1
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod imp {
    use super::*;
    use std::io;

    pub(super) fn trace_command(
        _command: &[String],
        _command_cwd: &Path,
        _raw_log_path: &Path,
    ) -> io::Result<i32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "direct sandbox audit is not supported on this Linux architecture",
        ))
    }
}
