//! Server-side handlers for `ClientReq::RequestShell`.
//!
//! Phase 16 implements the two non-interactive modes:
//! - `Oneshot` — run to completion, capture output, one response frame.
//! - `FireAndForget` — detach the child, return its pid immediately.
//!
//! `Interactive` is deferred to Phase 17 since it requires a PTY crate
//! + matching client-side terminal handling. Phase 16 responds
//! `Error{NotYetSupported}` for that mode.
//!
//! The default program is chosen at call time so the same config parses
//! cleanly on both Windows and Unix:
//! - Windows: `%ComSpec%` → `cmd.exe`.
//! - Unix: `$SHELL` → `/bin/sh`.
//!
//! `args` is passed verbatim to the child — no shell interpolation on
//! the server side.

use std::process::Stdio;

use tokio::process::Command;
use tokio::sync::mpsc;

use crate::proxy::ProxyMsg;
use crate::runtime::{ConnectionId, SmoltcpHandle};
use crate::wire::{ErrorKind, ServerResp, ShellMode};

/// Execute a `RequestShell` for the non-interactive modes. Returns a
/// response frame the control handler writes back, then closes the
/// flow. Interactive mode is NOT handled here — it takes over the flow
/// and uses [`run_interactive`] instead.
pub async fn handle_shell_request(
    mode: ShellMode,
    program: Option<String>,
    args: Vec<String>,
) -> ServerResp {
    match mode {
        ShellMode::Interactive => {
            // Callers who reach this path with Interactive mode have a
            // wiring bug — interactive sessions are dispatched via
            // `run_interactive` before we return a synchronous response.
            ServerResp::Error {
                kind: ErrorKind::Internal,
                msg: "interactive mode must be dispatched via run_interactive".into(),
            }
        }
        ShellMode::Oneshot => run_oneshot(program, args).await,
        ShellMode::FireAndForget => run_detached(program, args),
    }
}

pub fn default_program() -> String {
    if cfg!(windows) {
        std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".to_string())
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

/// Run an interactive shell on the control flow. Spawns a PTY + child
/// via `portable-pty`, then runs three concurrent pumps:
///   * client → PTY: decode framed STDIN / RESIZE / STDIN_EOF frames,
///     apply to the PTY master or child stdin.
///   * PTY → client: encode PTY reader output as STDOUT frames, write
///     back through smoltcp.
///   * child watcher: await exit, emit EXIT frame, tear down.
///
/// The control handler calls this AFTER writing `ServerResp::ShellReady`
/// on the flow. `leftover` holds any bytes already pulled from the
/// smoltcp side that belong to the framed protocol (empty in the
/// common case where the client waits for ShellReady before sending
/// STDIN).
pub async fn run_interactive(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    leftover: Vec<u8>,
    msg_rx: mpsc::UnboundedReceiver<ProxyMsg>,
    program: Option<String>,
    args: Vec<String>,
) {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use tokio::io::AsyncWriteExt;

    // Bridge the smoltcp-side ProxyMsg stream into a plain AsyncRead.
    // The reader task writes every incoming Data chunk into the duplex
    // half; the main interactive logic reads framed bytes from the
    // other half.
    let (mut client_reader, client_writer_half) = tokio::io::duplex(64 * 1024);
    let read_bridge = {
        let mut msg_rx = msg_rx;
        let mut writer = client_writer_half;
        tokio::spawn(async move {
            if !leftover.is_empty() {
                if writer.write_all(&leftover).await.is_err() {
                    return;
                }
            }
            while let Some(msg) = msg_rx.recv().await {
                match msg {
                    ProxyMsg::Data(d) => {
                        if writer.write_all(&d).await.is_err() {
                            return;
                        }
                    }
                    ProxyMsg::PeerFin | ProxyMsg::Closed => return,
                }
            }
        })
    };

    // Spawn the PTY + child.
    let pty_system = native_pty_system();
    let pty_pair = match pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    }) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(?id, error = %e, "interactive: openpty failed");
            send_exit_and_close(&smoltcp, id, -1).await;
            read_bridge.abort();
            return;
        }
    };
    let resolved_program = program.unwrap_or_else(default_program);
    let mut cmd = CommandBuilder::new(&resolved_program);
    for a in args {
        cmd.arg(a);
    }
    // Inherit a reasonable TERM so CLI tools emit ANSI.
    if std::env::var("TERM").is_err() {
        cmd.env("TERM", "xterm-256color");
    }
    let child = match pty_pair.slave.spawn_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(?id, program = %resolved_program, error = %e, "interactive: spawn failed");
            send_exit_and_close(&smoltcp, id, -1).await;
            read_bridge.abort();
            return;
        }
    };
    // Parent doesn't need the slave end.
    drop(pty_pair.slave);
    let master = pty_pair.master;
    let pty_reader = match master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(?id, error = %e, "interactive: clone_reader failed");
            send_exit_and_close(&smoltcp, id, -1).await;
            read_bridge.abort();
            return;
        }
    };
    let pty_writer = match master.take_writer() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(?id, error = %e, "interactive: take_writer failed");
            send_exit_and_close(&smoltcp, id, -1).await;
            read_bridge.abort();
            return;
        }
    };
    tracing::info!(?id, program = %resolved_program, "interactive shell started");

    // master is moved into a shared handle for resize + child drop.
    let master = std::sync::Arc::new(std::sync::Mutex::new(Some(master)));

    // Bridge PTY writer (std::io::Write) + reader (std::io::Read) to
    // tokio. spawn_blocking wraps each end in a task.
    let (pty_stdin_tx, mut pty_stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let pty_writer_task = tokio::task::spawn_blocking({
        let mut writer = pty_writer;
        move || {
            use std::io::Write;
            while let Some(bytes) = pty_stdin_rx.blocking_recv() {
                if writer.write_all(&bytes).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
        }
    });

    let (pty_stdout_tx, mut pty_stdout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let pty_reader_task = tokio::task::spawn_blocking({
        let mut reader = pty_reader;
        move || {
            use std::io::Read;
            let mut buf = [0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if pty_stdout_tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    // Child watcher — runs blocking .wait() and reports exit code.
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<i32>();
    let child_task = tokio::task::spawn_blocking({
        let mut child = child;
        move || {
            let status = match child.wait() {
                Ok(s) => s.exit_code() as i32,
                Err(_) => -1,
            };
            let _ = exit_tx.send(status);
        }
    });

    // Main pump: read framed bytes from client → dispatch to PTY,
    // forward PTY stdout → STDOUT frames, terminate on child exit.
    // Everything is in a single select! loop; keeps one mutable borrow
    // of each channel end.
    let smoltcp_w = smoltcp.clone();
    let mut exit_rx = exit_rx;
    let mut exit_status: Option<i32> = None;
    let mut scratch = Vec::new();
    loop {
        use crate::shell_protocol::{read_frame, Frame};
        tokio::select! {
            // Inbound frame from the client.
            frame_res = read_frame(&mut client_reader, &mut scratch) => {
                match frame_res {
                    Ok(Frame::Stdin(data)) => {
                        if pty_stdin_tx.send(data.to_vec()).is_err() { break; }
                    }
                    Ok(Frame::Resize { cols, rows }) => {
                        if let Some(m) = master.lock().unwrap().as_ref() {
                            let _ = m.resize(PtySize { cols, rows, pixel_width: 0, pixel_height: 0 });
                        }
                    }
                    Ok(Frame::StdinEof) => {
                        // Dropping the sender would close the channel,
                        // but we still own the main sender here — convert
                        // to "no more client stdin will come". Breaking
                        // the loop lets us handle outbound drain + exit.
                        break;
                    }
                    Ok(_) => { /* ignore unknown / server-only frames */ }
                    Err(e) => {
                        tracing::debug!(?id, error = %e, "interactive: frame read ended");
                        break;
                    }
                }
            }
            // Outbound stdout chunk from PTY.
            Some(out) = pty_stdout_rx.recv() => {
                if send_stdout_frame(&smoltcp_w, id, &out).await.is_err() { break; }
            }
            // Child exited.
            res = &mut exit_rx => {
                exit_status = Some(res.unwrap_or(-1));
                break;
            }
        }
    }

    // If pump ended first (client disconnect), drop the PTY master so
    // the child gets SIGHUP / closed console.
    if exit_status.is_none() {
        let mut guard = master.lock().unwrap();
        *guard = None;
    }

    // Drain any last stdout produced between the pump exit and now.
    while let Ok(out) = pty_stdout_rx.try_recv() {
        let _ = send_stdout_frame(&smoltcp_w, id, &out).await;
    }

    let exit_code = if let Some(c) = exit_status {
        c
    } else {
        // Wait briefly for the child to actually exit after we dropped
        // the master.
        match tokio::time::timeout(std::time::Duration::from_secs(5), exit_rx).await {
            Ok(Ok(c)) => c,
            _ => -1,
        }
    };
    tracing::info!(?id, exit_code, "interactive shell ended");

    send_exit_and_close(&smoltcp_w, id, exit_code).await;

    pty_writer_task.abort();
    pty_reader_task.abort();
    child_task.abort();
    read_bridge.abort();
}

async fn send_stdout_frame(
    smoltcp: &SmoltcpHandle,
    id: ConnectionId,
    data: &[u8],
) -> Result<(), ()> {
    // Manual frame: u8 tag + u32 be len + payload, emitted as one
    // `write_tcp` call so smoltcp doesn't split the frame header from
    // its body across poll cycles.
    let mut buf = Vec::with_capacity(5 + data.len());
    buf.push(crate::shell_protocol::TAG_STDOUT);
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
    write_all_tcp(smoltcp, id, &buf).await
}

async fn send_exit_and_close(smoltcp: &SmoltcpHandle, id: ConnectionId, status: i32) {
    let mut buf = Vec::with_capacity(9);
    buf.push(crate::shell_protocol::TAG_EXIT);
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(&status.to_be_bytes());
    let _ = write_all_tcp(smoltcp, id, &buf).await;
    smoltcp.close_tcp(id);
}

/// Push `data` through smoltcp's write-tcp pipe in full, retrying
/// briefly on `Ok(0)` (buffer full). Gives up after 500 iterations
/// (~1 s) to avoid wedging the interactive session on a broken flow.
async fn write_all_tcp(smoltcp: &SmoltcpHandle, id: ConnectionId, data: &[u8]) -> Result<(), ()> {
    let mut remaining = data;
    for _ in 0..500 {
        if remaining.is_empty() {
            return Ok(());
        }
        match smoltcp.write_tcp(id, remaining.to_vec()).await {
            Ok(0) => tokio::time::sleep(std::time::Duration::from_millis(2)).await,
            Ok(n) => remaining = &remaining[n..],
            Err(_) => return Err(()),
        }
    }
    Err(())
}

async fn run_oneshot(program: Option<String>, args: Vec<String>) -> ServerResp {
    let program = program.unwrap_or_else(default_program);
    let output = match Command::new(&program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            return ServerResp::Error {
                kind: ErrorKind::Internal,
                msg: format!("spawn `{program}`: {e}"),
            };
        }
    };
    ServerResp::ShellResult {
        exit_code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn run_detached(program: Option<String>, args: Vec<String>) -> ServerResp {
    let program = program.unwrap_or_else(default_program);
    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // `kill_on_drop(false)` is the default, but stating it makes the
    // fire-and-forget semantics explicit: when `child` drops at the end
    // of this function, the child process must keep running.
    cmd.kill_on_drop(false);
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ServerResp::Error {
                kind: ErrorKind::Internal,
                msg: format!("spawn `{program}`: {e}"),
            };
        }
    };
    let pid = child.id().unwrap_or(0);
    // Explicitly drop the handle so wait-on-drop behaviors don't fire.
    drop(child);
    ServerResp::ShellSpawned { pid }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Interactive mode is dispatched via `run_interactive` before the
    // synchronous-response path, so `handle_shell_request` no longer
    // sees it under normal flow. The legacy NotYetSupported check was
    // removed once Phase 17b wired interactive end-to-end.

    #[tokio::test]
    async fn oneshot_captures_stdout() {
        // Use a command that's on every platform:
        //   Windows:  cmd.exe /C echo hello
        //   Unix:     /bin/sh -c "echo hello"
        let (program, args) = if cfg!(windows) {
            (
                Some("cmd.exe".to_string()),
                vec!["/C".to_string(), "echo hello".to_string()],
            )
        } else {
            (
                Some("/bin/sh".to_string()),
                vec!["-c".to_string(), "echo hello".to_string()],
            )
        };
        let resp = handle_shell_request(ShellMode::Oneshot, program, args).await;
        match resp {
            ServerResp::ShellResult {
                exit_code,
                stdout,
                stderr: _,
            } => {
                assert_eq!(exit_code, Some(0));
                let stdout_str = String::from_utf8_lossy(&stdout);
                assert!(
                    stdout_str.contains("hello"),
                    "expected 'hello' in stdout, got {stdout_str:?}"
                );
            }
            other => panic!("expected ShellResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oneshot_nonzero_exit() {
        // Always returns a non-zero exit.
        let (program, args) = if cfg!(windows) {
            (
                Some("cmd.exe".to_string()),
                vec!["/C".to_string(), "exit 7".to_string()],
            )
        } else {
            (
                Some("/bin/sh".to_string()),
                vec!["-c".to_string(), "exit 7".to_string()],
            )
        };
        let resp = handle_shell_request(ShellMode::Oneshot, program, args).await;
        match resp {
            ServerResp::ShellResult { exit_code, .. } => {
                assert_eq!(exit_code, Some(7));
            }
            other => panic!("expected ShellResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oneshot_missing_program_errors() {
        let resp = handle_shell_request(
            ShellMode::Oneshot,
            Some("this-binary-definitely-does-not-exist-zzz".to_string()),
            vec![],
        )
        .await;
        match resp {
            ServerResp::Error {
                kind: ErrorKind::Internal,
                ..
            } => (),
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fire_and_forget_returns_pid() {
        // A trivially short-lived program. We don't wait for it.
        let (program, args) = if cfg!(windows) {
            (
                Some("cmd.exe".to_string()),
                vec!["/C".to_string(), "exit 0".to_string()],
            )
        } else {
            (
                Some("/bin/sh".to_string()),
                vec!["-c".to_string(), "exit 0".to_string()],
            )
        };
        let resp = handle_shell_request(ShellMode::FireAndForget, program, args).await;
        match resp {
            ServerResp::ShellSpawned { pid } => {
                assert!(pid > 0, "expected a nonzero pid, got {pid}");
            }
            other => panic!("expected ShellSpawned, got {other:?}"),
        }
    }
}
