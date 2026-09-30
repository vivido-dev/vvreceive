//! Background Linux receiver for user-initiated Vivid file drops.

use std::fs::File;
use std::io::{self, Seek, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use cap_std::fs::OpenOptionsExt;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use sha2::{Digest, Sha256};
use vivid_sdk::{
    AdvanceFileTransfer, FileDropOffer, FileDropState, FileResult, FileResultCode,
    IncomingFileTransferEvent, IncomingFileTransferRequest, QueryFileDrop, RequestMetadata,
    Session,
};

/// A physically committed desktop drop whose terminal protocol result still needs reconciliation.
///
/// Keeping this separate from receipt lets a desktop's main control-loop own all correlated
/// control requests while bulk data and disk I/O remain on an independent worker.
pub struct CommittedFileDrop {
    final_name: String,
    result: FileResult,
    channel: vivid_sdk::IncomingFileTransfer,
    request: IncomingFileTransferRequest,
    sha256: [u8; 32],
}

/// Receive an already-opened transfer relative to an already-open destination directory.
///
/// Every create, link, and unlink remains relative to this retained OS directory handle. The path
/// that originally opened the directory is never consulted again.
pub fn receive_accepted(
    mut channel: vivid_sdk::IncomingFileTransfer,
    offer: FileDropOffer,
    directory: File,
) -> io::Result<CommittedFileDrop> {
    receive_to_directory(&mut channel, &offer, directory, || Ok(())).map(|(final_name, sha256)| {
        let result = FileResult {
            transfer_id: channel.request().transfer_id,
            transfer_generation: channel.request().transfer_generation,
            result: FileResultCode::Committed,
            committed_length: offer.declared_length,
            final_name: final_name.clone(),
            committed_path: None,
        };
        // Delivery is not acknowledgement; retain the exact result for control reconciliation.
        let _ = channel.send_result(&result);
        CommittedFileDrop {
            request: channel.request(),
            result,
            final_name,
            channel,
            sha256,
        }
    })
}

fn failure_result(channel: &vivid_sdk::IncomingFileTransfer, code: FileResultCode) {
    let request = channel.request();
    let _ = channel.send_result(&FileResult {
        transfer_id: request.transfer_id,
        transfer_generation: request.transfer_generation,
        result: code,
        committed_length: 0,
        final_name: String::new(),
        committed_path: None,
    });
}

fn receive_to_directory(
    channel: &mut vivid_sdk::IncomingFileTransfer,
    offer: &FileDropOffer,
    directory: File,
    check_live: impl Fn() -> io::Result<()>,
) -> io::Result<(String, [u8; 32])> {
    let directory = Dir::from_std_file(directory);
    let mut temporary_name = None;
    let mut failure = FileResultCode::IoError;
    let result = (|| {
        check_live().inspect_err(|_| failure = FileResultCode::Cancelled)?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let name = format!(".vivid-drop-{}", portable_hex(&random));
        let mut options = CapOpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut temporary = directory.open_with(&name, &options)?;
        temporary_name = Some(name.clone());
        let mut hasher = Sha256::new();
        let mut credit = Credit::new(channel.request());
        credit.start(channel)?;
        loop {
            check_live().inspect_err(|_| failure = FileResultCode::Cancelled)?;
            match channel.read_event()? {
                IncomingFileTransferEvent::Data { offset, bytes } => {
                    if temporary.stream_position()? != offset {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "temporary offset mismatch",
                        ));
                    }
                    write_hashed(&mut temporary, &mut hasher, &bytes)?;
                    credit.received(bytes.len(), channel)?;
                }
                IncomingFileTransferEvent::Finished(finish) => {
                    let actual: [u8; 32] = hasher.finalize().into();
                    if actual != finish.sha256 {
                        failure = FileResultCode::HashMismatch;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "file hash mismatch",
                        ));
                    }
                    temporary.sync_all()?;
                    check_live().inspect_err(|_| failure = FileResultCode::Cancelled)?;
                    for collision in 0..10_000 {
                        let candidate = collision_name(&offer.suggested_name, collision);
                        match directory.hard_link(&name, &directory, &candidate) {
                            Ok(()) => return Ok((candidate, actual)),
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                            Err(error) => return Err(error),
                        }
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "collision limit reached",
                    ));
                }
                IncomingFileTransferEvent::Aborted(_) => {
                    failure = FileResultCode::Cancelled;
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "sender aborted",
                    ));
                }
            }
        }
    })();
    if let Some(name) = temporary_name {
        let _ = directory.remove_file(name);
    }
    if result.is_err() {
        failure_result(channel, failure);
    }
    result
}

// Hash each successfully written prefix, so a partial write and subsequent error cannot
// separate the file position from the retained hash state.
fn write_hashed(writer: &mut impl Write, hasher: &mut Sha256, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "temporary write made no progress",
                ));
            }
            Ok(n) => {
                hasher.update(&bytes[..n]);
                bytes = &bytes[n..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct Credit {
    body: u64,
    records: u64,
    window_body: u64,
    window_records: u64,
    used_body: u64,
    used_records: u64,
    record_body: u64,
}

impl Credit {
    fn new(request: IncomingFileTransferRequest) -> Self {
        Self {
            body: request.maximum_body_bytes,
            records: request.maximum_records,
            window_body: request
                .maximum_body_bytes
                .max(u64::from(request.maximum_record_body)),
            window_records: request.maximum_records.max(1),
            used_body: 0,
            used_records: 0,
            record_body: u64::from(request.maximum_record_body),
        }
    }

    fn start(&mut self, channel: &mut vivid_sdk::IncomingFileTransfer) -> io::Result<()> {
        if self.body < self.record_body || self.records == 0 {
            self.body = self.body.max(self.record_body);
            self.records = self.records.max(1);
            channel.grant(self.body, self.records)?;
        }
        Ok(())
    }

    fn account(&mut self, length: usize) -> io::Result<Option<(u64, u64)>> {
        let overflow = || io::Error::new(io::ErrorKind::InvalidData, "credit overflow");
        self.used_body = self
            .used_body
            .checked_add(
                u64::try_from(length)
                    .map_err(|_| overflow())?
                    .checked_add(16)
                    .ok_or_else(overflow)?,
            )
            .ok_or_else(overflow)?;
        self.used_records = self.used_records.checked_add(1).ok_or_else(overflow)?;
        if self.body.saturating_sub(self.used_body) < self.record_body
            || self.records.saturating_sub(self.used_records) == 0
        {
            self.body = self
                .body
                .checked_add(self.window_body)
                .ok_or_else(overflow)?;
            self.records = self
                .records
                .checked_add(self.window_records)
                .ok_or_else(overflow)?;
            Ok(Some((self.body, self.records)))
        } else {
            Ok(None)
        }
    }

    fn received(
        &mut self,
        length: usize,
        channel: &mut vivid_sdk::IncomingFileTransfer,
    ) -> io::Result<()> {
        if let Some((body, records)) = self.account(length)? {
            channel.grant(body, records)?;
        }
        Ok(())
    }
}

/// Reconcile a physically committed file. Transport failures leave the committed file intact.
/// Callers needing to retry an uncertain result can retain it with `reconcile_committed_pending`.
pub fn reconcile_committed(
    session: &Session,
    mut committed: CommittedFileDrop,
) -> io::Result<String> {
    reconcile_committed_pending(session, &mut committed)?;
    Ok(committed.final_name)
}

/// Settle a committed result without consuming the state on a transient failure.
pub fn reconcile_committed_pending(
    session: &Session,
    committed: &mut CommittedFileDrop,
) -> io::Result<()> {
    reconcile(session, committed)
}

fn committed_status(
    status: &vivid_sdk::FileDropStatus,
    committed: &CommittedFileDrop,
) -> io::Result<bool> {
    let request = committed.request;
    if status.drop_id != request.drop_id || status.transfer_id != request.transfer_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file-drop status identity mismatch",
        ));
    }
    match status.state {
        FileDropState::Committed
            if status.final_name == committed.final_name
                && status.committed_offset == request.declared_length
                && matches!(
                    status.result,
                    Some(FileResultCode::Committed | FileResultCode::AlreadyCommitted)
                ) =>
        {
            Ok(true)
        }
        FileDropState::Accepted | FileDropState::Transferring => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file-drop status has a conflicting terminal outcome",
        )),
    }
}

fn reconcile(session: &Session, committed: &mut CommittedFileDrop) -> io::Result<()> {
    let mut last_error = io::Error::other("could not reconcile the committed file result");
    for attempt in 0..6 {
        let _ = committed.channel.send_result(&committed.result);
        let status = match session.query_file_drop(
            QueryFileDrop {
                drop_id: committed.request.drop_id,
            },
            &RequestMetadata::default(),
        ) {
            Ok(status) => status,
            Err(error) => {
                last_error = error;
                thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        if committed_status(&status, committed)? {
            return Ok(());
        }
        if attempt == 5 {
            break;
        }
        // The reply may follow a successful but unacknowledged advance. Adopt its generation
        // rather than repeatedly advancing from the stale local generation.
        if status.generation == committed.request.transfer_generation {
            let generation = status.generation.advance()?;
            match session.advance_file_transfer(
                AdvanceFileTransfer {
                    context_id: committed.request.context_id,
                    surface_id: committed.request.surface_id,
                    drop_id: committed.request.drop_id,
                    transfer_id: committed.request.transfer_id,
                    expected_generation: status.generation,
                    new_generation: generation,
                    committed_offset: committed.request.declared_length,
                    maximum_body_bytes: committed.request.maximum_body_bytes,
                    maximum_records: committed.request.maximum_records,
                },
                &RequestMetadata::default(),
            ) {
                Ok(_) => committed.request.transfer_generation = generation,
                Err(error) => {
                    last_error = error;
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
            }
        } else if status.generation == committed.request.transfer_generation.advance()? {
            committed.request.transfer_generation = status.generation;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file-drop status generation mismatch",
            ));
        }
        committed.request.resume_offset = committed.request.declared_length;
        match session.open_incoming_file_transfer(committed.request) {
            Ok(mut channel) => match channel.read_event() {
                Ok(IncomingFileTransferEvent::Finished(finish))
                    if finish.sha256 == committed.sha256
                        && finish.final_length == committed.request.declared_length =>
                {
                    committed.channel = channel;
                    committed.result.transfer_generation = committed.request.transfer_generation;
                    committed.result.result = FileResultCode::AlreadyCommitted;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "committed replay changed finish",
                    ));
                }
                Err(error) => last_error = error,
            },
            Err(error) => last_error = error,
        }
        // Always query again, including after failed advance/open/read: the original result
        // may have become terminal concurrently on the independent bulk connection.
        thread::sleep(Duration::from_millis(20));
    }
    Err(last_error)
}

fn collision_name(name: &str, collision: u32) -> String {
    if collision == 0 {
        return name.to_owned();
    }
    let path = Path::new(name);
    let original_stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("dropped-file");
    let suffix = format!(" ({collision})");
    let mut extension = path
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    const MAX_NAME: usize = vivid_protocol::file_drop::MAX_FILE_DROP_NAME_BYTES;
    if extension
        .len()
        .saturating_add(suffix.len())
        .saturating_add(1)
        > MAX_NAME
    {
        extension.clear();
    }
    let available = MAX_NAME.saturating_sub(suffix.len() + extension.len());
    let stem = truncate_utf8(original_stem, available);
    let stem = if stem.is_empty() {
        truncate_utf8("dropped-file", available)
    } else {
        stem
    };
    format!("{stem}{suffix}{extension}")
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> &str {
    let mut end = value.len().min(maximum_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn portable_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(unix)]
mod transport;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod os;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use std::fs::File;
    use std::io::{self, Seek, SeekFrom};
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use sha2::{Digest, Sha256};
    use vivid_protocol::file_drop::{
        DEFAULT_ACTIVE_FILE_TRANSFERS, DEFAULT_FILE_DROP_ACCEPTANCE_US,
        DEFAULT_FILE_TRANSFER_IDLE_US, DEFAULT_PENDING_FILE_DROPS, FileDropDestination, FileResult,
        FileResultCode, validate_committed_path,
    };
    use vivid_protocol::revision::{FileTransferGeneration, SurfaceGeneration};
    use vivid_protocol::{HARD_MAX_RECORD_BODY, registry};
    use vivid_sdk::{
        AcceptFileDrop, AdvanceFileTransfer, FileDropBindingGuard, IncomingFileTransferEvent,
        IncomingFileTransferRequest, ProducerAuthentication, ProducerConfig, RequestMetadata,
        Session, SessionEvent,
    };

    #[cfg(target_os = "macos")]
    pub use crate::os::open_macos_desktop;
    #[cfg(target_os = "linux")]
    pub use crate::os::open_xdg_desktop;
    use crate::os::{self, open_shell_cwd, process_start_time, resolve_directory};

    const MAXIMUM_FILE_BYTES: u64 = 1 << 40;
    const RECORD_BODY: u32 = 1024 * 1024;
    const CREDIT_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
    const CREDIT_WINDOW_RECORDS: u64 = 32;
    const MAXIMUM_RESUME_ATTEMPTS: u32 = 3;

    pub fn run() -> io::Result<()> {
        let (shell_pid, signal_ready) = parse_shell_pid()?;
        let shell_start = process_start_time(shell_pid)?;
        if signal_ready {
            // The vvssh wrapper installs SIGUSR1 before spawning us and does not exec the login
            // shell until this identity capture is complete.
            if unsafe { libc::kill(shell_pid as libc::pid_t, libc::SIGUSR1) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut required_profiles = vec![
            registry::CORE_CONTROL.to_owned(),
            registry::FILE_DROP.to_owned(),
            registry::TERMINAL_SURFACE.to_owned(),
        ];
        required_profiles.sort();
        let transport = std::sync::Arc::new(crate::transport::Transport::from_env()?);
        let _watch = crate::transport::Watch::start(transport.clone(), move || {
            ensure_shell(shell_pid, shell_start).is_ok()
        })?;
        let session = Session::connect_with_factory(
            ProducerConfig {
                authentication: ProducerAuthentication::RootFromEnvironment,
                producer_name: "vvreceive".into(),
                producer_version: env!("CARGO_PKG_VERSION").into(),
                target_profile: registry::TERMINAL_SURFACE.into(),
                required_profiles,
                // Optional, never required: an older presenter must still connect and copy.
                optional_profiles: vec![registry::FILE_DROP_PATH.to_owned()],
                ..ProducerConfig::default()
            },
            transport.clone(),
        )?;
        transport.established();
        let mut binding = FileDropBindingGuard::new();
        let request = binding.enable(
            session.info().root_context_id,
            0,
            SurfaceGeneration::ZERO,
            FileDropDestination::ShellCwd,
            MAXIMUM_FILE_BYTES,
            DEFAULT_PENDING_FILE_DROPS,
            DEFAULT_ACTIVE_FILE_TRANSFERS,
            RECORD_BODY.min(HARD_MAX_RECORD_BODY),
            DEFAULT_FILE_DROP_ACCEPTANCE_US,
            DEFAULT_FILE_TRANSFER_IDLE_US,
        )?;
        let grant = session.set_file_drop_binding(&request, &RequestMetadata::default())?;
        transport.set_idle(grant.idle_timeout_us);
        binding.handle_bound(grant)?;
        // Negotiation is the whole switch: a presenter that does not want the committed path
        // typed into its terminal simply never offers this profile.
        let disclose_path = session.supports(registry::FILE_DROP_PATH);
        while process_start_time(shell_pid).is_ok_and(|current| current == shell_start) {
            match session.take_event()? {
                Some(SessionEvent::FileDropOffered(offer)) => {
                    let maximum_record_body = binding
                        .grant()
                        .map(|grant| grant.maximum_record_body)
                        .ok_or_else(|| io::Error::other("file-drop grant is no longer active"))?;
                    if receive_offer(
                        &session,
                        &transport,
                        shell_pid,
                        shell_start,
                        maximum_record_body,
                        disclose_path,
                        offer.clone(),
                    )
                    .is_err()
                    {
                        // Only uncommitted failures reach here; cancellation is owner-scoped.
                        let _ = session.cancel_file_drop(
                            vivid_sdk::CancelFileDrop {
                                binding: offer.binding,
                                reason: 0,
                            },
                            &RequestMetadata::default(),
                        );
                    }
                }
                Some(SessionEvent::ConnectionClosed { .. }) => break,
                Some(_) | None => thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = session.set_file_drop_binding(&binding.disable()?, &RequestMetadata::default());
        use vivid_sdk::ConnectionFactory;
        transport.cancel();
        Ok(())
    }

    fn receive_offer(
        session: &Session,
        transport: &crate::transport::Transport,
        shell_pid: u32,
        shell_start: u64,
        maximum_record_body: u32,
        disclose_path: bool,
        offer: vivid_sdk::FileDropOffer,
    ) -> io::Result<()> {
        if process_start_time(shell_pid)? != shell_start {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "login shell exited",
            ));
        }
        let destination = open_shell_cwd(shell_pid)?;
        ensure_shell(shell_pid, shell_start)?;
        let mut temporary = TemporaryFile::create(destination, &offer.suggested_name)?;
        let transfer_id = session.allocate_id()?;
        let acceptance = AcceptFileDrop {
            binding: offer.binding,
            transfer_id,
            transfer_generation: FileTransferGeneration::ONE,
            maximum_record_body,
            initial_maximum_body_bytes: CREDIT_WINDOW_BYTES,
            initial_maximum_records: CREDIT_WINDOW_RECORDS,
        };
        session.accept_file_drop(acceptance, &RequestMetadata::default())?;

        let mut generation = FileTransferGeneration::ONE;
        let mut offset = 0_u64;
        let mut hasher = Sha256::new();
        for attempt in 0..MAXIMUM_RESUME_ATTEMPTS {
            let request = IncomingFileTransferRequest {
                context_id: offer.binding.context_id,
                surface_id: offer.binding.surface_id,
                producer_epoch: offer.binding.producer_epoch,
                grant_generation: offer.binding.grant_generation,
                surface_generation: offer.binding.surface_generation,
                drop_id: offer.binding.drop_id,
                transfer_id,
                transfer_generation: generation,
                resume_offset: offset,
                declared_length: offer.declared_length,
                maximum_record_body,
                maximum_body_bytes: CREDIT_WINDOW_BYTES,
                maximum_records: CREDIT_WINDOW_RECORDS,
            };
            match receive_generation(session, &mut temporary.file, &mut hasher, request) {
                Ok(finish) => {
                    let actual: [u8; 32] = hasher.finalize().into();
                    if finish.sha256 != actual {
                        let received = temporary.file.stream_position()?;
                        let result = FileResult {
                            transfer_id,
                            transfer_generation: generation,
                            result: FileResultCode::HashMismatch,
                            committed_length: received,
                            final_name: String::new(),
                            committed_path: None,
                        };
                        let _ = finish.channel.send_result(&result);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "file hash mismatch",
                        ));
                    }
                    let final_name = match (|| {
                        temporary.file.sync_all()?;
                        ensure_shell(shell_pid, shell_start)?;
                        transport.ensure_live()?;
                        temporary.commit()
                    })() {
                        Ok(name) => name,
                        Err(error) => {
                            crate::failure_result(&finish.channel, FileResultCode::IoError);
                            return Err(error);
                        }
                    };
                    let destination_directory = disclose_path
                        .then(|| resolve_directory(&temporary.directory))
                        .flatten();
                    let result = FileResult {
                        transfer_id,
                        transfer_generation: generation,
                        result: FileResultCode::Committed,
                        committed_length: offer.declared_length,
                        committed_path: committed_path(destination_directory.as_ref(), &final_name),
                        final_name: final_name.clone(),
                    };
                    let _ = confirm_committed_result(session, actual, result, finish.channel);
                    return Ok(());
                }
                Err(error)
                    if attempt + 1 < MAXIMUM_RESUME_ATTEMPTS
                        && matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::BrokenPipe
                                | io::ErrorKind::TimedOut
                        ) =>
                {
                    offset = temporary.file.stream_position()?;
                    generation = generation.advance()?;
                    session.advance_file_transfer(
                        AdvanceFileTransfer {
                            context_id: offer.binding.context_id,
                            surface_id: offer.binding.surface_id,
                            drop_id: offer.binding.drop_id,
                            transfer_id,
                            expected_generation: FileTransferGeneration::new(generation.get() - 1),
                            new_generation: generation,
                            committed_offset: offset,
                            maximum_body_bytes: CREDIT_WINDOW_BYTES,
                            maximum_records: CREDIT_WINDOW_RECORDS,
                        },
                        &RequestMetadata::default(),
                    )?;
                    temporary.file.seek(SeekFrom::Start(offset))?;
                    let _ = error;
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("file transfer retry exhausted"))
    }

    fn confirm_committed_result(
        session: &Session,
        sha256: [u8; 32],
        result: FileResult,
        channel: vivid_sdk::IncomingFileTransfer,
    ) -> io::Result<()> {
        let request = channel.request();
        let mut committed = crate::CommittedFileDrop {
            final_name: result.final_name.clone(),
            result,
            channel,
            request,
            sha256,
        };
        crate::reconcile_committed_pending(session, &mut committed)
    }

    struct FinishedGeneration {
        sha256: [u8; 32],
        channel: vivid_sdk::IncomingFileTransfer,
    }

    fn receive_generation(
        session: &Session,
        file: &mut File,
        hasher: &mut Sha256,
        request: IncomingFileTransferRequest,
    ) -> io::Result<FinishedGeneration> {
        let channel = session.open_incoming_file_transfer(request)?;
        receive_channel(channel, file, hasher)
    }

    fn receive_channel(
        mut channel: vivid_sdk::IncomingFileTransfer,
        file: &mut File,
        hasher: &mut Sha256,
    ) -> io::Result<FinishedGeneration> {
        let mut credit = crate::Credit::new(channel.request());
        credit.start(&mut channel)?;
        loop {
            match channel.read_event()? {
                IncomingFileTransferEvent::Data { offset, bytes } => {
                    if file.stream_position()? != offset {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "temporary offset mismatch",
                        ));
                    }
                    if let Err(error) = crate::write_hashed(file, hasher, &bytes) {
                        crate::failure_result(&channel, FileResultCode::IoError);
                        return Err(io::Error::other(error));
                    }
                    credit.received(bytes.len(), &mut channel)?;
                }
                IncomingFileTransferEvent::Finished(finish) => {
                    return Ok(FinishedGeneration {
                        sha256: finish.sha256,
                        channel,
                    });
                }
                IncomingFileTransferEvent::Aborted(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "sender aborted",
                    ));
                }
            }
        }
    }

    struct TemporaryFile {
        directory: File,
        directory_path: Option<PathBuf>,
        file: File,
        temporary_name: String,
        suggested_name: String,
        committed: bool,
    }

    impl TemporaryFile {
        fn create(directory: File, suggested_name: &str) -> io::Result<Self> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(io::Error::other)?;
            let temporary_name = format!(".vivid-drop-{}", hex(&random));
            let (file, directory_path) = os::create_temporary_file(&directory, &temporary_name)?;
            Ok(Self {
                directory,
                directory_path,
                file,
                temporary_name,
                suggested_name: suggested_name.to_owned(),
                committed: false,
            })
        }

        fn commit(&mut self) -> io::Result<String> {
            for collision in 0..10_000_u32 {
                let candidate = crate::collision_name(&self.suggested_name, collision);
                match os::commit_temporary(&self.directory, &self.temporary_name, &candidate) {
                    Ok(true) => {
                        self.committed = true;
                        return Ok(candidate);
                    }
                    Ok(false) => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "collision limit reached",
            ))
        }
    }

    impl Drop for TemporaryFile {
        fn drop(&mut self) {
            if !self.committed {
                os::remove_temporary_file(
                    &self.directory,
                    self.directory_path.as_ref(),
                    &self.temporary_name,
                );
            }
        }
    }

    /// Join a resolved destination directory to a committed basename, if the result is safe.
    ///
    /// Reusing the protocol validator here means the producer can never emit a record it would
    /// itself reject.
    fn committed_path(directory: Option<&PathBuf>, final_name: &str) -> Option<String> {
        let text = directory?
            .join(final_name)
            .into_os_string()
            .into_string()
            .ok()?;
        validate_committed_path(&text, final_name).ok()?;
        Some(text)
    }

    fn ensure_shell(pid: u32, start: u64) -> io::Result<()> {
        if process_start_time(pid).is_ok_and(|current| current == start) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "login shell exited",
            ))
        }
    }

    fn parse_shell_pid() -> io::Result<(u32, bool)> {
        let mut arguments = std::env::args_os().skip(1);
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--shell-pid")) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected --shell-pid",
            ));
        }
        let pid = arguments
            .next()
            .and_then(|value| value.to_str().and_then(|value| value.parse().ok()))
            .filter(|pid| *pid != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid shell PID"))?;
        let signal_ready = match arguments.next() {
            Some(value) if value == std::ffi::OsStr::new("--signal-ready") => true,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected argument",
                ));
            }
            None => false,
        };
        if arguments.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected argument",
            ));
        }
        Ok((pid, signal_ready))
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(DIGITS[(byte >> 4) as usize] as char);
            output.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        output
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::OpenOptionsExt;

        #[test]
        fn collision_suffix_preserves_extension() {
            assert_eq!(crate::collision_name("report.txt", 2), "report (2).txt");
            assert_eq!(crate::collision_name("README", 1), "README (1)");
            assert!(crate::collision_name(&format!("{}.txt", "é".repeat(126)), 1).len() <= 255);
        }

        #[test]
        fn proc_parser_reads_this_process_identity() {
            assert!(process_start_time(std::process::id()).unwrap() > 0);
        }

        #[test]
        fn exited_unreaped_shell_is_not_live() {
            use std::process::{Command, Stdio};
            let mut child = Command::new("sh")
                .args(["-c", "read value"])
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let start = process_start_time(child.id()).unwrap();
            drop(child.stdin.take());
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while ensure_shell(child.id(), start).is_ok() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            child.wait().unwrap();
        }

        fn scratch(name: &str) -> PathBuf {
            let path =
                std::env::temp_dir().join(format!("vvreceive-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::canonicalize(&path).unwrap_or(path)
        }

        fn open_directory(path: &std::path::Path) -> File {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)
                .unwrap()
        }

        #[test]
        fn a_live_directory_resolves_to_a_path_the_protocol_accepts() {
            let path = scratch("live");
            let directory = open_directory(&path);
            let resolved = resolve_directory(&directory).unwrap();
            assert_eq!(resolved, std::fs::canonicalize(&path).unwrap());

            // The committed name is what pins the tail of the disclosed path, including after a
            // collision rename.
            for name in ["report.txt", "report (1).txt", "my report.txt"] {
                let disclosed = committed_path(Some(&resolved), name).unwrap();
                assert!(disclosed.ends_with(&format!("/{name}")));
                validate_committed_path(&disclosed, name).unwrap();
            }
            std::fs::remove_dir_all(&path).unwrap();
        }

        #[test]
        fn commit_reports_renamed_directory_and_preserves_existing_file() {
            let root = scratch("renamed");
            let old = root.join("old");
            let new = root.join("new");
            std::fs::create_dir(&old).unwrap();
            let mut temporary = TemporaryFile::create(open_directory(&old), "report.txt").unwrap();
            std::io::Write::write_all(&mut temporary.file, b"received").unwrap();
            std::fs::write(old.join("report.txt"), b"original").unwrap();
            std::fs::rename(&old, &new).unwrap();
            std::fs::create_dir(&old).unwrap();
            let name = temporary.commit().unwrap();
            assert_eq!(name, "report (1).txt");
            let resolved = resolve_directory(&temporary.directory);
            assert_eq!(
                committed_path(resolved.as_ref(), &name),
                Some(new.join(&name).to_str().unwrap().to_owned())
            );
            assert_eq!(std::fs::read(new.join(name)).unwrap(), b"received");
            assert_eq!(std::fs::read(new.join("report.txt")).unwrap(), b"original");
            assert_eq!(std::fs::read_dir(&old).unwrap().count(), 0);
            drop(temporary);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn an_unlinked_directory_discloses_nothing() {
            let path = scratch("unlinked");
            let directory = open_directory(&path);
            std::fs::remove_dir_all(&path).unwrap();
            // On Linux the kernel appends " (deleted)". On macOS fcntl fails or is unlinked.
            assert!(resolve_directory(&directory).is_none());
        }

        #[test]
        fn a_directory_name_that_cannot_be_disclosed_safely_yields_nothing() {
            // A directory name may hold a newline; such a path must never reach a terminal.
            let path = scratch("control").join("in\nvalid");
            std::fs::create_dir_all(&path).unwrap();
            let directory = open_directory(&path);
            assert!(resolve_directory(&directory).is_none());
            std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }

        #[test]
        fn a_mismatched_basename_is_never_disclosed() {
            let resolved = PathBuf::from("/home/u");
            assert_eq!(
                committed_path(Some(&resolved), "report.txt").as_deref(),
                Some("/home/u/report.txt")
            );
            // A relative destination could never be typed safely, so it discloses nothing.
            assert!(committed_path(Some(&PathBuf::from("home/u")), "report.txt").is_none());
            assert!(committed_path(None, "report.txt").is_none());
        }
    }
}

#[cfg(target_os = "macos")]
pub use platform::open_macos_desktop;
#[cfg(target_os = "linux")]
pub use platform::open_xdg_desktop;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use platform::run;

#[cfg(test)]
mod portable_tests {
    #[test]
    fn collision_suffix_is_safe_bounded_and_preserves_extensions() {
        assert_eq!(super::collision_name("report.txt", 2), "report (2).txt");
        assert_eq!(super::collision_name("README", 1), "README (1)");
        assert!(super::collision_name(&format!("{}.txt", "é".repeat(126)), 1).len() <= 255);
    }
}

#[cfg(all(test, unix))]
mod tests;
