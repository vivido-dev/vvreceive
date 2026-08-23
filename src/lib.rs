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
    offer: FileDropOffer,
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
    let request = channel.request();
    let directory = Dir::from_std_file(directory);
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let temporary_name = format!(".vivid-drop-{}", portable_hex(&random));
    let mut options = CapOpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut temporary = directory.open_with(&temporary_name, &options)?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut received_body = 0_u64;
        let mut received_records = 0_u64;
        let mut maximum_body = 16 * 1024 * 1024_u64;
        let mut maximum_records = 32_u64;
        let finish = loop {
            match channel.read_event()? {
                IncomingFileTransferEvent::Data { offset, bytes } => {
                    if temporary.stream_position()? != offset {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "temporary offset mismatch",
                        ));
                    }
                    temporary.write_all(&bytes)?;
                    hasher.update(&bytes);
                    received_body = received_body
                        .checked_add(bytes.len() as u64 + 16)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                        })?;
                    received_records = received_records.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                    })?;
                    if maximum_body.saturating_sub(received_body) < 4 * 1024 * 1024
                        || maximum_records.saturating_sub(received_records) < 4
                    {
                        maximum_body =
                            maximum_body.checked_add(16 * 1024 * 1024).ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                            })?;
                        maximum_records = maximum_records.checked_add(32).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                        })?;
                        channel.grant(maximum_body, maximum_records)?;
                    }
                }
                IncomingFileTransferEvent::Finished(finish) => break finish,
                IncomingFileTransferEvent::Aborted(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "sender aborted",
                    ));
                }
            }
        };
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != finish.sha256 {
            channel.send_result(&FileResult {
                transfer_id: finish.transfer_id,
                transfer_generation: finish.transfer_generation,
                result: FileResultCode::HashMismatch,
                committed_length: temporary.stream_position()?,
                final_name: String::new(),
                committed_path: None,
            })?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file hash mismatch",
            ));
        }
        temporary.sync_all()?;
        for collision in 0..10_000 {
            let candidate = collision_name(&offer.suggested_name, collision);
            match directory.hard_link(&temporary_name, &directory, &candidate) {
                Ok(()) => {
                    // The no-replace hard link is the atomic commit point. Failure to unlink the
                    // now-redundant temporary name must not turn a committed file into an unknown
                    // outcome; the outer cleanup retries it.
                    let _ = directory.remove_file(&temporary_name);
                    let result = FileResult {
                        transfer_id: finish.transfer_id,
                        transfer_generation: finish.transfer_generation,
                        result: FileResultCode::Committed,
                        committed_length: offer.declared_length,
                        final_name: candidate.clone(),
                        // A desktop drop has no terminal to type into, so this portable path
                        // never discloses a destination. Only the shell-cwd receiver does.
                        committed_path: None,
                    };
                    // A successful write is not an acknowledgement. The control-loop must QUERY
                    // the cached outcome, and may advance/replay the finish if this write was lost.
                    let _ = channel.send_result(&result);
                    return Ok(CommittedFileDrop {
                        final_name: candidate,
                        offer,
                        result,
                        channel,
                        request,
                        sha256: actual,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "collision limit reached",
        ))
    })();
    let _ = directory.remove_file(&temporary_name);
    result
}

/// Reconcile a committed desktop file without ever creating a second destination file.
pub fn reconcile_committed(
    session: &Session,
    mut committed: CommittedFileDrop,
) -> io::Result<String> {
    const ATTEMPTS: u32 = 3;
    for attempt in 0..ATTEMPTS {
        let mut known_nonterminal = false;
        for _ in 0..3 {
            match session.query_file_drop(
                QueryFileDrop {
                    drop_id: committed.offer.binding.drop_id,
                },
                &RequestMetadata::default(),
            ) {
                Ok(status)
                    if status.state == FileDropState::Committed
                        && status.final_name == committed.final_name
                        && status.committed_offset == committed.offer.declared_length =>
                {
                    return Ok(committed.final_name);
                }
                Ok(_) => {
                    known_nonterminal = true;
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
        if !known_nonterminal || attempt + 1 == ATTEMPTS {
            break;
        }

        let previous = committed.request.transfer_generation;
        let generation = previous.advance()?;
        session.advance_file_transfer(
            AdvanceFileTransfer {
                context_id: committed.request.context_id,
                surface_id: committed.request.surface_id,
                drop_id: committed.request.drop_id,
                transfer_id: committed.request.transfer_id,
                expected_generation: previous,
                new_generation: generation,
                committed_offset: committed.offer.declared_length,
                maximum_body_bytes: committed.request.maximum_body_bytes,
                maximum_records: committed.request.maximum_records,
            },
            &RequestMetadata::default(),
        )?;
        committed.request.transfer_generation = generation;
        committed.request.resume_offset = committed.offer.declared_length;
        committed.channel = session.open_incoming_file_transfer(committed.request)?;
        match committed.channel.read_event()? {
            IncomingFileTransferEvent::Finished(finish)
                if finish.final_length == committed.offer.declared_length
                    && finish.sha256 == committed.sha256 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "committed transfer replay was not an identical finish",
                ));
            }
        }
        committed.result.transfer_generation = generation;
        committed.result.result = FileResultCode::AlreadyCommitted;
        let _ = committed.channel.send_result(&committed.result);
    }
    Err(io::Error::other(
        "could not reconcile the committed file result",
    ))
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

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Seek, SeekFrom, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;

    use rustix::fs::{RenameFlags, renameat_with};
    use sha2::{Digest, Sha256};
    use vivid_protocol::file_drop::{
        DEFAULT_ACTIVE_FILE_TRANSFERS, DEFAULT_FILE_DROP_ACCEPTANCE_US,
        DEFAULT_FILE_TRANSFER_IDLE_US, DEFAULT_PENDING_FILE_DROPS, FileDropDestination,
        FileDropState, FileResult, FileResultCode, MAX_COMMITTED_PATH_BYTES, QueryFileDrop,
        validate_committed_path,
    };
    use vivid_protocol::revision::{FileTransferGeneration, SurfaceGeneration};
    use vivid_protocol::{HARD_MAX_RECORD_BODY, registry};
    use vivid_sdk::{
        AcceptFileDrop, AdvanceFileTransfer, FileDropBindingGuard, IncomingFileTransferEvent,
        IncomingFileTransferRequest, ProducerAuthentication, ProducerConfig, RequestMetadata,
        Session, SessionEvent,
    };

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
        let session = Session::connect(ProducerConfig {
            authentication: ProducerAuthentication::RootFromEnvironment,
            producer_name: "vvreceive".into(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
            target_profile: registry::TERMINAL_SURFACE.into(),
            required_profiles,
            // Optional, never required: an older presenter must still connect and copy.
            optional_profiles: vec![registry::FILE_DROP_PATH.to_owned()],
            ..ProducerConfig::default()
        })?;
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
                        shell_pid,
                        shell_start,
                        maximum_record_body,
                        disclose_path,
                        offer,
                    )
                    .is_err()
                    {
                        // The helper has no terminal or log output by design. Per-drop failures are
                        // reported through FILE_RESULT when a transfer connection exists.
                    }
                }
                Some(SessionEvent::ConnectionClosed { .. }) => break,
                Some(_) | None => thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = session.set_file_drop_binding(&binding.disable()?, &RequestMetadata::default());
        let _ = session.close();
        Ok(())
    }

    fn receive_offer(
        session: &Session,
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
        // Captured with the directory handle, at acceptance, so a later `cd` retargets neither
        // the transfer nor the path this drop reports.
        let destination_directory = disclose_path
            .then(|| resolve_directory(&destination))
            .flatten();
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
                    temporary.file.sync_all()?;
                    let final_name = temporary.commit()?;
                    let result = FileResult {
                        transfer_id,
                        transfer_generation: generation,
                        result: FileResultCode::Committed,
                        committed_length: offer.declared_length,
                        committed_path: committed_path(destination_directory.as_ref(), &final_name),
                        final_name: final_name.clone(),
                    };
                    confirm_committed_result(
                        session,
                        &offer,
                        transfer_id,
                        generation,
                        maximum_record_body,
                        actual,
                        result,
                        finish.channel,
                    )?;
                    return Ok(());
                }
                Err(error) if attempt + 1 < MAXIMUM_RESUME_ATTEMPTS => {
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

    #[allow(clippy::too_many_arguments)]
    fn confirm_committed_result(
        session: &Session,
        offer: &vivid_sdk::FileDropOffer,
        transfer_id: u64,
        mut generation: FileTransferGeneration,
        maximum_record_body: u32,
        sha256: [u8; 32],
        mut result: FileResult,
        mut channel: vivid_sdk::IncomingFileTransfer,
    ) -> io::Result<()> {
        for attempt in 0..MAXIMUM_RESUME_ATTEMPTS {
            let _ = channel.send_result(&result);
            for _ in 0..3 {
                if let Ok(status) = session.query_file_drop(
                    QueryFileDrop {
                        drop_id: offer.binding.drop_id,
                    },
                    &RequestMetadata::default(),
                ) && status.state == FileDropState::Committed
                    && status.final_name == result.final_name
                    && status.committed_offset == offer.declared_length
                {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(20));
            }
            if attempt + 1 == MAXIMUM_RESUME_ATTEMPTS {
                break;
            }
            let previous = generation;
            generation = generation.advance()?;
            session.advance_file_transfer(
                AdvanceFileTransfer {
                    context_id: offer.binding.context_id,
                    surface_id: offer.binding.surface_id,
                    drop_id: offer.binding.drop_id,
                    transfer_id,
                    expected_generation: previous,
                    new_generation: generation,
                    committed_offset: offer.declared_length,
                    maximum_body_bytes: CREDIT_WINDOW_BYTES,
                    maximum_records: CREDIT_WINDOW_RECORDS,
                },
                &RequestMetadata::default(),
            )?;
            channel = session.open_incoming_file_transfer(IncomingFileTransferRequest {
                context_id: offer.binding.context_id,
                surface_id: offer.binding.surface_id,
                producer_epoch: offer.binding.producer_epoch,
                grant_generation: offer.binding.grant_generation,
                surface_generation: offer.binding.surface_generation,
                drop_id: offer.binding.drop_id,
                transfer_id,
                transfer_generation: generation,
                resume_offset: offer.declared_length,
                declared_length: offer.declared_length,
                maximum_record_body,
                maximum_body_bytes: CREDIT_WINDOW_BYTES,
                maximum_records: CREDIT_WINDOW_RECORDS,
            })?;
            match channel.read_event()? {
                IncomingFileTransferEvent::Finished(finish) if finish.sha256 == sha256 => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "completed transfer replay was not an identical finish",
                    ));
                }
            }
            result.transfer_generation = generation;
            result.result = FileResultCode::AlreadyCommitted;
            // `committed_path` is deliberately left alone: spec section 6 requires the replayed
            // already-committed result to carry the byte-identical path, so the presenter types
            // it exactly once no matter how many results were lost.
        }
        Err(io::Error::other(
            "could not reconcile the committed file result",
        ))
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
        let mut received_body = 0_u64;
        let mut received_records = 0_u64;
        let mut maximum_body = CREDIT_WINDOW_BYTES;
        let mut maximum_records = CREDIT_WINDOW_RECORDS;
        loop {
            match channel.read_event()? {
                IncomingFileTransferEvent::Data { offset, bytes } => {
                    if file.stream_position()? != offset {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "temporary offset mismatch",
                        ));
                    }
                    file.write_all(&bytes)?;
                    hasher.update(&bytes);
                    received_body = received_body
                        .checked_add(bytes.len() as u64 + 16)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                        })?;
                    received_records = received_records.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                    })?;
                    if maximum_body.saturating_sub(received_body) < 4 * u64::from(RECORD_BODY)
                        || maximum_records.saturating_sub(received_records) < 4
                    {
                        maximum_body =
                            maximum_body
                                .checked_add(CREDIT_WINDOW_BYTES)
                                .ok_or_else(|| {
                                    io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                                })?;
                        maximum_records = maximum_records
                            .checked_add(CREDIT_WINDOW_RECORDS)
                            .ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "credit overflow")
                            })?;
                        channel.grant(maximum_body, maximum_records)?;
                    }
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

    /// Open the XDG Desktop directory without following the final path component.
    pub fn open_xdg_desktop() -> io::Result<File> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is unavailable"))?;
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(".config"))
            .join("user-dirs.dirs");
        let desktop = std::fs::read_to_string(config)
            .ok()
            .and_then(|content| {
                content.lines().find_map(|line| {
                    let value = line.strip_prefix("XDG_DESKTOP_DIR=")?.trim();
                    let value = value.strip_prefix('"')?.strip_suffix('"')?;
                    Some(PathBuf::from(value.replace("$HOME", home.to_str()?)))
                })
            })
            .unwrap_or_else(|| home.join("Desktop"));
        if !desktop.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XDG Desktop is not absolute",
            ));
        }
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(desktop)
    }

    struct TemporaryFile {
        directory: File,
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
            let path = directory_path(&directory).join(&temporary_name);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            Ok(Self {
                directory,
                file,
                temporary_name,
                suggested_name: suggested_name.to_owned(),
                committed: false,
            })
        }

        fn commit(mut self) -> io::Result<String> {
            for collision in 0..10_000_u32 {
                let candidate = crate::collision_name(&self.suggested_name, collision);
                match renameat_with(
                    self.directory.as_fd(),
                    Path::new(&self.temporary_name),
                    self.directory.as_fd(),
                    Path::new(&candidate),
                    RenameFlags::NOREPLACE,
                ) {
                    Ok(()) => {
                        self.committed = true;
                        return Ok(candidate);
                    }
                    Err(error) if error == rustix::io::Errno::EXIST => continue,
                    Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error())),
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
                let _ = std::fs::remove_file(
                    directory_path(&self.directory).join(&self.temporary_name),
                );
            }
        }
    }

    fn open_shell_cwd(pid: u32) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}/cwd"))
    }

    fn directory_path(directory: &File) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
    }

    /// Resolve a retained destination directory handle to its absolute path, or nothing.
    ///
    /// Every failure mode degrades to the pre-`file-drop-path-v1` behavior of disclosing no path
    /// at all: an unreadable link, a relative or already-unlinked target, non-UTF-8 bytes, or a
    /// path that could never pass the protocol validator anyway. A Linux directory name may
    /// legally contain a newline, so the control-character check is not decoration.
    fn resolve_directory(directory: &File) -> Option<PathBuf> {
        let target = std::fs::read_link(directory_path(directory)).ok()?;
        let text = target.to_str()?;
        if !text.starts_with('/')
            || text.ends_with(" (deleted)")
            || text.len() >= MAX_COMMITTED_PATH_BYTES
            || text.chars().any(char::is_control)
            || text.split('/').any(|component| component == "..")
        {
            return None;
        }
        Some(target)
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

    fn process_start_time(pid: u32) -> io::Result<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let end = stat
            .rfind(')')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proc stat"))?;
        stat[end + 2..]
            .split_ascii_whitespace()
            .nth(19)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proc start time is absent"))?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc start time"))
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

        fn scratch(name: &str) -> PathBuf {
            let path =
                std::env::temp_dir().join(format!("vvreceive-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            path
        }

        fn open_directory(path: &Path) -> File {
            OpenOptions::new()
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
        fn an_unlinked_directory_discloses_nothing() {
            let path = scratch("unlinked");
            let directory = open_directory(&path);
            std::fs::remove_dir_all(&path).unwrap();
            // The kernel appends " (deleted)", which is not a path anyone should be typing.
            assert!(resolve_directory(&directory).is_none());
        }

        #[test]
        fn a_directory_name_that_cannot_be_disclosed_safely_yields_nothing() {
            // A Linux directory name may hold a newline; such a path must never reach a terminal.
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

#[cfg(target_os = "linux")]
pub use linux::open_xdg_desktop;
#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(test)]
mod portable_tests {
    #[test]
    fn collision_suffix_is_safe_bounded_and_preserves_extensions() {
        assert_eq!(super::collision_name("report.txt", 2), "report (2).txt");
        assert_eq!(super::collision_name("README", 1), "README (1)");
        assert!(super::collision_name(&format!("{}.txt", "é".repeat(126)), 1).len() <= 255);
    }
}
