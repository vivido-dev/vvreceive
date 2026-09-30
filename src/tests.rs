use super::*;
use std::io::Read;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use vivid_protocol::file_drop::*;
use vivid_protocol::registry::record as records;
use vivid_protocol::wire::{Connection, ConnectionKind, HEADER_SIZE, PREFACE_SIZE, RecordHeader};
use vivid_protocol::{auth, messages, registry};
use vivid_sdk::{ConnectionFactory, LaneClass, ProducerAuthentication, ProducerConfig};

fn request() -> IncomingFileTransferRequest {
    IncomingFileTransferRequest {
        context_id: 1,
        surface_id: 0,
        producer_epoch: vivid_protocol::revision::FileDropEpoch::ONE,
        grant_generation: vivid_protocol::revision::FileDropGrantGeneration::ONE,
        surface_generation: vivid_protocol::revision::SurfaceGeneration::ZERO,
        drop_id: 1,
        transfer_id: 1,
        transfer_generation: vivid_sdk::FileTransferGeneration::ONE,
        resume_offset: 0,
        declared_length: 2048,
        maximum_record_body: 1040,
        maximum_body_bytes: 1040,
        maximum_records: 1,
    }
}
fn offer() -> FileDropOffer {
    let r = request();
    FileDropOffer {
        binding: FileDropTuple {
            context_id: r.context_id,
            surface_id: r.surface_id,
            producer_epoch: r.producer_epoch,
            grant_generation: r.grant_generation,
            surface_generation: r.surface_generation,
            drop_id: r.drop_id,
        },
        declared_length: r.declared_length,
        suggested_name: "report.txt".into(),
    }
}
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("vvreceive-test-{}", portable_hex(&nonce)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn directory(&self) -> File {
        File::open(&self.0).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn credit_refills_small_and_large_actual_grants() {
    let mut small = Credit::new(request());
    assert_eq!(small.account(1024).unwrap(), Some((2080, 2)));
    let mut r = request();
    r.maximum_body_bytes = 64 * 1024 * 1024;
    r.maximum_records = 1;
    let mut large = Credit::new(r);
    assert_eq!(large.account(1024).unwrap(), Some((128 * 1024 * 1024, 2)));
    large.body = u64::MAX;
    assert!(large.account(1024).is_err());
}
#[test]
fn partial_write_preserves_hash_at_exact_persisted_offset() {
    struct Partial {
        data: Vec<u8>,
        failed: bool,
    }
    impl Write for Partial {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.data.len() == 3 && !self.failed {
                self.failed = true;
                return Err(io::ErrorKind::StorageFull.into());
            }
            let n = if self.data.is_empty() { 3 } else { b.len() };
            self.data.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let bytes = b"abcdefgh";
    let mut writer = Partial {
        data: vec![],
        failed: false,
    };
    let mut hash = Sha256::new();
    assert!(write_hashed(&mut writer, &mut hash, bytes).is_err());
    assert_eq!(writer.data, b"abc");
    write_hashed(&mut writer, &mut hash, &bytes[3..]).unwrap();
    assert_eq!(hash.finalize(), Sha256::digest(bytes));
    assert_eq!(writer.data, bytes);
}

fn read_record(stream: &mut TcpStream) -> io::Result<(RecordHeader, Vec<u8>)> {
    let mut header = [0; HEADER_SIZE];
    stream.read_exact(&mut header)?;
    let header = RecordHeader::decode(header);
    let mut body = vec![0; header.body_length as usize];
    stream.read_exact(&mut body)?;
    Ok((header, body))
}
fn send(stream: &mut TcpStream, seq: &mut u64, ty: u16, id: u64, body: Vec<u8>) {
    *seq += 1;
    stream
        .write_all(
            &RecordHeader {
                body_length: body.len() as u32,
                record_type: ty,
                flags: 0,
                object_id: id,
                sequence: *seq,
            }
            .encode(),
        )
        .unwrap();
    stream.write_all(&body).unwrap();
}
#[derive(Default)]
struct Observed {
    grants: usize,
    results: Vec<FileResult>,
    queries: usize,
    advances: usize,
    unavailable: bool,
}
struct Peer {
    observed: Arc<Mutex<Observed>>,
    sockets: Mutex<Vec<TcpStream>>,
    race: bool,
    bad_hash: bool,
    replay: bool,
}
impl ConnectionFactory for Peer {
    fn cancel(&self) {
        for socket in self.sockets.lock().unwrap().iter() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
    fn open(&self, kind: ConnectionKind, _: Option<LaneClass>) -> io::Result<Connection> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (mut server, _) = listener.accept()?;
        server.set_read_timeout(Some(Duration::from_secs(2)))?;
        self.sockets.lock().unwrap().push(server.try_clone()?);
        let observed = self.observed.clone();
        let race = self.race;
        let bad_hash = self.bad_hash;
        let replay = self.replay;
        std::thread::spawn(move || {
            let mut preface = [0; PREFACE_SIZE];
            server.read_exact(&mut preface).unwrap();
            let (header, body) = read_record(&mut server).unwrap();
            let mut seq = 0;
            if kind == ConnectionKind::Control {
                let (id, hello) = messages::Hello::decode(&body).unwrap();
                let info = Session::connect(ProducerConfig::offline())
                    .unwrap()
                    .info()
                    .clone();
                let nonce = [7; 32];
                let root = auth::Secret32::new([5; 32]);
                let prk = auth::extract_handshake_prk(&root, &hello.client_nonce, &nonce, &[0; 32]);
                let mut welcome = messages::Welcome {
                    session_id: 1,
                    session_tag: [3; 16],
                    root_context_id: 1,
                    target_generation: 1,
                    target_profile: hello.target_profile,
                    target_descriptor: info.target_descriptor,
                    accepted_profiles: hello.required_profiles,
                    maximum_control_body: vivid_protocol::CONTROL_MAX_RECORD_BODY,
                    server_nonce: nonce,
                    authentication: messages::WelcomeAuthentication {
                        kind: messages::AUTHENTICATION_ROOT,
                        confirmation: [0; 32],
                        lease_state: 0,
                        activation_attempt_status: 0,
                    },
                    session_revision: 1,
                    scene_revision: 1,
                    resource_contract: info.resource_contract,
                    establishment_state: 0,
                    resume_generation: 0,
                    extensions: vec![],
                };
                welcome.confirm(&prk).unwrap();
                send(
                    &mut server,
                    &mut seq,
                    messages::WELCOME,
                    0,
                    welcome.encode(id).unwrap(),
                );
                while let Ok((h, b)) = read_record(&mut server) {
                    let envelope = messages::decode_control(&b).unwrap();
                    if h.record_type == records::QUERY_FILE_DROP {
                        let mut seen = observed.lock().unwrap();
                        seen.queries += 1;
                        if seen.unavailable {
                            send(
                                &mut server,
                                &mut seq,
                                messages::OK,
                                0,
                                messages::ok(envelope.request_id),
                            );
                            continue;
                        }
                        let terminal = if replay {
                            seen.results
                                .iter()
                                .any(|r| r.result == FileResultCode::AlreadyCommitted)
                        } else {
                            !race || seen.queries > 1
                        };
                        let status = FileDropStatus {
                            drop_id: 1,
                            transfer_id: 1,
                            generation: vivid_sdk::FileTransferGeneration::new(
                                1 + seen.advances as u64,
                            ),
                            state: if terminal {
                                FileDropState::Committed
                            } else {
                                FileDropState::Transferring
                            },
                            committed_offset: if terminal { 2048 } else { 0 },
                            result: terminal.then_some(FileResultCode::Committed),
                            final_name: if terminal {
                                "report.txt".into()
                            } else {
                                String::new()
                            },
                        };
                        send(
                            &mut server,
                            &mut seq,
                            records::FILE_DROP_STATUS,
                            1,
                            messages::Envelope::new(envelope.request_id, status.payload().unwrap())
                                .encode()
                                .unwrap(),
                        );
                    } else if h.record_type == records::ADVANCE_FILE_TRANSFER {
                        observed.lock().unwrap().advances += 1;
                        if replay {
                            let generation = vivid_sdk::FileTransferGeneration::new(
                                1 + observed.lock().unwrap().advances as u64,
                            );
                            let advanced = FileTransferAdvanced {
                                transfer_id: 1,
                                generation,
                                committed_offset: 2048,
                                open_timeout_us: 60_000_000,
                            };
                            send(
                                &mut server,
                                &mut seq,
                                records::FILE_TRANSFER_ADVANCED,
                                1,
                                messages::encode_payload(
                                    envelope.request_id,
                                    advanced.payload().unwrap(),
                                )
                                .unwrap(),
                            );
                        } else {
                            let error = messages::ErrorReply {
                                code: registry::error::BAD_STATE,
                                request_id: envelope.request_id,
                                detail: messages::ErrorDetail::new(vec![]).unwrap(),
                                fatal: false,
                                diagnostic: "offer is terminal".into(),
                            };
                            send(
                                &mut server,
                                &mut seq,
                                messages::ERROR,
                                0,
                                error.encode().unwrap(),
                            );
                        }
                    } else {
                        send(
                            &mut server,
                            &mut seq,
                            messages::OK,
                            0,
                            messages::ok(envelope.request_id),
                        );
                    }
                }
            } else {
                assert_eq!(header.record_type, records::FILE_TRANSFER_OPEN);
                let open = FileTransferOpen::decode(&body).unwrap();
                send(
                    &mut server,
                    &mut seq,
                    records::FILE_TRANSFER_ACCEPTED,
                    1,
                    FileTransferAccepted {
                        transfer_id: 1,
                        transfer_generation: open.transfer_generation,
                        resume_offset: open.resume_offset,
                    }
                    .encode()
                    .unwrap(),
                );
                let bytes = vec![9; 1024];
                for offset in [0u64, 1024]
                    .into_iter()
                    .filter(|offset| *offset >= open.resume_offset)
                {
                    let mut body = vec![];
                    body.extend_from_slice(&file_data_prefix(offset, bytes.len()).unwrap());
                    body.extend_from_slice(&bytes);
                    send(&mut server, &mut seq, records::FILE_DATA, 1, body);
                    let (h, b) = match read_record(&mut server) {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                    if h.record_type == records::FILE_RESULT {
                        observed
                            .lock()
                            .unwrap()
                            .results
                            .push(FileResult::decode(&b).unwrap());
                        return;
                    }
                    assert_eq!(h.record_type, records::MAX_FILE_DATA);
                    observed.lock().unwrap().grants += 1;
                }
                let hash = if bad_hash {
                    [0; 32]
                } else {
                    Sha256::digest(vec![9; 2048]).into()
                };
                send(
                    &mut server,
                    &mut seq,
                    records::FILE_FINISH,
                    1,
                    FileFinish {
                        transfer_id: 1,
                        transfer_generation: open.transfer_generation,
                        final_length: 2048,
                        sha256: hash,
                    }
                    .encode()
                    .unwrap(),
                );
                while let Ok((h, b)) = read_record(&mut server) {
                    if h.record_type == records::FILE_RESULT {
                        observed
                            .lock()
                            .unwrap()
                            .results
                            .push(FileResult::decode(&b).unwrap());
                    }
                }
            }
        });
        Connection::from_streams(Box::new(client.try_clone()?), Box::new(client), kind)
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn session(race: bool, bad_hash: bool) -> (Session, Arc<Peer>) {
    session_with_replay(race, bad_hash, false)
}
fn session_with_replay(race: bool, bad_hash: bool, replay: bool) -> (Session, Arc<Peer>) {
    let peer = Arc::new(Peer {
        observed: Arc::new(Mutex::new(Observed::default())),
        sockets: Mutex::new(vec![]),
        race,
        bad_hash,
        replay,
    });
    let mut config = ProducerConfig {
        authentication: ProducerAuthentication::Root {
            root_secret: auth::Secret32::new([5; 32]),
        },
        ..ProducerConfig::default()
    };
    config.required_profiles.push(registry::FILE_DROP.into());
    config.required_profiles.sort();
    (
        Session::connect_with_factory(config, peer.clone()).unwrap(),
        peer,
    )
}
#[test]
fn receipt_replenishes_one_record_credit_and_reconciles_late_success() {
    let dir = Scratch::new();
    let (session, peer) = session(true, false);
    let channel = session.open_incoming_file_transfer(request()).unwrap();
    let mut committed = receive_accepted(channel, offer(), dir.directory()).unwrap();
    reconcile_committed_pending(&session, &mut committed).unwrap();
    assert_eq!(
        std::fs::read(dir.0.join("report.txt")).unwrap(),
        vec![9; 2048]
    );
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    let seen = peer.observed.lock().unwrap();
    assert_eq!(seen.grants, 2);
    assert_eq!(seen.advances, 1);
    assert_eq!(seen.queries, 2);
    drop(seen);
    peer.cancel();
}
#[test]
fn create_and_hash_failures_report_terminal_results_and_remove_temporary_files() {
    for bad_hash in [false, true] {
        let dir = Scratch::new();
        let (session, peer) = session(false, bad_hash);
        let channel = session.open_incoming_file_transfer(request()).unwrap();
        let destination = if bad_hash {
            dir.directory()
        } else {
            File::create(dir.0.join("not-directory")).unwrap()
        };
        assert!(receive_accepted(channel, offer(), destination).is_err());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while peer.observed.lock().unwrap().results.is_empty() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            peer.observed.lock().unwrap().results[0].result,
            if bad_hash {
                FileResultCode::HashMismatch
            } else {
                FileResultCode::IoError
            }
        );
        assert!(!std::fs::read_dir(&dir.0).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".vivid-drop-")
        }));
        peer.cancel();
    }
}

#[test]
fn uncertain_reconciliation_keeps_state_for_retry_and_rejects_other_transfer() {
    let dir = Scratch::new();
    let (session, peer) = session(false, false);
    let channel = session.open_incoming_file_transfer(request()).unwrap();
    let mut committed = receive_accepted(channel, offer(), dir.directory()).unwrap();
    peer.observed.lock().unwrap().unavailable = true;
    assert!(reconcile_committed_pending(&session, &mut committed).is_err());
    peer.observed.lock().unwrap().unavailable = false;
    reconcile_committed_pending(&session, &mut committed).unwrap();
    let mut status = FileDropStatus {
        drop_id: 1,
        transfer_id: 2,
        generation: request().transfer_generation,
        state: FileDropState::Committed,
        committed_offset: 2048,
        result: Some(FileResultCode::Committed),
        final_name: "report.txt".into(),
    };
    assert!(committed_status(&status, &committed).is_err());
    status.transfer_id = 1;
    status.state = FileDropState::Cancelled;
    assert!(committed_status(&status, &committed).is_err());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    peer.cancel();
}

#[test]
fn cancellation_before_commit_cleans_temporary_and_preserves_neighbor() {
    let dir = Scratch::new();
    let neighbor = Scratch::new();
    std::fs::write(neighbor.0.join("report.txt"), b"neighbor").unwrap();
    let (session, peer) = session(false, false);
    let mut channel = session.open_incoming_file_transfer(request()).unwrap();
    let check = || {
        let complete = std::fs::read_dir(&dir.0)
            .unwrap()
            .any(|e| e.unwrap().metadata().unwrap().len() == 2048);
        if complete {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "owner cancelled",
            ))
        } else {
            Ok(())
        }
    };
    assert!(receive_to_directory(&mut channel, &offer(), dir.directory(), check).is_err());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(neighbor.0.join("report.txt")).unwrap(),
        b"neighbor"
    );
    peer.cancel();
}

#[test]
fn lost_success_replays_identical_finish_without_second_destination() {
    let dir = Scratch::new();
    let (session, peer) = session_with_replay(false, false, true);
    let channel = session.open_incoming_file_transfer(request()).unwrap();
    let mut committed = receive_accepted(channel, offer(), dir.directory()).unwrap();
    reconcile_committed_pending(&session, &mut committed).unwrap();
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(dir.0.join("report.txt")).unwrap(),
        vec![9; 2048]
    );
    assert!(
        peer.observed
            .lock()
            .unwrap()
            .results
            .iter()
            .any(|r| r.result == FileResultCode::AlreadyCommitted)
    );
    peer.cancel();
}

#[test]
fn commit_failure_reports_io_error_after_verification() {
    let dir = Scratch::new();
    let (session, peer) = session(false, false);
    let mut channel = session.open_incoming_file_transfer(request()).unwrap();
    let calls = std::cell::Cell::new(0);
    let check = || {
        calls.set(calls.get() + 1);
        if calls.get() == 5 {
            for entry in std::fs::read_dir(&dir.0).unwrap() {
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
        }
        Ok(())
    };
    assert!(receive_to_directory(&mut channel, &offer(), dir.directory(), check).is_err());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while peer.observed.lock().unwrap().results.is_empty() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(
        peer.observed.lock().unwrap().results[0].result,
        FileResultCode::IoError
    );
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
    peer.cancel();
}
