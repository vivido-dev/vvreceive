//! Receiver-owned native transport cancellation and bulk idle enforcement.
use std::io::{self, Read};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vivid_protocol::wire::{Connection, Endpoint};
use vivid_sdk::{ConnectionFactory, ConnectionKind, LaneClass};

// Linux AF_UNIX nonblocking connect succeeds immediately or rejects a full listener
// backlog. Do not let a stalled local acceptor trap the helper before cancellation is registered.
#[cfg(target_os = "linux")]
fn connect_unix(path: &std::path::Path) -> io::Result<UnixStream> {
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    connect(&fd, &SocketAddrUnix::new(path)?)?;
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}
#[cfg(not(target_os = "linux"))]
fn connect_unix(path: &std::path::Path) -> io::Result<UnixStream> {
    UnixStream::connect(path)
}

trait Socket: Read + Send {
    fn clone_socket(&self) -> io::Result<Box<dyn Socket>>;
    fn shutdown(&self);
    fn writer(&self) -> io::Result<Box<dyn io::Write + Send>>;
}
macro_rules! socket {
    ($ty:ty) => {
        impl Socket for $ty {
            fn clone_socket(&self) -> io::Result<Box<dyn Socket>> {
                Ok(Box::new(self.try_clone()?))
            }
            fn shutdown(&self) {
                let _ = self.shutdown(Shutdown::Both);
            }
            fn writer(&self) -> io::Result<Box<dyn io::Write + Send>> {
                Ok(Box::new(self.try_clone()?))
            }
        }
    };
}
socket!(TcpStream);
socket!(UnixStream);

#[derive(Default)]
struct State {
    closed: bool,
    control: Option<Box<dyn Socket>>,
    bulk: Option<Box<dyn Socket>>,
    establishment: Option<Instant>,
}

pub(crate) struct Transport {
    control: Endpoint,
    bulk: Endpoint,
    state: Arc<Mutex<State>>,
    idle_us: Arc<AtomicU64>,
}

impl Transport {
    #[cfg(unix)]
    pub(crate) fn from_env() -> io::Result<Self> {
        let control = std::env::var("VIVID_ENDPOINT_CONTROL")
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "control endpoint absent"))?;
        let bulk = std::env::var("VIVID_ENDPOINT_BULK").unwrap_or_else(|_| control.clone());
        Ok(Self::new(
            Endpoint::parse(&control)?,
            Endpoint::parse(&bulk)?,
        ))
    }

    fn new(control: Endpoint, bulk: Endpoint) -> Self {
        Self {
            control,
            bulk,
            state: Arc::new(Mutex::new(State {
                establishment: Some(Instant::now() + Duration::from_secs(30)),
                ..State::default()
            })),
            idle_us: Arc::new(AtomicU64::new(30_000_000)),
        }
    }

    pub(crate) fn established(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .establishment = None;
    }

    pub(crate) fn ensure_live(&self) -> io::Result<()> {
        if self.state.lock().unwrap_or_else(|e| e.into_inner()).closed {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "receiver stopped",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn set_idle(&self, microseconds: u64) {
        self.idle_us.store(microseconds, Ordering::Relaxed);
    }
}

fn cancel(state: &Mutex<State>) {
    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
    state.closed = true;
    if let Some(socket) = state.control.take() {
        socket.shutdown();
    }
    if let Some(socket) = state.bulk.take() {
        socket.shutdown();
    }
}

impl ConnectionFactory for Transport {
    fn cancel(&self) {
        cancel(&self.state);
    }

    fn open(&self, kind: ConnectionKind, _: Option<LaneClass>) -> io::Result<Connection> {
        let bulk = kind == ConnectionKind::FileTransfer;
        if self.state.lock().unwrap_or_else(|e| e.into_inner()).closed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "receiver stopped",
            ));
        }
        let endpoint = if bulk { &self.bulk } else { &self.control };
        let socket: Box<dyn Socket> = match endpoint {
            Endpoint::Tcp(address) => {
                let address = address
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid endpoint"))?;
                let stream = TcpStream::connect_timeout(&address, Duration::from_millis(250))?;
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                Box::new(stream)
            }
            Endpoint::Unix(path) => {
                let stream = connect_unix(path)?;
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                Box::new(stream)
            }
        };
        let writer = socket.writer()?;
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed {
                socket.shutdown();
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "receiver stopped",
                ));
            }
            let slot = if bulk {
                &mut state.bulk
            } else {
                &mut state.control
            };
            if let Some(previous) = slot.replace(socket.clone_socket()?) {
                previous.shutdown();
            }
        }
        Connection::from_streams(
            Box::new(Reader {
                socket,
                state: self.state.clone(),
                idle_us: self.idle_us.clone(),
                bulk,
                progress: Instant::now(),
            }),
            writer,
            kind,
        )
    }
}

struct Reader {
    socket: Box<dyn Socket>,
    state: Arc<Mutex<State>>,
    idle_us: Arc<AtomicU64>,
    bulk: bool,
    progress: Instant,
}

impl Read for Reader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let expired = {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.closed {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "receiver stopped",
                    ));
                }
                state
                    .establishment
                    .is_some_and(|deadline| Instant::now() >= deadline)
            };
            if expired {
                cancel(&self.state);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection establishment timed out",
                ));
            }
            let result = self.socket.read(bytes);
            match result {
                Ok(n) if n > 0 => {
                    self.progress = Instant::now();
                    return Ok(n);
                }
                Err(ref error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    if self.bulk
                        && self.progress.elapsed()
                            >= Duration::from_micros(self.idle_us.load(Ordering::Relaxed))
                    {
                        self.socket.shutdown();
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "file transfer idle timeout",
                        ));
                    }
                }
                other => {
                    if !self.bulk {
                        cancel(&self.state);
                    }
                    return other;
                }
            }
        }
    }
}

/// Joins promptly on normal completion and cancels both sockets on owner loss.
pub(crate) struct Watch {
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Watch {
    pub(crate) fn start(
        transport: Arc<Transport>,
        alive: impl Fn() -> bool + Send + 'static,
    ) -> io::Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        let done = stopped.clone();
        let worker = std::thread::Builder::new()
            .name("vvreceive-lifetime".into())
            .spawn(move || {
                while !done.load(Ordering::Acquire) {
                    if !alive() {
                        transport.cancel();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })?;
        Ok(Self {
            stopped,
            worker: Some(worker),
        })
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        cancel(&self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use vivid_protocol::wire::{PREFACE_SIZE, RecordHeader};

    fn factory(listener: &TcpListener) -> Arc<Transport> {
        let endpoint = Endpoint::Tcp(listener.local_addr().unwrap().to_string());
        let transport = Arc::new(Transport::new(endpoint.clone(), endpoint));
        transport.established();
        transport
    }
    fn accept(listener: &TcpListener) -> TcpStream {
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.read_exact(&mut [0; PREFACE_SIZE]).unwrap();
        peer
    }
    fn record(peer: &mut TcpStream) {
        peer.write_all(
            &RecordHeader {
                body_length: 1,
                record_type: 0x8001,
                flags: 0,
                object_id: 1,
                sequence: 1,
            }
            .encode(),
        )
        .unwrap();
        peer.write_all(&[42]).unwrap();
    }
    #[test]
    fn owner_loss_interrupts_stalled_bulk_without_touching_same_id_neighbor() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let first = factory(&listener);
        let second = factory(&listener);
        let connection = first.open(ConnectionKind::FileTransfer, None).unwrap();
        let _peer = accept(&listener);
        let neighbor = second.open(ConnectionKind::FileTransfer, None).unwrap();
        let mut neighbor_peer = accept(&listener);
        let (mut reader, _) = connection.split().unwrap();
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || tx.send(reader.read_record().is_err()).unwrap());
        let alive = Arc::new(AtomicBool::new(true));
        let observed = alive.clone();
        let watch = Watch::start(first.clone(), move || observed.load(Ordering::Acquire)).unwrap();
        alive.store(false, Ordering::Release);
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        assert!(first.ensure_live().is_err());
        assert!(second.ensure_live().is_ok());
        record(&mut neighbor_peer);
        let (mut reader, _) = neighbor.split().unwrap();
        assert_eq!(reader.read_record().unwrap().body, [42]);
        worker.join().unwrap();
        drop(watch);
        second.cancel();
    }
    #[test]
    fn idle_timeout_closes_only_bulk_and_control_eof_cancels_owner() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let transport = factory(&listener);
        transport.set_idle(20_000);
        let control = transport.open(ConnectionKind::Control, None).unwrap();
        let mut control_peer = accept(&listener);
        let bulk = transport.open(ConnectionKind::FileTransfer, None).unwrap();
        let _bulk_peer = accept(&listener);
        let (mut bulk, _) = bulk.split().unwrap();
        assert_eq!(
            bulk.read_record().err().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(transport.ensure_live().is_ok());
        record(&mut control_peer);
        let (mut control, _) = control.split().unwrap();
        assert_eq!(control.read_record().unwrap().body, [42]);
        drop(control_peer);
        assert!(control.read_record().is_err());
        assert!(transport.ensure_live().is_err());
    }
}
