# vvreceive

`vvreceive` is the Linux receiver for authenticated
[Vivid Protocol 1.5](https://github.com/vivido-dev/vivid_protocol) file drops. It runs on the
remote host of a `vvssh` session and turns a drag gesture in a
[Vivido](https://github.com/vivido-dev/vivido) window on macOS or Windows into a real file in the
remote login shell's current directory.

It is not a file-transfer tool. There is no way to ask it for a file, list a directory, or push
one from the remote side. It only ever accepts a single regular file that a user just dropped onto
a terminal they are already logged into.

## How a drop arrives

Vivido opens the source, verifies it is a regular file, and offers only an inert basename and
length — never a path. `vvreceive` accepts, receives the bytes under its own cumulative credit on
an authenticated bulk connection, verifies SHA-256, and commits atomically. Existing files are
never overwritten; a collision becomes `name (1).ext`, `name (2).ext`, and so on.

The destination is the login shell's working directory, opened as a directory handle at the moment
the drop is accepted. Every create, link, and unlink stays relative to that handle, so a `cd` while
a transfer is in flight cannot retarget it, and neither can a symlink swapped in underneath.

`vvreceive` never reads or writes the PTY, and never puts a secret, tag, or hash in its arguments
or diagnostics. It has no output at all, by design — per-drop failures are reported over the
protocol as a `FILE_RESULT`, not to a terminal the user is working in.

## Typing the path back

With the `file-drop-path-v1` profile negotiated, a successful `FILE_RESULT` also carries the
absolute path of the file just committed, and Vivido types it at the prompt — the way a local drag
types a local path. An AI-agent CLI running on the remote host therefore sees an image path and
attaches it, exactly as it would locally.

`vvreceive` requests that profile as optional and never as required, so an older Vivido still
connects and copies with nothing typed. The presenter decides: Vivido offers the profile only while
`[file_drop] paste_remote_path` is on. Path resolution degrades to disclosing nothing whenever the
directory cannot be named safely — an unreadable link, an already-unlinked working directory,
non-UTF-8 bytes, or anything carrying a control character.

## Install

```bash
cargo install vvreceive
```

Installing [`vivi`](https://github.com/vivido-dev/vivi) also installs the `vvreceive` binary, so a
host that already has the Vivid media player needs nothing further.

Linux only. The crate builds on other platforms so that portable consumers can depend on it, but
`run` and the shell-cwd receiver exist only on Linux.

## Usage

You do not run `vvreceive` yourself. A current `vvssh` starts it quietly before executing the login
shell:

```sh
vvreceive --shell-pid $$ --signal-ready </dev/null >/dev/null 2>&1 &
```

`--shell-pid` is required and must come first; `--signal-ready` is optional and must follow it.
Nothing else is accepted, and there is no `--help` or `--version`. With `--signal-ready`,
`vvreceive` raises `SIGUSR1` on the shell once it has captured the shell's identity, which is how
`vvssh` knows it is safe to `exec` the shell.

Discovery and authentication come from the environment `vvssh` exports —
`VIVID_ENDPOINT_CONTROL`, optionally `VIVID_ENDPOINT_BULK`, and `VIVID_ROOT_SECRET`. The root
secret is read only from the environment and has no command-line option.

To suppress the helper for one session:

```bash
vvssh --no-receive-drops user@host
```

A host without `vvreceive` on `PATH` is not an error. Vivido keeps its existing behavior of pasting
the local filename into the PTY.

## Lifetime

`vvreceive` is not a daemon. It is started once per `vvssh` login shell, records that shell's
process start time from `/proc/<pid>/stat`, and exits as soon as the shell does. Comparing the
start time rather than the PID alone means a recycled PID cannot inherit a live receiver. On exit
it disables its file-drop binding when control is available. An independent lifetime watcher
cancels control and bulk sockets when the shell exits; control loss also cancels bulk I/O.
Bulk reads enforce the negotiated idle timeout locally, and the receiver rechecks lifetime
before committing. Destination failures settle through an I/O result or owner-scoped cancellation.

## Limits

| Limit | Value |
|---|---|
| Maximum file | 1 TiB |
| Record body | 1 MiB |
| Credit window | 16 MiB / 32 records |
| Pending offers | 4 |
| Active transfers | 1 |
| Resume attempts per transfer | 3 |

These are compile-time constants. There is no configuration file and no environment tuning; the
only switch that reaches `vvreceive` is whether `vvssh` starts it at all.

## Library

Desktop producers reuse the receive half without the shell-cwd logic:

- `receive_accepted` — receive an already-opened transfer relative to an already-open destination
  directory, using `cap-std` so it works on Linux, macOS, and Windows. It reports no committed
  path: a desktop drop has no terminal to type into.
- `reconcile_committed` — settle a physically committed drop whose protocol result was lost,
  advancing a generation and replying `already committed` rather than ever creating a second file.
- `reconcile_committed_pending` — borrow the committed state so a control loop can retain and
  retry it after a transient error. vvland and vvdesk retain pending outcomes for up to 60 seconds
  without terminating the desktop session. Failed receipt workers request control cancellation.
- `open_xdg_desktop` — resolve the XDG Desktop directory (Linux only).

Portable receipt replenishes the actual channel credit grant. Disk writes update SHA-256 for
each successfully written prefix, including before an error. The Linux receiver resolves the
retained destination directory's current path after commit and caches that path for replay.

[`vvland`](https://github.com/vivido-dev/vvland) and `vvdesk` use these to accept drops onto an
isolated desktop surface.

## Interoperability

`vvreceive` requires `vivid-core-control-v1`, `file-drop-v1`, and `terminal-surface-v1`, and
optionally negotiates `file-drop-path-v1`. The normative contract is
[Vivid 1.5 File Drop](https://github.com/vivido-dev/vivid_protocol/blob/main/vivid-protocol-1.5-file-drop.md).

## License

Apache-2.0.
