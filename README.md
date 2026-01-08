# NFS-over-TLS Handshake Proxy

A Rust-based transparent proxy designed to sit in front of a Linux kernel NFS server (`nfsd`). It performs deep packet inspection of the initial connection handshake to ensure only valid RPC and TLS sequences reach the kernel space, mitigating potential parsing vulnerabilities in the kernel's pre-authentication code paths.

## Features

- **XDR Validation**: Hand-rolled decoder to verify the initial `STARTTLS` RPC Call (RFC 9289).
- **TLS Handshake Inspection**: Uses `tls-parser` to validate the bidirectional flight of TLS record headers until encryption is established.
- **Zero-Copy Splicing**: Switches to `splice(2)` via `tokio-splice2` for high-performance bidirectional data transfer once the handshake is verified.
- **Security-First**: Aborts connections immediately if invalid byte sequences or unexpected record types are detected.

## Architecture

1. **Phase 1: XDR Sanity**: Validates the first RPC fragment is a `STARTTLS` command (Program 100235, Version 1, Procedure 0).
2. **Phase 2: Handshake Loop**: Intercepts and parses all TLS records (Handshake, Alert, CCS). Validates record structure and header integrity.
3. **Phase 3: Splice**: Upon detecting the first `ApplicationData` record, the proxy flushes its buffers and offloads the remaining stream to the kernel using zero-copy splicing.

## Usage

### Prerequisites
- Linux with `splice(2)` support.
- Rust toolchain (Stable).

### Building
```bash
cargo build --release
```

### Running
The proxy listens on port 2049 by default and forwards to an upstream `nfsd`.

```bash
# Run the proxy (requires privileges to bind 2049)
sudo target/release/nfs-tls-proxy --listen 0.0.0.0:2049 --upstream 127.0.0.1:20000
```

*Note: Ensure your kernel `nfsd` is configured to listen on the `--upstream` port (e.g., 20000) instead of the default 2049.*

## Testing

The project includes a robust integration test suite that uses a real `rustls` stack to simulate a full encrypted NFS negotiation.

```bash
cargo test
```

## Dependencies

- `tokio`: Async I/O runtime.
- `tokio-splice2`: Rust bindings for Linux `splice(2)`.
- `tls-parser`: Nominal parsing of TLS records.
- `rustls`: Used for real-world integration testing.
