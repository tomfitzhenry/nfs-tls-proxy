use anyhow::{bail, Result};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

pub const STARTTLS_PROGRAM: u32 = 100235;
pub const STARTTLS_VERSION: u32 = 1;
pub const STARTTLS_PROC: u32 = 0; // NULL
pub const RPC_VERSION_2: u32 = 2;
pub const MSG_TYPE_CALL: u32 = 0;

/// Validates that the provided buffer contains a valid RPC CALL header for NfsTlshd STARTTLS.
/// Returns Ok(()) if valid, Err otherwise.
pub fn validate_starttls_header(buf: &[u8]) -> Result<()> {
    // Basic length check: XID(4) + Type(4) + RpcVer(4) + Prog(4) + Vers(4) + Proc(4) = 24 bytes minimum
    if buf.len() < 24 {
        bail!("Message too short to be an RPC Call");
    }

    let mut rdr = Cursor::new(buf);

    // Skip XID (4 bytes) - opaque identifier
    let _xid = rdr.read_u32::<BigEndian>()?;

    let msg_type = rdr.read_u32::<BigEndian>()?;
    if msg_type != MSG_TYPE_CALL {
        bail!("Invalid IPC Message Type: expected CALL (0), got {}", msg_type);
    }

    let rpc_vers = rdr.read_u32::<BigEndian>()?;
    if rpc_vers != RPC_VERSION_2 {
        bail!("Invalid RPC Version: expected 2, got {}", rpc_vers);
    }

    let program = rdr.read_u32::<BigEndian>()?;
    if program != STARTTLS_PROGRAM {
        bail!("Invalid RPC Program: expected NfsTlshd (100235), got {}", program);
    }

    let version = rdr.read_u32::<BigEndian>()?;
    if version != STARTTLS_VERSION {
        bail!("Invalid Program Version: expected 1, got {}", version);
    }

    let proc = rdr.read_u32::<BigEndian>()?;
    if proc != STARTTLS_PROC {
        bail!("Invalid Procedure: expected NULL (0), got {}", proc);
    }

    // We don't strictly need to parse Cred/Verf for the basic sanity check of "Is this a STARTTLS attempt?"
    // If the client sends garbage creds, the upstream server will reject it, which is fine.
    // We just want to ensure we aren't proxying random TLS noise or HTTP or SSH to the kernel port
    // before the switch happens (though the switch only happens AFTER this RPC reply).

    // Wait, strictly speaking, this proxy sits in front.
    // Flow:
    // 1. Client connects.
    // 2. Client sends RPC NULL Call to Program 100235 to signal "I want TLS".
    // 3. Server (Proxy -> Upstream) replies with RPC Reply.
    // 4. Client sends TLS ClientHello.
    //
    // So we need to validate step 2.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;

    #[test]
    fn test_valid_starttls_header() {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(0x12345678).unwrap(); // XID
        buf.write_u32::<BigEndian>(MSG_TYPE_CALL).unwrap();
        buf.write_u32::<BigEndian>(RPC_VERSION_2).unwrap();
        buf.write_u32::<BigEndian>(STARTTLS_PROGRAM).unwrap();
        buf.write_u32::<BigEndian>(STARTTLS_VERSION).unwrap();
        buf.write_u32::<BigEndian>(STARTTLS_PROC).unwrap();
        
        assert!(validate_starttls_header(&buf).is_ok());
    }

    #[test]
    fn test_invalid_program() {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(0x12345678).unwrap();
        buf.write_u32::<BigEndian>(MSG_TYPE_CALL).unwrap();
        buf.write_u32::<BigEndian>(RPC_VERSION_2).unwrap();
        buf.write_u32::<BigEndian>(100003).unwrap(); // NFS program, not STARTTLS
        buf.write_u32::<BigEndian>(STARTTLS_VERSION).unwrap();
        buf.write_u32::<BigEndian>(STARTTLS_PROC).unwrap();
        
        assert!(validate_starttls_header(&buf).is_err());
    }
}
