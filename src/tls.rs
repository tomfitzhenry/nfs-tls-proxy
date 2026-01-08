use anyhow::{bail, Result};
use nom::{Err as NomErr};
use tls_parser::{parse_tls_plaintext, parse_tls_record_header, TlsMessage, TlsRecordType};

pub fn process_tls_buffer(buf: &[u8], source: &str) -> Result<(usize, Option<TlsRecordType>)> {
    let input = buf;
    let (_, hdr) = match parse_tls_record_header(input) {
        Ok(res) => res,
        Err(NomErr::Incomplete(_)) => return Ok((0, None)),
        Err(e) => bail!("{} sent truly invalid TLS data: {:?}", source, e),
    };

    // RFC 5246/8446: Max record length is 2^14 bytes (16384)
    if hdr.len > 16384 {
        bail!("{} sent oversized TLS record: {} bytes", source, hdr.len);
    }

    // Sanity check version: 0x0301 (TLS 1.0) or higher.
    if hdr.version.0 < 0x0301 {
        bail!("{} sent unsupported TLS version: 0x{:04x}", source, hdr.version.0);
    }

    let record_len = 5 + hdr.len as usize;
    if input.len() < record_len {
        return Ok((0, None));
    }
    let record = &input[..record_len];

    match hdr.record_type {
        TlsRecordType::ApplicationData => {
            log::debug!("Forwarding {} record: Type={:?}, Len={}", source, hdr.record_type, hdr.len);
            Ok((record_len, Some(TlsRecordType::ApplicationData)))
        }
        TlsRecordType::Handshake => {
            if hdr.len < 4 {
                bail!("{} sent too short Handshake record: {} bytes", source, hdr.len);
            }
            validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            Ok((record_len, Some(TlsRecordType::Handshake)))
        }
        TlsRecordType::ChangeCipherSpec => {
            if hdr.len != 1 {
                bail!("{} sent invalid ChangeCipherSpec record: {} bytes", source, hdr.len);
            }
            validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            Ok((record_len, Some(TlsRecordType::ChangeCipherSpec)))
        }
        TlsRecordType::Alert => {
            if hdr.len != 2 {
                bail!("{} sent invalid Alert record: {} bytes", source, hdr.len);
            }
            validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            Ok((record_len, Some(TlsRecordType::Alert)))
        }
        TlsRecordType::Heartbeat => {
            validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            Ok((record_len, Some(TlsRecordType::Heartbeat)))
        }
        _ => {
            bail!("{} sent invalid or unsupported TLS record type: {}", source, hdr.record_type.0);
        }
    }
}

fn validate_plaintext(record: &[u8], source: &str, record_type: TlsRecordType, record_payload_len: u16) -> Result<()> {
    match parse_tls_plaintext(record) {
        Ok((_, plaintext)) => {
            for msg in &plaintext.msg {
                // Validate that the record type matches the message type
                let msg_matches_record = match (&msg, record_type) {
                    (TlsMessage::Handshake(_), TlsRecordType::Handshake) => true,
                    (TlsMessage::Alert(_), TlsRecordType::Alert) => true,
                    (TlsMessage::ChangeCipherSpec, TlsRecordType::ChangeCipherSpec) => true,
                    (TlsMessage::Heartbeat(_), TlsRecordType::Heartbeat) => true,
                    (TlsMessage::ApplicationData(_), TlsRecordType::ApplicationData) => true,
                    _ => false,
                };
                
                if !msg_matches_record {
                    bail!("{} sent TLS record with mismatched type: record_type={:?}, but message is {:?}", 
                          source, record_type, msg);
                }
                
                if let TlsMessage::Heartbeat(hb) = msg {
                    // Explicit check for Heartbleed-style length mismatch.
                    // The payload field in TlsMessageHeartbeat is the actual data parsed.
                    // If its length is less than the claimed payload_len, it's an attack.
                    if hb.payload.len() < hb.payload_len as usize {
                        bail!("{} sent Heartbeat with mismatched length: claimed {}, got {}", source, hb.payload_len, hb.payload.len());
                    }
                }
            }
            log::debug!("Parsed {} {:?}: Len={}", source, record_type, record_payload_len);
            Ok(())
        }
        Err(e) => {
            log::debug!("{} {:?} parsing issue (potentially encrypted): {:?}", source, record_type, e);
            
            // If the parser fails with an error that indicates we ran out of data
            // (even though we provided the full record), it's a length mismatch.
            let err_str = format!("{:?}", e);
            if err_str.contains("Complete") || err_str.contains("Incomplete") {
                 bail!("{} sent {:?} message with mismatched length", source, record_type);
            }

            bail!("{} sent malformed or unsupported {:?} data: {:?}", source, record_type, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_tls_buffer_incomplete() {
        let buf = [0x16, 0x03, 0x01]; // Incomplete header
        let (consumed, record_type) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 0);
        assert_eq!(record_type, None);
    }

    #[test]
    fn test_process_tls_buffer_handshake() {
        // Simple Handshake header (HelloRequest)
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04];
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // HelloRequest (Type 0, Length 0)
        let (consumed, record_type) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 9);
        assert_eq!(record_type, Some(TlsRecordType::Handshake));
    }

    #[test]
    fn test_process_tls_buffer_application_data() {
        let mut buf = vec![0x17, 0x03, 0x03, 0x00, 0x04];
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let (consumed, record_type) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 9);
        assert_eq!(record_type, Some(TlsRecordType::ApplicationData));
    }

    #[test]
    fn test_process_tls_buffer_multiple_records() {
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04]; // Handshake (HelloRequest)
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02]); // App Data
        buf.extend_from_slice(&[0x05, 0x06]);
        
        // First call: Handshake
        let (consumed1, record_type1) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed1, 9);
        assert_eq!(record_type1, Some(TlsRecordType::Handshake));

        // Second call: App Data
        let (consumed2, record_type2) = process_tls_buffer(&buf[consumed1..], "Test").unwrap();
        assert_eq!(consumed2, 7);
        assert_eq!(record_type2, Some(TlsRecordType::ApplicationData));
    }

    #[test]
    fn test_process_tls_buffer_change_cipher_spec() {
        let buf = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        let (consumed, record_type) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(record_type, Some(TlsRecordType::ChangeCipherSpec));
    }

    #[test]
    fn test_process_tls_buffer_alert() {
        let buf = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00]; // Close notify
        let (consumed, record_type) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(record_type, Some(TlsRecordType::Alert));
    }

    #[test]
    fn test_process_tls_buffer_heartbeat() {
        // Heartbeat request: Type 1, Payload Length 1, 1 byte payload, 16 bytes padding
        let mut heartbeat_data = vec![0x01, 0x00, 0x01, 0x42];
        heartbeat_data.extend_from_slice(&[0x00; 16]);
        
        let mut buf = vec![0x18, 0x03, 0x03];
        let len = heartbeat_data.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&heartbeat_data);

        let (consumed, record_type) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 5 + heartbeat_data.len());
        assert_eq!(record_type, Some(TlsRecordType::Heartbeat));
    }

    #[test]
    fn test_process_tls_buffer_invalid_ccs() {
        let buf = [0x14, 0x03, 0x03, 0x00, 0x01, 0x02]; // CCS must be 1
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
    }

    #[test]
    fn test_process_tls_buffer_invalid() {
        // Record type 0 is invalid.
        let buf = [0x00, 0x03, 0x03, 0x00, 0x01, 0xFF];
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
    }

    #[test]
    fn test_process_tls_buffer_oversized_record() {
        let mut buf = vec![0x16, 0x03, 0x03, 0x40, 0x01]; // Length 16385 (0x4001)
        buf.resize(5 + 16385, 0);
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("oversized"));
    }

    #[test]
    fn test_process_tls_buffer_invalid_version() {
        let buf = [0x16, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]; // SSL 3.0
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("unsupported TLS version"));
    }

    #[test]
    fn test_process_tls_buffer_handshake_too_short() {
        let buf = [0x16, 0x03, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00]; // Handshake length 3 (min 4)
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("too short Handshake record"));
    }

    #[test]
    fn test_process_tls_buffer_alert_wrong_size() {
        let buf = [0x15, 0x03, 0x03, 0x00, 0x03, 0x02, 0x00, 0x00]; // Alert length 3 (must be 2)
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid Alert record"));
    }

    #[test]
    fn test_process_tls_buffer_handshake_mismatched_length() {
        // Handshake record with length 4, but inner handshake header says length 10
        let buf = [
            0x16, 0x03, 0x03, 0x00, 0x04, // Record header: Handshake, length 4
            0x00, 0x00, 0x00, 0x0a,       // Handshake header: HelloRequest (0), length 10
        ];
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("mismatched length"));
    }

    #[test]
    fn test_process_tls_buffer_heartbeat_mismatched_length() {
        // Heartbeat request: Type 1, Payload Length 100, but only 1 byte payload and 16 bytes padding
        let mut heartbeat_data = vec![0x01, 0x00, 0x64, 0x42]; // Type 1, Len 100, Payload 0x42
        heartbeat_data.extend_from_slice(&[0x00; 16]); // 16 bytes padding
        
        let mut buf = vec![0x18, 0x03, 0x03]; // Heartbeat record
        let len = heartbeat_data.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&heartbeat_data);

        let res = process_tls_buffer(&buf, "Test");
        // This should fail because the payload length (100) exceeds the actual record payload length
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("mismatched length"));
    }

    #[test]
    fn test_process_tls_buffer_mismatched_record_and_message_type() {
        // Try to create a scenario where tls-parser successfully parses the content
        // but the record type doesn't match the message type.
        // We'll use an Alert record (0x15) with proper Alert content (2 bytes),
        // but claim it's a Handshake record (0x16) in the header.
        
        // First, let's try with a valid Alert wrapped as Handshake
        // Alert: level=2 (fatal), description=0 (close_notify)
        // But we need at least 4 bytes for handshake validation to pass
        let buf = [
            0x16, 0x03, 0x03, 0x00, 0x04, // Record header: Handshake type, length 4
            0x02, 0x00, 0x00, 0x00,       // Alert-like content: level 2, desc 0, padding
        ];
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        println!("Error message: {}", err_msg);
        // Should fail with either mismatched type or malformed/mismatched length
        assert!(err_msg.contains("mismatched") || err_msg.contains("malformed"));
    }

}
