use anyhow::{bail, Result};
use nom::{Err as NomErr};
use tls_parser::{parse_tls_plaintext, parse_tls_record_header, TlsRecordType};

pub fn process_tls_buffer(buf: &[u8], source: &str) -> Result<(usize, bool)> {
    let mut offset = 0;
    while offset < buf.len() {
        let input = &buf[offset..];
        let (_, hdr) = match parse_tls_record_header(input) {
            Ok(res) => res,
            Err(NomErr::Incomplete(_)) => break,
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
            break;
        }
        let record = &input[..record_len];

        match hdr.record_type {
            TlsRecordType::ApplicationData => {
                log::debug!("Forwarding {} record: Type={:?}, Len={}", source, hdr.record_type, hdr.len);
                return Ok((offset + record_len, true));
            }
            TlsRecordType::Handshake => {
                if hdr.len < 4 {
                    bail!("{} sent too short Handshake record: {} bytes", source, hdr.len);
                }
                validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            }
            TlsRecordType::ChangeCipherSpec => {
                if hdr.len != 1 {
                    bail!("{} sent invalid ChangeCipherSpec record: {} bytes", source, hdr.len);
                }
                validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            }
            TlsRecordType::Alert => {
                if hdr.len != 2 {
                    bail!("{} sent invalid Alert record: {} bytes", source, hdr.len);
                }
                validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            }
            TlsRecordType::Heartbeat => {
                validate_plaintext(record, source, hdr.record_type, hdr.len)?;
            }
            _ => {
                bail!("{} sent invalid or unsupported TLS record type: {}", source, hdr.record_type.0);
            }
        }
        offset += record_len;
    }

    Ok((offset, false))
}

fn validate_plaintext(record: &[u8], source: &str, record_type: TlsRecordType, len: u16) -> Result<()> {
    if let Err(e) = parse_tls_plaintext(record) {
        log::debug!("{} {:?} parsing issue (potentially encrypted): {:?}", source, record_type, e);
        bail!("{} sent malformed or unsupported {:?} data: {:?}", source, record_type, e);
    }
    log::debug!("Parsed {} {:?}: Len={}", source, record_type, len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_tls_buffer_incomplete() {
        let buf = [0x16, 0x03, 0x01]; // Incomplete header
        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 0);
        assert!(!hit_app_data);
    }

    #[test]
    fn test_process_tls_buffer_handshake() {
        // Simple Handshake header (HelloRequest)
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04];
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // HelloRequest (Type 0, Length 0)
        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 9);
        assert!(!hit_app_data);
    }

    #[test]
    fn test_process_tls_buffer_application_data() {
        let mut buf = vec![0x17, 0x03, 0x03, 0x00, 0x04];
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 9);
        assert!(hit_app_data);
    }

    #[test]
    fn test_process_tls_buffer_multiple_records() {
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04]; // Handshake (HelloRequest)
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02]); // App Data
        buf.extend_from_slice(&[0x05, 0x06]);
        
        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 9 + 7);
        assert!(hit_app_data);
    }

    #[test]
    fn test_process_tls_buffer_change_cipher_spec() {
        let buf = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 6);
        assert!(!hit_app_data);
    }

    #[test]
    fn test_process_tls_buffer_alert() {
        let buf = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00]; // Close notify
        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 7);
        assert!(!hit_app_data);
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

        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 5 + heartbeat_data.len());
        assert!(!hit_app_data);
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
}
