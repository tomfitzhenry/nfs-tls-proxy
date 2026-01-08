use anyhow::{bail, Result};
use tls_parser::{parse_tls_plaintext, parse_tls_record_header, TlsRecordType};

pub fn process_tls_buffer(buf: &[u8], source: &str) -> Result<(usize, bool)> {
    let mut offset = 0;
    let mut found_app_data = false;

    loop {
        let remaining = &buf[offset..];
        if remaining.is_empty() {
            break;
        }

        // Try to parse as plaintext first (to inspect handshake messages)
        match parse_tls_plaintext(remaining) {
            Ok((rem, plaintext)) => {
                let consumed = remaining.len() - rem.len();
                log::debug!("Parsed {} record: Type={:?}, Len={}", source, plaintext.hdr.record_type, plaintext.hdr.len);
                
                if plaintext.hdr.record_type == TlsRecordType::ApplicationData {
                    found_app_data = true;
                }
                
                offset += consumed;
                
                if found_app_data {
                    return Ok((offset, true));
                }
            }
            Err(tls_parser::Err::Incomplete(_)) => {
                break; // Need more data
            }
            Err(_) => {
                // Background: if parse_tls_plaintext fails, it might be an encrypted record (e.g. TLS 1.3 after ServerHello).
                // We fallback to just parsing the record header to advance and check for ApplicationData.
                match parse_tls_record_header(remaining) {
                    Ok((_, hdr)) => {
                        // Sanity check: valid record type (20-24)
                        let raw_type = hdr.record_type.0;
                        if raw_type < 20 || raw_type > 24 {
                            bail!("{} sent invalid TLS record type: {}", source, raw_type);
                        }

                        let total_record_len = 5 + hdr.len as usize;
                        if remaining.len() < total_record_len {
                            break; // Need more data for the full record
                        }
                        
                        log::debug!("Forwarding {} encrypted record: Type={:?}, Len={}", source, hdr.record_type, hdr.len);
                        
                        if hdr.record_type == TlsRecordType::ApplicationData {
                            found_app_data = true;
                        }
                        
                        offset += total_record_len;
                        
                        if found_app_data {
                            return Ok((offset, true));
                        }
                    }
                    Err(e) => {
                        bail!("{} sent truly invalid TLS data: {:?}", source, e);
                    }
                }
            }
        }
    }

    Ok((offset, false))
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
        // Simple Handshake header (ClientHello-like)
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04];
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // 4 bytes of "handshake"
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
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04]; // Handshake
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02]); // App Data
        buf.extend_from_slice(&[0x05, 0x06]);
        
        let (consumed, hit_app_data) = process_tls_buffer(&buf, "Test").unwrap();
        assert_eq!(consumed, 9 + 7);
        assert!(hit_app_data);
    }

    #[test]
    fn test_process_tls_buffer_invalid() {
        // Record type 0 is invalid.
        let buf = [0x00, 0x03, 0x03, 0x00, 0x01, 0xFF];
        let res = process_tls_buffer(&buf, "Test");
        assert!(res.is_err());
    }
}
