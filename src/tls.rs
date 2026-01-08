use anyhow::{bail, Result};
use nom::bytes::streaming::take;
use nom::{Err as NomErr, IResult};
use tls_parser::{parse_tls_plaintext, parse_tls_record_header, TlsRecordHeader, TlsRecordType};

pub fn process_tls_buffer(buf: &[u8], source: &str) -> Result<(usize, bool)> {
    let mut input = buf;
    let mut found_app_data = false;

    while !input.is_empty() {
        match parse_record_envelope(input) {
            Ok((remaining, (hdr, record_data))) => {
                // Sanity check: valid record type (20-24)
                let raw_type = hdr.record_type.0;
                if !(20..=24).contains(&raw_type) {
                    bail!("{} sent invalid TLS record type: {}", source, raw_type);
                }

                if hdr.record_type == TlsRecordType::Handshake {
                    match parse_tls_plaintext(record_data) {
                        Ok((_, plaintext)) => {
                            log::debug!("Parsed {} handshake: Len={}", source, plaintext.hdr.len);
                        }
                        Err(_) => {
                            // Handshake might be encrypted (TLS 1.3) or just malformed for the parser.
                            log::debug!(
                                "Forwarding {} opaque or encrypted handshake: Len={}",
                                source,
                                hdr.len
                            );
                        }
                    }
                } else {
                    log::debug!(
                        "Forwarding {} record: Type={:?}, Len={}",
                        source,
                        hdr.record_type,
                        hdr.len
                    );
                }

                if hdr.record_type == TlsRecordType::ApplicationData {
                    found_app_data = true;
                }

                input = remaining;

                if found_app_data {
                    break;
                }
            }
            Err(NomErr::Incomplete(_)) => {
                break; // Need more data
            }
            Err(e) => {
                bail!("{} sent truly invalid TLS data: {:?}", source, e);
            }
        }
    }

    let consumed = buf.len() - input.len();
    Ok((consumed, found_app_data))
}

fn parse_record_envelope(i: &[u8]) -> IResult<&[u8], (TlsRecordHeader, &[u8])> {
    let start = i;
    let (i, hdr) = parse_tls_record_header(i)?;
    let (i, _) = take(hdr.len)(i)?;
    let consumed = start.len() - i.len();
    Ok((i, (hdr, &start[..consumed])))
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
