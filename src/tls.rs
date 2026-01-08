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
                match hdr.record_type {
                    TlsRecordType::Handshake
                    | TlsRecordType::ChangeCipherSpec
                    | TlsRecordType::Alert
                    | TlsRecordType::Heartbeat => {
                        match parse_tls_plaintext(record_data) {
                            Ok((_, plaintext)) => {
                                log::debug!(
                                    "Parsed {} {:?}: Len={}",
                                    source,
                                    hdr.record_type,
                                    plaintext.hdr.len
                                );
                            }
                            Err(e) => {
                                log::debug!(
                                    "{} {:?} parsing issue (potentially encrypted): {:?}",
                                    source,
                                    hdr.record_type,
                                    e
                                );
                                // Treat parsing errors as fatal during handshake phase
                                bail!(
                                    "{} sent malformed or unsupported {:?} data: {:?}",
                                    source,
                                    hdr.record_type,
                                    e
                                );
                            }
                        }
                    }
                    TlsRecordType::ApplicationData => {
                        log::debug!(
                            "Forwarding {} record: Type={:?}, Len={}",
                            source,
                            hdr.record_type,
                            hdr.len
                        );
                        found_app_data = true;
                    }
                    _ => {
                        bail!(
                            "{} sent invalid or unsupported TLS record type: {}",
                            source,
                            hdr.record_type.0
                        );
                    }
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
}
