//! An incremental TLS ClientHello parser that yields the requested server name (AL-4).
//!
//! The guest decides how its bytes are cut into TCP segments and TLS records, so the parser is a small state
//! machine that can be fed any chunking: it reassembles the handshake message across records and stops at the
//! first complete ClientHello. It never trusts a declared length further than the bytes that actually arrived:
//!
//! * at most [`MAX_CLIENT_HELLO_LEN`] bytes of ClientHello body and [`MAX_RECORDS`] records are accepted, so a
//!   terminal status is reached after at most [`MAX_BUFFERED_LEN`] bytes, whatever the guest sends;
//! * memory grows with the bytes received, never with a length field;
//! * a name is reported only if it is the single `host_name` of the single `server_name` extension and parses
//!   as a [`DnsName`]. An IP literal, a second name or a duplicate extension is `Malformed`, because a relay
//!   and a server that could read different names out of one hello would defeat the check.

use crate::policy::DnsName;
use crate::reader::Reader;

/// Largest ClientHello body accepted. Real ones, post-quantum key shares included, stay below 4 KiB.
pub const MAX_CLIENT_HELLO_LEN: usize = 16 * 1024;
/// Most TLS records one ClientHello may be fragmented across.
pub const MAX_RECORDS: usize = 16;
/// Upper bound on the bytes consumed before a terminal status: the body, its handshake header and the record headers.
pub const MAX_BUFFERED_LEN: usize = MAX_CLIENT_HELLO_LEN + HANDSHAKE_HEADER_LEN + MAX_RECORDS * RECORD_HEADER_LEN;

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
/// TLS plaintext records carry at most 2^14 bytes.
const MAX_RECORD_PAYLOAD_LEN: usize = 16 * 1024;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// Record-layer versions a ClientHello may travel under: TLS 1.0 (what current clients write) to TLS 1.3.
const RECORD_VERSIONS: std::ops::RangeInclusive<u16> = 0x0301..=0x0304;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST_NAME: u8 = 0;
const MAX_SESSION_ID_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniStatus {
    /// The ClientHello is not complete yet.
    NeedMore,
    /// A complete, well-formed ClientHello; `None` when it carries no server name.
    Done(Option<DnsName>),
    /// The first bytes are not a TLS handshake record.
    NotTls,
    /// TLS, but not a ClientHello this parser accepts.
    Malformed,
}

#[derive(Debug, Default)]
pub struct ClientHelloParser {
    /// The terminal status once reached; input after it is ignored.
    outcome: Option<SniStatus>,
    header: [u8; RECORD_HEADER_LEN],
    header_len: usize,
    /// Payload bytes of the current record still to come.
    record_remaining: usize,
    records: usize,
    /// The reassembled handshake message: its four-byte header, then the ClientHello body.
    hello: Vec<u8>,
    consumed: usize,
}

impl ClientHelloParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes the next bytes of the stream, however they were segmented. Once a status other than
    /// `NeedMore` is returned it is final: later calls return it again and consume nothing.
    pub fn feed(&mut self, mut bytes: &[u8]) -> SniStatus {
        while self.outcome.is_none() && !bytes.is_empty() {
            let used = if self.record_remaining == 0 { self.feed_record_header(bytes) } else { self.feed_fragment(bytes) };
            self.consumed += used;
            bytes = bytes.get(used..).unwrap_or_default();
        }
        self.outcome.clone().unwrap_or(SniStatus::NeedMore)
    }

    /// Bytes consumed so far; never more than [`MAX_BUFFERED_LEN`].
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// Bytes currently held for reassembly; never more than [`MAX_CLIENT_HELLO_LEN`] plus the handshake header.
    pub fn buffered(&self) -> usize {
        self.hello.len()
    }

    /// Collects and checks a record header as its bytes arrive, so plain-text protocols are recognised at once.
    fn feed_record_header(&mut self, bytes: &[u8]) -> usize {
        if self.records == MAX_RECORDS {
            self.outcome = Some(SniStatus::Malformed);
            return 0;
        }
        let before = self.header_len;
        for (slot, byte) in self.header.iter_mut().skip(before).zip(bytes) {
            *slot = *byte;
            self.header_len += 1;
        }
        let used = self.header_len - before;
        let [content_type, major, minor, length_high, length_low] = self.header;
        let not_handshake = self.header_len >= 1 && content_type != CONTENT_TYPE_HANDSHAKE;
        let bad_version = self.header_len >= 3 && !RECORD_VERSIONS.contains(&u16::from_be_bytes([major, minor]));
        if not_handshake || bad_version {
            // The first record decides whether this is TLS at all; later ones must continue the handshake.
            self.outcome = Some(if self.records == 0 { SniStatus::NotTls } else { SniStatus::Malformed });
        } else if self.header_len == RECORD_HEADER_LEN {
            let length = usize::from(u16::from_be_bytes([length_high, length_low]));
            if length == 0 || length > MAX_RECORD_PAYLOAD_LEN {
                self.outcome = Some(SniStatus::Malformed);
            } else {
                self.records += 1;
                self.record_remaining = length;
                self.header_len = 0;
            }
        }
        used
    }

    /// Appends record payload to the handshake message and parses it once it is complete.
    fn feed_fragment(&mut self, bytes: &[u8]) -> usize {
        let take = self.record_remaining.min(bytes.len());
        self.record_remaining -= take;
        let fragment = bytes.get(..take).unwrap_or(bytes);

        let fragment = self.absorb(fragment, HANDSHAKE_HEADER_LEN);
        let Some([message_type, a, b, c]) = self.hello.first_chunk::<HANDSHAKE_HEADER_LEN>().copied() else { return take };
        let body_len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
        if message_type != HANDSHAKE_CLIENT_HELLO || body_len > MAX_CLIENT_HELLO_LEN {
            self.outcome = Some(SniStatus::Malformed);
            return take;
        }
        // Whatever the record carries past the ClientHello is not ours to parse and is left alone.
        let total = HANDSHAKE_HEADER_LEN + body_len;
        self.absorb(fragment, total);
        if self.hello.len() == total {
            let body = self.hello.get(HANDSHAKE_HEADER_LEN..).unwrap_or_default();
            self.outcome = Some(server_name(body).map_or(SniStatus::Malformed, SniStatus::Done));
        }
        take
    }

    /// Moves bytes from `fragment` into the handshake message until it holds `target` bytes; returns the rest.
    fn absorb<'a>(&mut self, fragment: &'a [u8], target: usize) -> &'a [u8] {
        let missing = target.saturating_sub(self.hello.len()).min(fragment.len());
        let (wanted, rest) = fragment.split_at_checked(missing).unwrap_or((fragment, &[]));
        self.hello.extend_from_slice(wanted);
        rest
    }
}

/// Walks a ClientHello body (RFC 8446 section 4.1.2) to its `server_name` extension. `None` is a malformed
/// hello; `Some(None)` is a well-formed hello without a server name.
fn server_name(body: &[u8]) -> Option<Option<DnsName>> {
    let mut hello = Reader::new(body);
    let _legacy_version = hello.take(2)?;
    let _random = hello.take(32)?;
    let session_id = hello.vec8()?;
    let cipher_suites = hello.vec16()?;
    let compression_methods = hello.vec8()?;
    if session_id.len() > MAX_SESSION_ID_LEN || cipher_suites.is_empty() || cipher_suites.len() % 2 != 0 || compression_methods.is_empty() {
        return None;
    }
    if hello.is_empty() {
        // Extensions are optional before TLS 1.3.
        return Some(None);
    }
    let mut extensions = Reader::new(hello.vec16()?);
    if !hello.is_empty() {
        return None;
    }
    let mut found = None;
    while !extensions.is_empty() {
        let extension_type = extensions.u16()?;
        let data = extensions.vec16()?;
        if extension_type == EXTENSION_SERVER_NAME {
            // RFC 8446 section 4.2: an extension type appears at most once.
            if found.is_some() {
                return None;
            }
            found = Some(host_name(data)?);
        }
    }
    Some(found)
}

/// RFC 6066 section 3, narrowed: the list holds exactly one name, of type `host_name`, and it is a [`DnsName`].
fn host_name(data: &[u8]) -> Option<DnsName> {
    let mut extension = Reader::new(data);
    let mut list = Reader::new(extension.vec16()?);
    let name_type = list.u8()?;
    let name = list.vec16()?;
    if !extension.is_empty() || !list.is_empty() || name_type != NAME_TYPE_HOST_NAME {
        return None;
    }
    DnsName::parse(std::str::from_utf8(name).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn len16(len: usize) -> [u8; 2] {
        u16::try_from(len).unwrap().to_be_bytes()
    }

    fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        [&extension_type.to_be_bytes()[..], &len16(data.len()), data].concat()
    }

    /// The `server_name` extension as real clients send it: one `host_name` entry.
    fn sni(name: &[u8]) -> Vec<u8> {
        let entry = [&[NAME_TYPE_HOST_NAME][..], &len16(name.len()), name].concat();
        extension(EXTENSION_SERVER_NAME, &[&len16(entry.len())[..], &entry].concat())
    }

    /// A ClientHello body shaped like a modern browser's: GREASE values, a large key share, and the server
    /// name in the middle of the extension list. `extensions` replaces the server_name extension.
    fn hello_body(extensions: &[u8]) -> Vec<u8> {
        let cipher_suites = [0x1a, 0x1a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f];
        let mut all = extension(0x2a2a, &[]);
        all.extend(extension(0x000a, &[0, 6, 0x3a, 0x3a, 0x11, 0xec, 0x00, 0x1d]));
        all.extend(extension(0x002b, &[4, 0x9a, 0x9a, 0x03, 0x04]));
        all.extend_from_slice(extensions);
        all.extend(extension(0x0010, &[0, 3, 2, b'h', b'2']));
        all.extend(extension(0x0033, &[0x77; 1220]));
        all.extend(extension(0xfafa, &[0]));

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x5a; 32]);
        body.push(32);
        body.extend_from_slice(&[0xa5; 32]);
        body.extend_from_slice(&len16(cipher_suites.len()));
        body.extend_from_slice(&cipher_suites);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&len16(all.len()));
        body.extend(all);
        body
    }

    fn handshake(message_type: u8, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        [&[message_type, len[1], len[2], len[3]][..], body].concat()
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        [&[CONTENT_TYPE_HANDSHAKE, 0x03, 0x01][..], &len16(payload.len()), payload].concat()
    }

    /// Splits `message` into records of the given payload sizes; the last record takes what is left.
    fn fragmented(message: &[u8], sizes: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = message;
        for size in sizes {
            let (head, tail) = rest.split_at((*size).min(rest.len()));
            if !head.is_empty() {
                out.extend(record(head));
            }
            rest = tail;
        }
        if !rest.is_empty() {
            out.extend(record(rest));
        }
        out
    }

    fn client_hello(name: &str) -> Vec<u8> {
        record(&handshake(HANDSHAKE_CLIENT_HELLO, &hello_body(&sni(name.as_bytes()))))
    }

    fn feed_all(stream: &[u8]) -> SniStatus {
        ClientHelloParser::new().feed(stream)
    }

    fn done(name: &str) -> SniStatus {
        SniStatus::Done(Some(DnsName::parse(name).unwrap()))
    }

    /// The status of a hello whose only variation is the bytes standing where the server_name extension goes.
    fn status_with(extensions: &[u8]) -> SniStatus {
        feed_all(&record(&handshake(HANDSHAKE_CLIENT_HELLO, &hello_body(extensions))))
    }

    #[test]
    fn extracts_the_server_name_from_one_record() {
        let stream = client_hello("api.example.com");
        assert!(stream.len() > 1300, "the fixture is as large as a real hello");
        let mut parser = ClientHelloParser::new();
        assert_eq!(parser.feed(&stream), done("api.example.com"));
        assert_eq!(parser.consumed(), stream.len());
        assert_eq!(feed_all(&client_hello("API.Example.COM")), done("api.example.com"));
    }

    #[test]
    fn a_split_at_every_byte_boundary_gives_the_same_answer() {
        let stream = client_hello("api.example.com");
        for cut in 0..=stream.len() {
            let mut parser = ClientHelloParser::new();
            let first = parser.feed(&stream[..cut]);
            assert_eq!(first, if cut == stream.len() { done("api.example.com") } else { SniStatus::NeedMore }, "cut at {cut}");
            assert_eq!(parser.feed(&stream[cut..]), done("api.example.com"), "cut at {cut}");
        }
    }

    #[test]
    fn one_byte_at_a_time_needs_every_byte() {
        let stream = client_hello("api.example.com");
        let mut parser = ClientHelloParser::new();
        for (index, byte) in stream.iter().enumerate() {
            let expected = if index + 1 == stream.len() { done("api.example.com") } else { SniStatus::NeedMore };
            assert_eq!(parser.feed(&[*byte]), expected, "byte {index}");
        }
    }

    #[test]
    fn reassembles_a_hello_fragmented_across_records() {
        let message = handshake(HANDSHAKE_CLIENT_HELLO, &hello_body(&sni(b"api.example.com")));
        // Fragments that cut the handshake header, the fixed fields and the server name itself.
        for sizes in [&[1][..], &[3, 1, 40], &[4], &[5, 100, 7, 1], &[150, 150, 150], &[1; 15], &[message.len() - 1]] {
            let stream = fragmented(&message, sizes);
            assert_eq!(feed_all(&stream), done("api.example.com"), "{sizes:?}");
            for cut in 0..stream.len() {
                let mut parser = ClientHelloParser::new();
                assert_eq!(parser.feed(&stream[..cut]), SniStatus::NeedMore, "{sizes:?} cut at {cut}");
                assert_eq!(parser.feed(&stream[cut..]), done("api.example.com"), "{sizes:?} cut at {cut}");
            }
        }
        // Record versions 0x0301..=0x0304 are all accepted in the record layer.
        for minor in 1..=4u8 {
            let mut stream = fragmented(&message, &[10]);
            stream[2] = minor;
            assert_eq!(feed_all(&stream), done("api.example.com"), "record version 3.{minor}");
        }
    }

    #[test]
    fn bytes_after_the_hello_are_ignored_and_the_status_is_final() {
        let hello = client_hello("api.example.com");
        let mut stream = hello.clone();
        stream.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02, 0xde, 0xad]);
        let mut parser = ClientHelloParser::new();
        assert_eq!(parser.feed(&stream), done("api.example.com"));
        assert_eq!(parser.consumed(), hello.len());
        let buffered = parser.buffered();
        assert_eq!(parser.feed(b"anything at all"), done("api.example.com"));
        assert_eq!((parser.consumed(), parser.buffered()), (hello.len(), buffered));

        // A second handshake message in the same record is left alone as well.
        let mut two = handshake(HANDSHAKE_CLIENT_HELLO, &hello_body(&sni(b"api.example.com")));
        two.extend(handshake(2, &[0; 8]));
        assert_eq!(feed_all(&record(&two)), done("api.example.com"));
    }

    #[test]
    fn a_hello_without_a_server_name_is_done_with_none() {
        assert_eq!(status_with(&[]), SniStatus::Done(None));
        // No extension block at all, as TLS 1.0 clients may send.
        let body = hello_body(&[]);
        let fixed = 2 + 32 + 1 + 32 + 2 + 12 + 2;
        assert_eq!(feed_all(&record(&handshake(HANDSHAKE_CLIENT_HELLO, &body[..fixed]))), SniStatus::Done(None));
    }

    #[test]
    fn names_that_are_not_dns_names_are_malformed() {
        for name in ["198.51.100.10", "0x7f.1", "localhost", "exa_mple.com", "example.com.", "", "bücher.example", "a b.example.com"] {
            assert_eq!(status_with(&sni(name.as_bytes())), SniStatus::Malformed, "{name:?}");
        }
        assert_eq!(status_with(&sni(b"exam\xffple.com")), SniStatus::Malformed);
        assert_eq!(status_with(&sni(b"example.com\0.evil.net")), SniStatus::Malformed);
    }

    #[test]
    fn ambiguous_or_broken_server_name_extensions_are_malformed() {
        let entry = |name_type: u8, name: &[u8]| [&[name_type][..], &len16(name.len()), name].concat();
        let list = |entries: &[u8]| [&len16(entries.len())[..], entries].concat();
        let one = entry(NAME_TYPE_HOST_NAME, b"api.example.com");
        let ext = |data: &[u8]| extension(EXTENSION_SERVER_NAME, data);
        assert_eq!(status_with(&ext(&list(&one))), done("api.example.com"));

        let rows: Vec<(&str, Vec<u8>)> = vec![
            ("duplicate extension", [sni(b"api.example.com"), sni(b"evil.example.net")].concat()),
            ("two names in one list", ext(&list(&[one.clone(), entry(NAME_TYPE_HOST_NAME, b"evil.example.net")].concat()))),
            ("unknown name type", ext(&list(&entry(1, b"api.example.com")))),
            ("empty extension", ext(&[])),
            ("empty list", ext(&list(&[]))),
            ("list shorter than the extension", ext(&[&list(&one)[..], &[0]].concat())),
            ("list longer than the extension", ext(&[&len16(one.len() + 1)[..], &one].concat())),
            ("name longer than the list", ext(&list(&[&[NAME_TYPE_HOST_NAME][..], &len16(40), b"api.example.com"].concat()))),
            ("bytes after the name", ext(&list(&[&one[..], &[0]].concat()))),
        ];
        for (what, extensions) in rows {
            assert_eq!(status_with(&extensions), SniStatus::Malformed, "{what}");
        }
    }

    #[test]
    fn broken_hello_structure_is_malformed() {
        let good = hello_body(&sni(b"api.example.com"));
        let hello = |body: &[u8]| feed_all(&record(&handshake(HANDSHAKE_CLIENT_HELLO, body)));
        assert_eq!(hello(&good), done("api.example.com"));

        // Cutting the body anywhere, with every outer length adjusted to match, never yields a name.
        for cut in 0..good.len() {
            assert!(!matches!(hello(&good[..cut]), SniStatus::Done(Some(_)) | SniStatus::NeedMore | SniStatus::NotTls), "cut at {cut}");
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(hello(&trailing), SniStatus::Malformed, "bytes after the extension block");

        let session_id_len = 2 + 32;
        let mut long_session = good.clone();
        long_session.splice(session_id_len..=session_id_len, [33, 0]);
        assert_eq!(hello(&long_session), SniStatus::Malformed, "session id longer than 32 bytes");

        let suites_len = session_id_len + 1 + 32;
        let mut odd_suites = good.clone();
        odd_suites.splice(suites_len..suites_len + 2 + 12, [0, 11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        assert_eq!(hello(&odd_suites), SniStatus::Malformed, "odd cipher suite length");
        let mut no_suites = good.clone();
        no_suites.splice(suites_len..suites_len + 2 + 12, [0, 0]);
        assert_eq!(hello(&no_suites), SniStatus::Malformed, "no cipher suites");

        let compression_len = suites_len + 2 + 12;
        let mut no_compression = good.clone();
        no_compression.splice(compression_len..compression_len + 2, [0]);
        assert_eq!(hello(&no_compression), SniStatus::Malformed, "no compression methods");

        assert_eq!(feed_all(&record(&handshake(2, &good))), SniStatus::Malformed, "not a ClientHello");
        assert_eq!(feed_all(&record(&handshake(HANDSHAKE_CLIENT_HELLO, &[]))), SniStatus::Malformed, "empty body");
    }

    #[test]
    fn other_protocols_are_not_tls() {
        for stream in [
            &b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            b"SSH-2.0-OpenSSH_9.9\r\n",
            b"\0",
            b"\x17\x03\x03\x00\x10",
            b"\x15\x03\x03\x00\x02",
        ] {
            let mut parser = ClientHelloParser::new();
            assert_eq!(parser.feed(&stream[..1]), SniStatus::NotTls, "decided on the first byte: {stream:?}");
            assert_eq!(parser.feed(&stream[1..]), SniStatus::NotTls);
            assert_eq!(parser.buffered(), 0);
        }
        // A handshake record with a version outside 0x0301..=0x0304 (SSL 3.0, a future 3.5, a 2.x header).
        for version in [[0x03, 0x00], [0x03, 0x05], [0x02, 0x03], [0x04, 0x01]] {
            let mut stream = client_hello("api.example.com");
            stream[1..3].copy_from_slice(&version);
            let mut parser = ClientHelloParser::new();
            assert_eq!(parser.feed(&stream[..2]), SniStatus::NeedMore);
            assert_eq!(parser.feed(&stream[2..]), SniStatus::NotTls, "{version:02x?}");
        }
        assert_eq!(ClientHelloParser::new().feed(&[]), SniStatus::NeedMore);
    }

    #[test]
    fn record_layer_violations_are_malformed() {
        let message = handshake(HANDSHAKE_CLIENT_HELLO, &hello_body(&sni(b"api.example.com")));
        let first = record(&message[..10]);

        assert_eq!(feed_all(&[CONTENT_TYPE_HANDSHAKE, 3, 1, 0, 0]), SniStatus::Malformed, "empty record");
        assert_eq!(feed_all(&[CONTENT_TYPE_HANDSHAKE, 3, 1, 0x40, 0x01]), SniStatus::Malformed, "record longer than 2^14");
        assert_eq!(feed_all(&[&first[..], &[CONTENT_TYPE_HANDSHAKE, 3, 3, 0, 0]].concat()), SniStatus::Malformed, "empty continuation");
        // Anything but handshake data between the fragments of a ClientHello is a protocol error, not "not TLS".
        assert_eq!(feed_all(&[&first[..], &[0x14, 3, 3, 0, 1, 1]].concat()), SniStatus::Malformed, "interleaved record");
        assert_eq!(feed_all(&[&first[..], &[CONTENT_TYPE_HANDSHAKE, 2, 0]].concat()), SniStatus::Malformed, "continuation version");

        let within = fragmented(&message, &[1; MAX_RECORDS - 1]);
        assert_eq!(feed_all(&within), done("api.example.com"), "exactly MAX_RECORDS records");
        let mut parser = ClientHelloParser::new();
        assert_eq!(parser.feed(&fragmented(&message, &[1; MAX_RECORDS])), SniStatus::Malformed, "one record too many");
        assert_eq!(parser.consumed(), MAX_RECORDS * (RECORD_HEADER_LEN + 1), "refused before the extra record is read");
    }

    #[test]
    fn the_size_bound_is_exact() {
        let padding = |len: usize| extension(0x0015, &vec![0; len]);
        let base = hello_body(&[&sni(b"api.example.com")[..], &padding(0)].concat()).len();
        let largest = hello_body(&[&sni(b"api.example.com")[..], &padding(MAX_CLIENT_HELLO_LEN - base)].concat());
        assert_eq!(largest.len(), MAX_CLIENT_HELLO_LEN);
        let message = handshake(HANDSHAKE_CLIENT_HELLO, &largest);

        // The largest hello, in as many records as allowed, consumes exactly the documented bound.
        let stream = fragmented(&message, &[1; MAX_RECORDS - 1]);
        assert_eq!(stream.len(), MAX_BUFFERED_LEN);
        let mut parser = ClientHelloParser::new();
        assert_eq!(parser.feed(&stream), done("api.example.com"));
        assert_eq!((parser.consumed(), parser.buffered()), (MAX_BUFFERED_LEN, MAX_CLIENT_HELLO_LEN + HANDSHAKE_HEADER_LEN));

        // One byte more is refused as soon as its length is declared, before the body is buffered.
        let too_large = hello_body(&[&sni(b"api.example.com")[..], &padding(MAX_CLIENT_HELLO_LEN - base + 1)].concat());
        let message = handshake(HANDSHAKE_CLIENT_HELLO, &too_large);
        let mut parser = ClientHelloParser::new();
        assert_eq!(parser.feed(&fragmented(&message, &[4])[..RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN]), SniStatus::Malformed);
        assert_eq!(parser.buffered(), HANDSHAKE_HEADER_LEN);
        assert_eq!(
            feed_all(&[&[CONTENT_TYPE_HANDSHAKE, 3, 1, 0, 4][..], &[HANDSHAKE_CLIENT_HELLO, 0xff, 0xff, 0xff]].concat()),
            SniStatus::Malformed
        );
    }

    /// Feeds `stream` in the given chunk sizes and checks the invariants that hold for any input.
    fn feed_chunked(stream: &[u8], chunks: &[usize]) -> Result<SniStatus, TestCaseError> {
        let mut parser = ClientHelloParser::new();
        let mut status = SniStatus::NeedMore;
        let mut rest = stream;
        let mut sizes = chunks.iter().copied().chain(std::iter::repeat(usize::MAX));
        while !rest.is_empty() {
            let size = sizes.next().unwrap_or(usize::MAX).clamp(1, rest.len());
            let (chunk, tail) = rest.split_at(size);
            let terminal = status != SniStatus::NeedMore;
            let next = parser.feed(chunk);
            prop_assert!(!terminal || next == status, "a terminal status never changes");
            status = next;
            rest = tail;
            prop_assert!(parser.consumed() <= MAX_BUFFERED_LEN);
            prop_assert!(parser.buffered() <= MAX_CLIENT_HELLO_LEN + HANDSHAKE_HEADER_LEN);
            prop_assert!(parser.hello.capacity() <= 2 * (MAX_CLIENT_HELLO_LEN + HANDSHAKE_HEADER_LEN));
            if let SniStatus::Done(Some(name)) = &status {
                let reparsed = DnsName::parse(name.as_str());
                prop_assert_eq!(reparsed.as_ref(), Ok(name));
            }
        }
        Ok(status)
    }

    fn chunk_sizes() -> impl Strategy<Value = Vec<usize>> {
        prop::collection::vec(1usize..700, 0..12)
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_and_stay_bounded(stream in prop::collection::vec(any::<u8>(), 0..4096), chunks in chunk_sizes()) {
            let chunked = feed_chunked(&stream, &chunks)?;
            prop_assert_eq!(chunked, feed_all(&stream), "the answer does not depend on segmentation");
        }

        /// Streams that start like TLS reach the reassembly and extension code that random bytes rarely do.
        #[test]
        fn arbitrary_handshake_payload_never_panics(
            payload in prop::collection::vec(any::<u8>(), 0..3000),
            records in prop::collection::vec(1usize..600, 0..20),
            chunks in chunk_sizes(),
        ) {
            let mut message = vec![HANDSHAKE_CLIENT_HELLO, 0, (payload.len() >> 8) as u8, payload.len() as u8];
            message.extend_from_slice(&payload);
            let stream = fragmented(&message, &records);
            let chunked = feed_chunked(&stream, &chunks)?;
            prop_assert_eq!(chunked, feed_all(&stream));
        }

        #[test]
        fn mutated_hellos_never_panic(
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..5),
            records in prop::collection::vec(1usize..600, 0..6),
            chunks in chunk_sizes(),
        ) {
            let mut message = handshake(HANDSHAKE_CLIENT_HELLO, &hello_body(&sni(b"api.example.com")));
            for (at, byte) in edits {
                let at = at.index(message.len());
                message[at] = byte;
            }
            let stream = fragmented(&message, &records);
            let chunked = feed_chunked(&stream, &chunks)?;
            prop_assert_eq!(chunked, feed_all(&stream));
        }

        #[test]
        fn any_valid_name_survives_any_fragmentation(
            name in "[a-z0-9]{1,20}(-[a-z0-9]{1,8})?(\\.[a-z0-9]{1,12}){0,3}\\.[a-z][a-z0-9]{1,10}",
            records in prop::collection::vec(1usize..600, 0..(MAX_RECORDS - 1)),
            chunks in chunk_sizes(),
        ) {
            let message = handshake(HANDSHAKE_CLIENT_HELLO, &hello_body(&sni(name.as_bytes())));
            let stream = fragmented(&message, &records);
            prop_assert_eq!(feed_chunked(&stream, &chunks)?, done(&name));
        }
    }
}
