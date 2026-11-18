//! A bounds-checked cursor over guest-supplied bytes.
//!
//! Every accessor returns `None` instead of reading past the end, and nothing here allocates: a length field
//! declared by the guest can only ever select bytes that were actually received.

#[derive(Debug)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub(crate) fn remaining(&self) -> usize {
        self.rest.len()
    }

    pub(crate) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(len)?;
        self.rest = tail;
        Some(head)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        <[u8; 2]>::try_from(self.take(2)?).ok().map(u16::from_be_bytes)
    }

    /// A field prefixed with a one-byte length.
    pub(crate) fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    /// A field prefixed with a two-byte length.
    pub(crate) fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_at_the_end() {
        let mut reader = Reader::new(&[1, 0, 2, 2, 0xaa, 0xbb, 0, 1, 0xcc]);
        assert_eq!(reader.u8(), Some(1));
        assert_eq!(reader.u16(), Some(2));
        assert_eq!(reader.vec8(), Some(&[0xaa, 0xbb][..]));
        assert_eq!(reader.vec16(), Some(&[0xcc][..]));
        assert!(reader.is_empty() && reader.remaining() == 0);
        assert_eq!((reader.u8(), reader.u16(), reader.take(1), reader.vec8(), reader.vec16()), (None, None, None, None, None));
        assert_eq!(reader.take(0), Some(&[][..]));
    }

    #[test]
    fn a_declared_length_beyond_the_input_reads_nothing() {
        let mut reader = Reader::new(&[5, 1, 2]);
        assert_eq!(reader.vec8(), None);
        let mut reader = Reader::new(&[0xff, 0xff, 1]);
        assert_eq!(reader.vec16(), None);
        let mut reader = Reader::new(&[7]);
        assert_eq!(reader.u16(), None);
    }
}
