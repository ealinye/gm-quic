use std::{convert::TryFrom, fmt};

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
// It would be neat if we could express to Rust that the top two bits are available for use as enum
// discriminants
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(pub(crate) u64);

impl VarInt {
    /// The largest representable value
    pub const MAX: Self = Self((1 << 62) - 1);
    /// The largest encoded value length
    pub const MAX_SIZE: usize = 8;

    /// Construct a `VarInt` infallibly
    pub const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Succeeds if `x` < 2^62
    pub fn from_u64(x: u64) -> Result<Self, err::Error> {
        if x < (1 << 62) {
            Ok(Self(x))
        } else {
            Err(err::Error::Overflow(x))
        }
    }

    /// Create a VarInt without ensuring it's in range
    ///
    /// # Safety
    ///
    /// `x` must be less than 2^62.
    pub const unsafe fn from_u64_unchecked(x: u64) -> Self {
        Self(x)
    }

    /// Extract the integer value
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Compute the number of bytes needed to encode this value
    pub fn size(self) -> usize {
        let x = self.0;
        if x < (1 << 6) {
            1
        } else if x < (1 << 14) {
            2
        } else if x < (1 << 30) {
            4
        } else if x < (1 << 62) {
            8
        } else {
            unreachable!("malformed VarInt");
        }
    }
}

impl From<VarInt> for u64 {
    fn from(x: VarInt) -> Self {
        x.0
    }
}

impl From<u8> for VarInt {
    fn from(x: u8) -> Self {
        Self(x.into())
    }
}

impl From<u16> for VarInt {
    fn from(x: u16) -> Self {
        Self(x.into())
    }
}

impl From<u32> for VarInt {
    fn from(x: u32) -> Self {
        Self(x.into())
    }
}

impl TryFrom<u64> for VarInt {
    type Error = err::Error;

    /// Succeeds if `x` < 2^62
    fn try_from(x: u64) -> Result<Self, err::Error> {
        Self::from_u64(x)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = err::Error;

    /// Succeeds if `x` < 2^62
    fn try_from(x: usize) -> Result<Self, err::Error> {
        Self::try_from(x as u64)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub mod err {
    use std::fmt::Debug;
    use thiserror::Error;

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
    pub enum Error {
        /// Error returned when constructing a `VarInt` from a value >= 2^62
        #[error("value({0}) too large for varint encoding")]
        Overflow(u64),
        #[error("parse varint error")]
        ParseError,
    }

    impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
        fn from(_e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
            dbg!("nom parse varint error occured: {}", _e);
            Self::ParseError
        }
    }
}

pub mod ext {
    use super::{err, VarInt};
    use bytes::{Buf, BufMut};
    use nom::{bits::complete::take, combinator::flat_map, error::Error, IResult};

    /// Parse a variable-length integer, can be used like `be_u8/be_u16/be_u32` etc.
    /// ## Example
    /// ```
    /// use qbase::varint::ext::be_varint;
    ///
    /// let input = &[0b01000000, 0x01][..];
    /// let result = be_varint(input);
    /// assert_eq!(result, Ok((&[][..], 1u32.into())));
    /// ```
    pub fn be_varint(input: &[u8]) -> IResult<&[u8], VarInt> {
        flat_map(take(2usize), |prefix: u8| {
            take::<&[u8], u64, usize, Error<(&[u8], usize)>>((8 << prefix) - 2)
        })((input, 0))
        .map_err(|err| err.map(|e| Error::new(e.input.0, e.code)))
        .map(|((buf, _), value)| (buf, VarInt(value)))
    }

    pub trait BufExt {
        fn get_varint(&mut self) -> Result<VarInt, err::Error>;
    }

    pub trait BufMutExt {
        fn put_varint(&mut self, value: &VarInt);
    }

    impl<T: Buf> BufExt for T {
        fn get_varint(&mut self) -> Result<VarInt, err::Error> {
            let remained = self.remaining();
            let (remain, value) = be_varint(self.chunk())?;
            self.advance(remained - remain.len());
            Ok(value)
        }
    }

    // 所有的BufMut都可以调用put_varint来写入VarInt了
    impl<T: BufMut> BufMutExt for T {
        fn put_varint(&mut self, value: &VarInt) {
            let x = value.0;
            if x < 2u64.pow(6) {
                self.put_u8(x as u8);
            } else if x < 2u64.pow(14) {
                self.put_u16(0b01 << 14 | x as u16);
            } else if x < 2u64.pow(30) {
                self.put_u32(0b10 << 30 | x as u32);
            } else if x < 2u64.pow(62) {
                self.put_u64(0b11 << 62 | x);
            } else {
                unreachable!("malformed VarInt")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        err,
        ext::{BufExt, BufMutExt},
        VarInt,
    };
    use bytes::BufMut;

    #[test]
    fn reading_varint() {
        {
            let mut buf = &[0b00000001u8, 0x01][..];
            let r = buf.get_varint();
            assert_eq!(r, Ok(VarInt(1)));
            assert_eq!(buf, &[0x01][..]);
        }
        {
            let mut buf = &[0b01000000u8, 0x06u8][..];
            let r = buf.get_varint();
            assert_eq!(r, Ok(VarInt(6)));
            assert_eq!(buf, &[][..]);
        }
        {
            let mut buf = &[0b10000000u8, 1, 1, 1][..];
            let r = buf.get_varint();
            assert_eq!(r, Ok(VarInt(0x010101)));
            assert_eq!(buf, &[][..]);
        }
        {
            let mut buf = &[0b11000000u8, 1, 1, 1, 1, 1, 1, 1][..];
            let r = buf.get_varint();
            assert_eq!(r, Ok(VarInt(0x01010101010101)));
            assert_eq!(buf, &[][..]);
        }
        {
            let mut buf = &[0b11000000u8, 0x06u8][..];
            let r = buf.get_varint();
            assert_eq!(r, Err(err::Error::ParseError));
        }
    }

    #[test]
    fn write_varint() {
        let val = VarInt::from(255u32);
        let mut buf = vec![];
        buf.put_varint(&val);
        buf.put_u16(65535);
        assert_eq!(buf, vec![64, 255, 255, 255]);
    }
}