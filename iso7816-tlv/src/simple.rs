//! This module provides tools and utilities for handling SIMPLE-TLV data as
//! defined in [ISO7816-4][iso7816-4].
//!
//!
//!
//!
//! [iso7816-4]: https://www.iso.org/standard/54550.html
//!
use std::convert::TryFrom;
use untrusted::{Input, Reader};

use crate::{Result, TlvError};

/// Tag for SIMPLE-TLV data as defined in [ISO7816-4].
/// > The tag field consists of a single byte encoding a tag number from 1 to 254.
/// > The values '00' and 'FF' are invalid for tag fields.
///
/// Tags can be generated using the [`TryFrom`][TryFrom] trait
/// from u8 or hex [str][str].
///
/// [TryFrom]: https://doc.rust-lang.org/std/convert/trait.TryFrom.html
/// [str]:https://doc.rust-lang.org/std/str/
///
/// # Example
/// ```rust
/// use std::convert::TryFrom;
/// use iso7816_tlv::simple::Tag;
/// # use iso7816_tlv::TlvError;
/// # fn main() -> () {
///
/// assert!(Tag::try_from("80").is_ok());
/// assert!(Tag::try_from(8u8).is_ok());
/// assert!(Tag::try_from(0x80).is_ok());
/// assert!(Tag::try_from(127).is_ok());
///
/// assert!(Tag::try_from("er").is_err());
/// assert!(Tag::try_from("00").is_err());
/// assert!(Tag::try_from("ff").is_err());
///
/// assert_eq!(127_u8, Tag::try_from(127_u8).unwrap().into());
/// # }
/// #
/// ```
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Tag(u8);

/// Value for SIMPLE-TLV data as defined in [ISO7816].
/// > the value field consists of N consecutive bytes.
/// > N may be zero. In this case there is no value field.
/// In this case Value.0 is an empty vector
pub type Value = Vec<u8>;

/// SIMPLE-TLV data object representation.
/// > Each SIMPLE-TLV data object shall consist of two or three consecutive fields:
/// > a mandatory tag field, a mandatory length field and a conditional value field
#[derive(PartialEq, Debug, Clone)]
pub struct Tlv {
  tag: Tag,
  value: Value,
}

impl Into<u8> for Tag {
  fn into(self) -> u8 {
    self.0
  }
}

impl TryFrom<u8> for Tag {
  type Error = TlvError;
  fn try_from(v: u8) -> Result<Self> {
    match v {
      0x00 | 0xFF => Err(TlvError::InvalidInput),
      _ => Ok(Self(v)),
    }
  }
}

impl TryFrom<&str> for Tag {
  type Error = TlvError;
  fn try_from(v: &str) -> Result<Self> {
    let x = u8::from_str_radix(v, 16)?;
    Self::try_from(x)
  }
}

impl Tlv {
  /// Create a SIMPLE-TLV data object from valid tag and value.
  /// A value has a maximum size of 65_535 bytes.
  /// Otherwise this fonction fails with TlvError::InvalidLength.
  pub fn new(tag: Tag, value: Value) -> Result<Self> {
    if value.len() > 65_536 {
      Err(TlvError::InvalidLength)
    } else {
      Ok(Self { tag, value })
    }
  }

  /// Get SIMPLE-TLV  tag.
  pub fn tag(&self) -> Tag {
    self.tag
  }

  /// Get SIMPLE-TLV value length
  pub fn length(&self) -> usize {
    self.value.len()
  }

  /// Get SIMPLE-TLV value
  pub fn value(&self) -> &[u8] {
    self.value.as_slice()
  }

  /// serializes self into a byte vector.
  #[allow(clippy::cast_possible_truncation)]
  pub fn to_vec(&self) -> Vec<u8> {
    let mut ret = Vec::new();
    ret.push(self.tag.0);
    let len = self.value.len();
    if len < 255 {
      ret.push(len as u8);
    } else {
      ret.push(0xFF);
      ret.push((len >> 8) as u8);
      ret.push(len as u8);
    }
    ret.extend(&self.value);
    ret
  }

  fn read_len(r: &mut Reader) -> Result<usize> {
    let mut ret: usize = 0;
    let x = r.read_byte()?;
    if x == 0xFF {
      for _ in 0..2 {
        let x = r.read_byte()?;
        ret = ret << 8 | usize::from(x);
      }
    } else {
      ret = usize::from(x);
    }
    Ok(ret)
  }

  fn read(r: &mut Reader) -> Result<Self> {
    let tag = Tag::try_from(r.read_byte()?)?;
    let len = Self::read_len(r)?;
    let content = r.read_bytes(len)?;

    Ok(Self {
      tag,
      value: content.as_slice_less_safe().to_vec(),
    })
  }

  /// Parses a byte array into a SIMPLE-TLV structure.
  /// This also returns the unprocessed data.
  pub fn parse(input: &[u8]) -> (Result<Self>, &[u8]) {
    let mut r = Reader::new(Input::from(input));
    (
      Self::read(&mut r),
      r.read_bytes_to_end().as_slice_less_safe(),
    )
  }

  /// Parses a byte array into a SIMPLE-TLV structure.
  /// Input must exactly match a SIMPLE-TLV object.
  pub fn from_bytes(input: &[u8]) -> Result<Self> {
    let (r, n) = Self::parse(input);
    if n.is_empty() {
      r
    } else {
      Err(TlvError::InvalidInput)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::Rng;
  use std::convert::TryFrom;

  #[test]
  fn tag_import() {
    assert!(Tag::try_from("80").is_ok());
    assert!(Tag::try_from(8_u8).is_ok());
    assert_eq!(0x8_u8, Tag::try_from(8_u8).unwrap().into());

    assert!(Tag::try_from(0x80).is_ok());
    assert_eq!(0x80_u8, Tag::try_from(0x80_u8).unwrap().into());

    assert!(Tag::try_from(127).is_ok());
    assert_eq!(127_u8, Tag::try_from(127_u8).unwrap().into());

    assert!(Tag::try_from("er").is_err());
    assert!(Tag::try_from("00").is_err());
    assert!(Tag::try_from("ff").is_err());
  }

  #[test]
  fn parse_1() {
    let in_data = [
      0x84_u8, 0x01, 0x2C, 0x97, 0x00, 0x84, 0x01, 0x24, 0x9E, 0x01, 0x42,
    ];

    let (r, in_data) = Tlv::parse(&in_data);
    assert_eq!(8, in_data.len());
    assert!(r.is_ok());

    let t = r.unwrap();
    assert_eq!(0x84_u8, t.tag.into());
    assert_eq!(1, t.length());
    assert_eq!(&[0x2C], t.value());

    let (r, in_data) = Tlv::parse(&in_data);
    assert_eq!(6, in_data.len());
    assert!(r.is_ok());

    let t = r.unwrap();
    assert_eq!(0x97_u8, t.tag.into());
    assert_eq!(0, t.length());

    let (r, in_data) = Tlv::parse(&in_data);
    assert_eq!(3, in_data.len());
    assert!(r.is_ok());

    let t = r.unwrap();
    assert_eq!(0x84_u8, t.tag.into());
    assert_eq!(1, t.length());
    assert_eq!(&[0x24], t.value());

    let (r, in_data) = Tlv::parse(&in_data);
    assert_eq!(0, in_data.len());
    assert!(r.is_ok());

    let t = r.unwrap();
    assert_eq!(0x9E_u8, t.tag.into());
    assert_eq!(1, t.length());
    assert_eq!(&[0x42], t.value());
  }

  #[test]
  fn serialize_parse() -> Result<()> {
    let mut rng = rand::thread_rng();
    for r in 1_u8..0xFF {
      let v_len = rng.gen_range(1, 65537);
      let v: Value = (0..v_len).map(|_| rng.gen::<u8>()).collect();
      let tlv = Tlv::new(Tag::try_from(r)?, v.clone())?;
      let ser = tlv.to_vec();
      let tlv_2 = Tlv::from_bytes(&*ser)?;
      assert_eq!(tlv, tlv_2);

      assert_eq!(r, tlv.tag().into());
      assert_eq!(v, tlv.value());
    }
    Ok(())
  }
}
