use std::fmt;
use untrusted::{Input, Reader};

use super::{Tag, Value};
use crate::{Result, TlvError};

/// BER-TLV structure, following ISO/IEC 7816-4.
/// > # BER-TLV data objects
/// > Each BER-TLV data object consists of two or three consecutive fields
/// > (see the basic encoding rules of ASN.1 in ISO/IEC 8825-1):
/// > a mandatory tag field, a mandatory length field and a conditional value field.
/// > - The tag field consists of one or more consecutive bytes.
/// >   It indicates a class and an encoding and it encodes a tag number.
/// >   The value '00' is invalid for the first byte of tag fields (see ISO/IEC 8825-1).
/// > - The length field consists of one or more consecutive bytes.
/// >   It encodes a length, i.e., a number denoted N.
/// > - If N is zero, there is no value field, i.e., the data object is empty.
/// >   Otherwise (N > 0), the value field consists of N consecutive bytes.
#[derive(PartialEq, Debug, Clone)]
pub struct Tlv {
  tag: Tag,
  value: Value,
}

impl Tlv {
  /// Create a BER-TLV data object from valid tag and value
  /// Fails with TlvError::Inconsistant
  /// if the tag indicates a contructed value (resp. primitive) and the
  /// value is primitive (resp. contructed).
  pub fn new(tag: Tag, value: Value) -> Result<Self> {
    match value {
      Value::Constructed(_) => {
        if !tag.is_constructed() {
          return Err(TlvError::Inconsistant);
        }
      }
      _ => {
        if tag.is_constructed() {
          return Err(TlvError::Inconsistant);
        }
      }
    }
    Ok(Self { tag, value })
  }

  fn len_length(l: usize) -> usize {
    match l {
      0..=127 => 1,
      128..=255 => 2,
      256..=65_535 => 3,
      65_536..=16_777_215 => 4,
      _ => 5,
    }
  }

  #[allow(clippy::cast_possible_truncation)]
  fn inner_len_to_vec(&self) -> Vec<u8> {
    let l = self.value.len_as_bytes();
    if l < 0x7f {
      vec![l as u8]
    } else {
      let mut ret: Vec<u8> = l
        .to_be_bytes()
        .iter()
        .skip_while(|&x| *x == 0)
        .cloned()
        .collect();
      ret.insert(0, 0x80 | ret.len() as u8);
      ret
    }
  }

  pub(crate) fn len(&self) -> usize {
    let inner_len = self.value.len_as_bytes();
    self.tag.len_as_bytes() + Self::len_length(inner_len) + inner_len
  }

  /// serializes self into a byte vector.
  pub fn to_vec(&self) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    ret.extend(self.tag.to_bytes().iter());
    ret.append(&mut self.inner_len_to_vec());
    match &self.value {
      Value::Primitive(v) => ret.extend(v.iter()),
      Value::Constructed(tlv) => {
        for t in tlv {
          ret.append(&mut t.to_vec());
        }
      }
    };
    ret
  }

  fn read_len(r: &mut Reader) -> Result<usize> {
    let mut ret: usize = 0;
    let x = r.read_byte()?;
    if x & 0x80 == 0 {
      ret = x as usize;
    } else {
      let n_bytes = x as usize & 0x7f;
      if n_bytes > 4 {
        return Err(TlvError::InvalidLength);
      }
      for _ in 0..n_bytes {
        let x = r.read_byte()?;
        ret = ret << 8 | x as usize;
      }
    }
    Ok(ret)
  }

  fn read(r: &mut Reader) -> Result<Self> {
    let tag = Tag::read(r)?;
    let len = Self::read_len(r)?;

    let ret = if tag.is_constructed() {
      let mut val = Value::Constructed(vec![]);
      while val.len_as_bytes() < len {
        let tlv = Self::read(r)?;
        val.push(tlv)?;
      }
      Self::new(tag, val)?
    } else {
      let content = r.read_bytes(len)?;
      Self::new(tag, Value::Primitive(content.as_slice_less_safe().to_vec()))?
    };
    if ret.value.len_as_bytes() == len {
      Ok(ret)
    } else {
      Err(TlvError::Inconsistant)
    }
  }

  /// Parses a byte array into a BER-TLV structure.
  /// This also returns the unprocessed data.
  pub fn parse(input: &[u8]) -> (Result<Self>, &[u8]) {
    let mut r = Reader::new(Input::from(input));
    (
      Self::read(&mut r),
      r.read_bytes_to_end().as_slice_less_safe(),
    )
  }

  /// Parses a byte array into a BER-TLV structure.
  /// Input must exactly match a BER-TLV object.
  pub fn from_bytes(input: &[u8]) -> Result<Self> {
    let (r, n) = Self::parse(input);
    if n.is_empty() {
      r      
    } else {
      Err(TlvError::InvalidInput)
    }
  }

  /// Finds first occurence of a TLV object with given tag in self.
  pub fn find(&self, tag: &Tag) -> Option<&Self> {
    match &self.value {
      Value::Primitive(_) => {
        if self.tag == *tag {
          Some(&self)
        } else {
          None
        }
      }
      Value::Constructed(e) => {
        for x in e {
          match x.find(tag) {
            None => (),
            Some(e) => return Some(e),
          }
        }
        None
      }
    }
  }

  /// find all occurences of TLV objects with given given tag in self.
  /// Note that searching ContextSpecific class tag (0x80 for instance) will return
  /// a vector of possibly unrelated tlv data.
  pub fn find_all(&self, tag: &Tag) -> Vec<&Self> {
    let mut ret: Vec<&Self> = Vec::new();
    match &self.value {
      Value::Primitive(_) => {
        if self.tag == *tag {
          ret.push(self);
        }
      }
      Value::Constructed(e) => {
        for x in e {
          let v = x.find(tag);
          ret.extend(v);
        }
      }
    }
    ret
  }
}

impl fmt::Display for Tlv {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}, ", self.tag)?;
    write!(f, "len={}, ", self.value.len_as_bytes())?;
    write!(f, "value:")?;

    match &self.value {
      Value::Primitive(e) => {
        for x in e {
          write!(f, "{:02X}", x)?
        }
      }
      Value::Constructed(e) => {
        let padding_len = if let Some(width) = f.width() {
          width + 4
        } else {
          4
        };
        for x in e {
          writeln!(f)?;
          write!(
            f,
            "{}{:>padding$}",
            " ".repeat(padding_len),
            x,
            padding = padding_len
          )?;
        }
      }
    };
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::convert::TryFrom;

  #[test]
  fn tlv_to_from_vec_primitive() {
    let tlv = Tlv::new(Tag::try_from(1_u32).unwrap(), Value::Primitive(vec![0])).unwrap();
    assert_eq!(vec![1, 1, 0], tlv.to_vec());
    {
      let mut data = vec![0_u8; 255];
      let tlv = Tlv::new(
        Tag::try_from(1_u32).unwrap(),
        Value::Primitive(data.clone()),
      )
      .unwrap();
      let mut expected = vec![1_u8, 0x81, 0xFF];
      expected.append(&mut data);
      assert_eq!(expected, tlv.to_vec());

      let mut r = Reader::new(Input::from(&expected));
      let read = Tlv::read(&mut r).unwrap();
      assert_eq!(tlv, read);
    }
    {
      let mut data = vec![0_u8; 256];
      let tlv = Tlv::new(
        Tag::try_from(1_u32).unwrap(),
        Value::Primitive(data.clone()),
      )
      .unwrap();
      let mut expected = vec![1_u8, 0x82, 0x01, 0x00];
      expected.append(&mut data);
      assert_eq!(expected, tlv.to_vec());

      let mut r = Reader::new(Input::from(&expected));
      let read = Tlv::read(&mut r).unwrap();
      assert_eq!(tlv, read);
    }
    {
      let mut data = vec![0_u8; 65_536];
      let tlv = Tlv::new(
        Tag::try_from(1_u32).unwrap(),
        Value::Primitive(data.clone()),
      )
      .unwrap();
      let mut expected = vec![1_u8, 0x83, 0x01, 0x00, 0x00];
      expected.append(&mut data);
      assert_eq!(expected, tlv.to_vec());

      let mut r = Reader::new(Input::from(&expected));
      let read = Tlv::read(&mut r).unwrap();
      assert_eq!(tlv, read);
    }
  }

  #[test]
  #[allow(clippy::cast_possible_truncation)]
  fn tlv_to_from_vec_constructed() {
    let base = Tlv::new(Tag::try_from(1_u32).unwrap(), Value::Primitive(vec![0])).unwrap();
    let mut construct = Value::Constructed(vec![base.clone(), base.clone(), base.clone()]);

    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), construct.clone()).unwrap();
    let mut expected = vec![0x7f_u8, 0x22, 9];
    expected.append(&mut base.to_vec());
    expected.append(&mut base.to_vec());
    expected.append(&mut base.to_vec());
    assert_eq!(expected, tlv.to_vec());

    let mut r = Reader::new(Input::from(&expected));
    let read = Tlv::read(&mut r).unwrap();
    assert_eq!(tlv, read);

    construct.push(base.clone()).unwrap();
    expected[2] += base.len() as u8;
    expected.append(&mut base.to_vec());
    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), construct).unwrap();
    assert_eq!(expected, tlv.to_vec());

    let mut r = Reader::new(Input::from(&expected));
    let read = Tlv::read(&mut r).unwrap();
    assert_eq!(tlv, read);

    println!("{}", tlv)
  }

  #[test]
  fn parse() {
    let primitive_bytes = vec![1, 1, 0];
    let more_bytes = vec![1_u8; 10];
    let mut input = vec![0x7f_u8, 0x22, 9];
    input.extend(&primitive_bytes);
    input.extend(&primitive_bytes);
    input.extend(&primitive_bytes);
    let expected = input.clone();
    input.extend(&more_bytes);
    let (tlv, left) = Tlv::parse(&input);
    assert_eq!(expected, tlv.unwrap().to_vec());
    assert_eq!(more_bytes, left);
  }

  #[test]
  fn display() {
    let base = Tlv::new(Tag::try_from(0x80_u32).unwrap(), Value::Primitive(vec![0])).unwrap();
    let construct = Value::Constructed(vec![base.clone(), base.clone()]);
    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), construct.clone()).unwrap();

    let mut construct2 = construct.clone();
    construct2.push(tlv).unwrap();
    construct2.push(base).unwrap();
    let t = Tag::try_from("3F32").unwrap();
    let tlv = Tlv::new(t, construct2).unwrap();
    println!("{}", tlv)
  }

  #[test]
  fn find() {
    let base = Tlv::new(Tag::try_from(0x80_u32).unwrap(), Value::Primitive(vec![0])).unwrap();
    let t = base.clone();

    // shall return self
    assert_eq!(Some(&t), t.find(&Tag::try_from(0x80_u32).unwrap()));
    assert!(t.find(&Tag::try_from(0x81_u32).unwrap()).is_none());

    let construct = Value::Constructed(vec![t, base.clone()]);
    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), construct.clone()).unwrap();
    assert_eq!(None, tlv.find(&Tag::try_from(0x81_u32).unwrap()));
    let found = tlv.find(&Tag::try_from(0x80_u32).unwrap());
    assert!(found.is_some());
    assert_eq!(base.clone(), *found.unwrap());
  }

  #[test]
  fn find_all() {
    let base = Tlv::new(Tag::try_from(0x80_u32).unwrap(), Value::Primitive(vec![0])).unwrap();
    let t = base.clone();

    // shall return self
    assert_eq!(1, t.find_all(&Tag::try_from(0x80_u32).unwrap()).len());
    assert_eq!(0, t.find_all(&Tag::try_from(0x81_u32).unwrap()).len());

    let construct = Value::Constructed(vec![t, base.clone()]);
    let tlv = Tlv::new(Tag::try_from("7f22").unwrap(), construct.clone()).unwrap();
    assert_eq!(0, tlv.find_all(&Tag::try_from(0x81_u32).unwrap()).len());
    assert_eq!(2, tlv.find_all(&Tag::try_from(0x80_u32).unwrap()).len());
  }

}
