use super::Tlv;
use crate::error::TlvError;
use crate::Result;

/// Value definition of BER-TLV data
#[derive(PartialEq, Debug, Clone)]
pub enum Value {
  /// constructed data object, i.e., the value is encoded in BER-TLV
  Constructed(Vec<Tlv>),
  /// primitive data object, i.e., the value is not encoded in BER-TLV
  /// (may be empty)
  Primitive(Vec<u8>),
}

impl Value {
  /// Wether the value is constructed or not
  pub fn is_constructed(&self) -> bool {
    match self {
      Value::Constructed(_) => true,
      _ => false,
    }
  }

  /// Get value length once serialized into BER-TLV data
  pub fn len_as_bytes(&self) -> usize {
    match &self {
      Value::Primitive(v) => v.len(),
      Value::Constructed(tlv) => tlv.iter().fold(0, |sum, x| sum + x.len()),
    }
  }

  /// Append a BER-TLV data object.
  /// Fails with TlvError::Inconsistant on primitive or empty values.
  pub fn push(&mut self, tlv: Tlv) -> Result<()> {
    match self {
      Value::Constructed(t) => {
        t.push(tlv);
        Ok(())
      }
      _ => Err(TlvError::Inconsistant),
    }
  }
}
