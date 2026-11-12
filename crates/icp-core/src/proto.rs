//! A minimal protobuf wire codec.
//!
//! Apple's CloudKit messages are protobuf, but the schema (CloudKitDaemon) is not
//! published, so the fields are written by hand here rather than generated. That is
//! deliberate: the field numbers are the pins, and they are all named.

use crate::error::{Error, Result};

pub const WT_VARINT: u8 = 0;
pub const WT_I64: u8 = 1;
pub const WT_LEN: u8 = 2;
pub const WT_I32: u8 = 5;

/// Encode a varint.
pub fn encode_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// Encode a signed value the way protobuf's `int64` does: negative numbers go out as
/// their two's-complement bit pattern, ten bytes long.
pub fn encode_varint_i64(v: i64) -> Vec<u8> {
    encode_varint(v as u64)
}

/// A protobuf message under construction. Fields are appended in call order, so the
/// caller controls the order on the wire (Apple's own writer emits them in ascending
/// field number, and some of these blobs are signed).
#[derive(Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    fn tag(&mut self, field: u32, wire: u8) {
        self.buf
            .extend_from_slice(&encode_varint(((field as u64) << 3) | wire as u64));
    }

    pub fn uint64(&mut self, field: u32, value: Option<u64>) -> &mut Self {
        if let Some(v) = value {
            self.tag(field, WT_VARINT);
            self.buf.extend_from_slice(&encode_varint(v));
        }
        self
    }

    pub fn int64(&mut self, field: u32, value: Option<i64>) -> &mut Self {
        if let Some(v) = value {
            self.tag(field, WT_VARINT);
            self.buf.extend_from_slice(&encode_varint_i64(v));
        }
        self
    }

    pub fn bool(&mut self, field: u32, value: Option<bool>) -> &mut Self {
        if let Some(v) = value {
            self.tag(field, WT_VARINT);
            self.buf
                .extend_from_slice(&encode_varint(if v { 1 } else { 0 }));
        }
        self
    }

    pub fn bytes(&mut self, field: u32, value: Option<&[u8]>) -> &mut Self {
        if let Some(v) = value {
            self.tag(field, WT_LEN);
            self.buf.extend_from_slice(&encode_varint(v.len() as u64));
            self.buf.extend_from_slice(v);
        }
        self
    }

    pub fn string(&mut self, field: u32, value: Option<&str>) -> &mut Self {
        self.bytes(field, value.map(|s| s.as_bytes()))
    }

    pub fn message(&mut self, field: u32, value: Option<&[u8]>) -> &mut Self {
        self.bytes(field, value)
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// A decoded message: field number -> the values seen for it (a field may repeat).
#[derive(Debug, Default, Clone)]
pub struct Fields {
    inner: Vec<(u32, Value)>,
}

/// A decoded field value.
#[derive(Debug, Clone)]
pub enum Value {
    Varint(u64),
    Bytes(Vec<u8>),
    Fixed64(u64),
    Fixed32(u32),
}

impl Fields {
    /// Parse a message.
    pub fn decode(data: &[u8]) -> Result<Fields> {
        let mut out = Fields { inner: Vec::new() };
        let mut pos = 0usize;
        while pos < data.len() {
            let (tag, next) = read_varint(data, pos)?;
            pos = next;
            let field = (tag >> 3) as u32;
            let wire = (tag & 7) as u8;
            let value = match wire {
                WT_VARINT => {
                    let (v, next) = read_varint(data, pos)?;
                    pos = next;
                    Value::Varint(v)
                }
                WT_LEN => {
                    let (len, next) = read_varint(data, pos)?;
                    pos = next;
                    let end = pos + len as usize;
                    if end > data.len() {
                        return Err(Error::Proto("truncated length-delimited field".into()));
                    }
                    let chunk = data[pos..end].to_vec();
                    pos = end;
                    Value::Bytes(chunk)
                }
                WT_I64 => {
                    if pos + 8 > data.len() {
                        return Err(Error::Proto("truncated 64-bit field".into()));
                    }
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&data[pos..pos + 8]);
                    pos += 8;
                    Value::Fixed64(u64::from_le_bytes(b))
                }
                WT_I32 => {
                    if pos + 4 > data.len() {
                        return Err(Error::Proto("truncated 32-bit field".into()));
                    }
                    let mut b = [0u8; 4];
                    b.copy_from_slice(&data[pos..pos + 4]);
                    pos += 4;
                    Value::Fixed32(u32::from_le_bytes(b))
                }
                other => {
                    return Err(Error::Proto(format!("unsupported wire type {other}")));
                }
            };
            out.inner.push((field, value));
        }
        Ok(out)
    }

    /// The first value of a field, if any.
    pub fn get(&self, field: u32) -> Option<&Value> {
        self.inner.iter().find(|(f, _)| *f == field).map(|(_, v)| v)
    }

    /// Every value of a field.
    pub fn get_all(&self, field: u32) -> Vec<&Value> {
        self.inner
            .iter()
            .filter(|(f, _)| *f == field)
            .map(|(_, v)| v)
            .collect()
    }

    /// The first value of a field as bytes.
    pub fn bytes(&self, field: u32) -> Option<&[u8]> {
        match self.get(field) {
            Some(Value::Bytes(b)) => Some(b),
            _ => None,
        }
    }

    /// The first value of a field as a string.
    pub fn string(&self, field: u32) -> Option<String> {
        self.bytes(field)
            .and_then(|b| String::from_utf8(b.to_vec()).ok())
    }

    /// The first value of a field as an integer.
    pub fn uint(&self, field: u32) -> Option<u64> {
        match self.get(field) {
            Some(Value::Varint(v)) => Some(*v),
            Some(Value::Fixed64(v)) => Some(*v),
            Some(Value::Fixed32(v)) => Some(*v as u64),
            _ => None,
        }
    }

    /// The first value of a field as a boolean.
    pub fn bool(&self, field: u32) -> Option<bool> {
        self.uint(field).map(|v| v != 0)
    }

    /// The field numbers present in the message.
    pub fn field_numbers(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.inner.iter().map(|(f, _)| *f).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

fn read_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let mut shift = 0u32;
    let mut val = 0u64;
    loop {
        if pos >= data.len() {
            return Err(Error::Proto("truncated varint".into()));
        }
        let b = data[pos];
        pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((val, pos));
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::Proto("varint too long".into()));
        }
    }
}

/// Length-delimited framing: a uleb128 length prefix then the message.
pub fn delimit(message: &[u8]) -> Vec<u8> {
    let mut out = encode_varint(message.len() as u64);
    out.extend_from_slice(message);
    out
}

/// Split a stream of length-delimited messages.
pub fn undelimit(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let (len, next) = match read_varint(buf, pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos = next;
        let end = pos + len as usize;
        if end > buf.len() {
            break;
        }
        out.push(buf[pos..end].to_vec());
        pos = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let enc = encode_varint(v);
            let (dec, pos) = read_varint(&enc, 0).unwrap();
            assert_eq!(dec, v);
            assert_eq!(pos, enc.len());
        }
    }

    #[test]
    fn negative_int64_is_ten_bytes() {
        let enc = encode_varint_i64(-1);
        assert_eq!(enc.len(), 10);
        let (dec, _) = read_varint(&enc, 0).unwrap();
        assert_eq!(dec, u64::MAX);
    }

    #[test]
    fn fields_roundtrip() {
        let mut w = Writer::new();
        w.string(1, Some("hello"))
            .uint64(2, Some(42))
            .bytes(3, Some(&[1, 2, 3]))
            .bool(4, Some(true));
        let raw = w.finish();
        let f = Fields::decode(&raw).unwrap();
        assert_eq!(f.string(1).as_deref(), Some("hello"));
        assert_eq!(f.uint(2), Some(42));
        assert_eq!(f.bytes(3), Some(&[1u8, 2, 3][..]));
        assert_eq!(f.bool(4), Some(true));
        assert_eq!(f.field_numbers(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn repeated_fields_are_kept() {
        let mut w = Writer::new();
        w.string(1, Some("a")).string(1, Some("b"));
        let f = Fields::decode(&w.finish()).unwrap();
        assert_eq!(f.get_all(1).len(), 2);
        assert_eq!(f.string(1).as_deref(), Some("a"));
    }

    #[test]
    fn delimited_roundtrip() {
        let msg = b"hello world".to_vec();
        let framed = delimit(&msg);
        let parts = undelimit(&framed);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], msg);
    }
}
