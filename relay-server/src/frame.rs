use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ErrorCode, RelayError, Result};

pub const PROTOCOL_VERSION: u8 = 1;
const HEADER_BYTES: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Register = 1,
    RegisterOk = 2,
    Error = 3,
    Open = 10,
    OpenOk = 11,
    OpenError = 12,
    Data = 13,
    Fin = 14,
    Close = 15,
    WindowUpdate = 16,
    Ping = 20,
    Pong = 21,
}

impl TryFrom<u8> for FrameKind {
    type Error = RelayError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Register),
            2 => Ok(Self::RegisterOk),
            3 => Ok(Self::Error),
            10 => Ok(Self::Open),
            11 => Ok(Self::OpenOk),
            12 => Ok(Self::OpenError),
            13 => Ok(Self::Data),
            14 => Ok(Self::Fin),
            15 => Ok(Self::Close),
            16 => Ok(Self::WindowUpdate),
            20 => Ok(Self::Ping),
            21 => Ok(Self::Pong),
            _ => Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "unknown frame kind",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    pub stream_id: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    #[must_use]
    pub fn new(kind: FrameKind, stream_id: u64, payload: Vec<u8>) -> Self {
        Self {
            kind,
            stream_id,
            payload,
        }
    }

    /// Builds the mandatory first route-registration frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the route ID or token cannot fit the bounded wire representation.
    pub fn register(route_id: &str, token: &[u8]) -> Result<Self> {
        let route_len = u16::try_from(route_id.len()).map_err(|_| {
            RelayError::stable(ErrorCode::ProtocolInvalid, "route identifier is too long")
        })?;
        let token_len = u16::try_from(token.len()).map_err(|_| {
            RelayError::stable(ErrorCode::ProtocolInvalid, "route token is too long")
        })?;
        let mut payload = Vec::with_capacity(4 + route_id.len() + token.len());
        payload.extend_from_slice(&route_len.to_be_bytes());
        payload.extend_from_slice(route_id.as_bytes());
        payload.extend_from_slice(&token_len.to_be_bytes());
        payload.extend_from_slice(token);
        Ok(Self::new(FrameKind::Register, 0, payload))
    }

    /// Parses a route-registration frame without copying its secret material.
    ///
    /// # Errors
    ///
    /// Returns an error if the kind, stream ID, lengths, or route encoding are invalid.
    pub fn parse_register(&self) -> Result<(&str, &[u8])> {
        if self.kind != FrameKind::Register || self.stream_id != 0 || self.payload.len() < 4 {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "first frame must register one route",
            ));
        }
        let route_len = usize::from(u16::from_be_bytes([self.payload[0], self.payload[1]]));
        let token_len_offset = 2usize.checked_add(route_len).ok_or_else(|| {
            RelayError::stable(ErrorCode::ProtocolInvalid, "invalid register lengths")
        })?;
        if token_len_offset + 2 > self.payload.len() {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "invalid register route length",
            ));
        }
        let token_len = usize::from(u16::from_be_bytes([
            self.payload[token_len_offset],
            self.payload[token_len_offset + 1],
        ]));
        let token_offset = token_len_offset + 2;
        if token_offset.checked_add(token_len) != Some(self.payload.len()) {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "invalid register token length",
            ));
        }
        let route_id = std::str::from_utf8(&self.payload[2..token_len_offset]).map_err(|_| {
            RelayError::stable(ErrorCode::ProtocolInvalid, "route identifier is not UTF-8")
        })?;
        Ok((route_id, &self.payload[token_offset..]))
    }

    #[must_use]
    pub fn u32(kind: FrameKind, stream_id: u64, value: u32) -> Self {
        Self::new(kind, stream_id, value.to_be_bytes().to_vec())
    }

    /// Parses a four-byte unsigned frame payload.
    ///
    /// # Errors
    ///
    /// Returns an error unless the payload is exactly four bytes.
    pub fn parse_u32(&self) -> Result<u32> {
        self.payload
            .as_slice()
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| {
                RelayError::stable(
                    ErrorCode::ProtocolInvalid,
                    "frame requires one unsigned 32-bit value",
                )
            })
    }

    #[must_use]
    pub fn code(kind: FrameKind, stream_id: u64, code: ErrorCode) -> Self {
        Self::new(kind, stream_id, code.as_str().as_bytes().to_vec())
    }

    /// Reads and validates one length-delimited frame.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failure, unsupported protocol data, or a frame exceeding the
    /// configured maximum. The length is checked before payload allocation.
    pub async fn read_from<R>(reader: &mut R, max_frame_bytes: usize) -> Result<Option<Self>>
    where
        R: AsyncRead + Unpin,
    {
        let length = match reader.read_u32().await {
            Ok(length) => usize::try_from(length).map_err(|_| {
                RelayError::stable(ErrorCode::FrameTooLarge, "frame length is unsupported")
            })?,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if length < HEADER_BYTES {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "frame is shorter than its header",
            ));
        }
        if length > max_frame_bytes + HEADER_BYTES {
            return Err(RelayError::stable(
                ErrorCode::FrameTooLarge,
                "frame exceeds configured maximum",
            ));
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await?;
        if body[0] != PROTOCOL_VERSION {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "protocol version is unsupported",
            ));
        }
        let kind = FrameKind::try_from(body[1])?;
        let stream_id = u64::from_be_bytes(body[2..10].try_into().map_err(|_| {
            RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "invalid frame stream identifier",
            )
        })?);
        Ok(Some(Self {
            kind,
            stream_id,
            payload: body[HEADER_BYTES..].to_vec(),
        }))
    }

    /// Writes one bounded length-delimited frame.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failure, length overflow, or an oversized payload.
    pub async fn write_to<W>(&self, writer: &mut W, max_frame_bytes: usize) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if self.payload.len() > max_frame_bytes {
            return Err(RelayError::stable(
                ErrorCode::FrameTooLarge,
                "frame exceeds configured maximum",
            ));
        }
        let length = HEADER_BYTES
            .checked_add(self.payload.len())
            .ok_or_else(|| RelayError::stable(ErrorCode::FrameTooLarge, "frame length overflow"))?;
        writer
            .write_u32(u32::try_from(length).map_err(|_| {
                RelayError::stable(ErrorCode::FrameTooLarge, "frame length is unsupported")
            })?)
            .await?;
        writer.write_u8(PROTOCOL_VERSION).await?;
        writer.write_u8(self.kind as u8).await?;
        writer.write_u64(self.stream_id).await?;
        writer.write_all(&self.payload).await?;
        writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_round_trip() {
        let frame = Frame::register("route_0123456789", &[7; 32]).unwrap();
        let (route_id, token) = frame.parse_register().unwrap();
        assert_eq!(route_id, "route_0123456789");
        assert_eq!(token, &[7; 32]);
    }

    #[tokio::test]
    async fn frame_io_round_trip() {
        let (mut left, mut right) = tokio::io::duplex(1_024);
        let expected = Frame::new(FrameKind::Data, 42, b"opaque bytes".to_vec());
        let sent = expected.clone();
        let writer = tokio::spawn(async move { sent.write_to(&mut left, 512).await });
        let actual = Frame::read_from(&mut right, 512).await.unwrap().unwrap();
        writer.await.unwrap().unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocation() {
        let (mut left, mut right) = tokio::io::duplex(64);
        left.write_u32(1_000_000).await.unwrap();
        let error = Frame::read_from(&mut right, 512).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::FrameTooLarge);
    }
}
