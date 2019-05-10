/*!
 * MQTT protocol types.
 */

use std::convert::TryInto;

use bytes::{ Buf, BufMut, IntoBuf };

mod packet;

pub use self::packet::{
	Packet,

	Auth,
	ConnAck,
	Connect,
	Disconnect,
	PingReq,
	PingResp,
	PubAck,
	PubComp,
	Publish,
	PubRec,
	PubRel,
	SubAck,
	Subscribe,
	UnsubAck,
	Unsubscribe,

	Authentication,
	PacketCodec,
	PacketIdentifierDupQoS,
	PayloadFormat,
	Property,
	Publication,
	QoS,
	SubAckQos,
	SubscribeTo,
};

pub(crate) use self::packet::PacketMeta;

/// The client ID
///
/// Refs:
/// - 3.1.3.1 Client Identifier
/// - 3.1.2.4 Clean Session
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientId {
	ServerGenerated,
	IdWithCleanSession(String),
	IdWithExistingSession(String),
}

/// The return code for a connection attempt
///
/// Ref: 3.2.2.2 Connect Reason Code
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectReasonCode {
	Success,
	Failure(ConnectionFailureReason),
}

/// The reason the connection was refused by the server
///
/// Ref: 3.2.2.2 Connect Reason Code
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionFailureReason {
	UnspecifiedError,
	MalformedPacket,
	ProtocolError,
	ImplementationSpecificError,
	UnsupportedProtocolVersion,
	ClientIdentifierNotValid,
	BadUserNameOrPassword,
	NotAuthorized,
	ServerUnavailable,
	ServerBusy,
	Banned,
	BadAuthenticationMethod,
	TopicNameInvalid,
	PacketTooLarge,
	QuotaExceeded,
	PayloadFormatInvalid,
	RetainNotSupported,
	QoSNotSupported,
	UseAnotherServer,
	ServerMoved,
	ConnectionRateExceeded,
	Other(u8),
}

impl From<u8> for ConnectReasonCode {
	fn from(code: u8) -> Self {
		match code {
			0x00 => ConnectReasonCode::Success,
			0x80 => ConnectReasonCode::Failure(ConnectionFailureReason::UnspecifiedError),
			0x81 => ConnectReasonCode::Failure(ConnectionFailureReason::MalformedPacket),
			0x82 => ConnectReasonCode::Failure(ConnectionFailureReason::ProtocolError),
			0x83 => ConnectReasonCode::Failure(ConnectionFailureReason::ImplementationSpecificError),
			0x84 => ConnectReasonCode::Failure(ConnectionFailureReason::UnsupportedProtocolVersion),
			0x85 => ConnectReasonCode::Failure(ConnectionFailureReason::ClientIdentifierNotValid),
			0x86 => ConnectReasonCode::Failure(ConnectionFailureReason::BadUserNameOrPassword),
			0x87 => ConnectReasonCode::Failure(ConnectionFailureReason::NotAuthorized),
			0x88 => ConnectReasonCode::Failure(ConnectionFailureReason::ServerUnavailable),
			0x89 => ConnectReasonCode::Failure(ConnectionFailureReason::ServerBusy),
			0x8A => ConnectReasonCode::Failure(ConnectionFailureReason::Banned),
			0x8C => ConnectReasonCode::Failure(ConnectionFailureReason::BadAuthenticationMethod),
			0x90 => ConnectReasonCode::Failure(ConnectionFailureReason::TopicNameInvalid),
			0x95 => ConnectReasonCode::Failure(ConnectionFailureReason::PacketTooLarge),
			0x97 => ConnectReasonCode::Failure(ConnectionFailureReason::QuotaExceeded),
			0x99 => ConnectReasonCode::Failure(ConnectionFailureReason::PayloadFormatInvalid),
			0x9A => ConnectReasonCode::Failure(ConnectionFailureReason::RetainNotSupported),
			0x9B => ConnectReasonCode::Failure(ConnectionFailureReason::QoSNotSupported),
			0x9C => ConnectReasonCode::Failure(ConnectionFailureReason::UseAnotherServer),
			0x9D => ConnectReasonCode::Failure(ConnectionFailureReason::ServerMoved),
			0x9F => ConnectReasonCode::Failure(ConnectionFailureReason::ConnectionRateExceeded),
			code => ConnectReasonCode::Failure(ConnectionFailureReason::Other(code)),
		}
	}
}

impl From<ConnectReasonCode> for u8 {
	fn from(code: ConnectReasonCode) -> Self {
		match code {
			ConnectReasonCode::Success => 0x00,
			ConnectReasonCode::Failure(ConnectionFailureReason::UnspecifiedError) => 0x80,
			ConnectReasonCode::Failure(ConnectionFailureReason::MalformedPacket) => 0x81,
			ConnectReasonCode::Failure(ConnectionFailureReason::ProtocolError) => 0x82,
			ConnectReasonCode::Failure(ConnectionFailureReason::ImplementationSpecificError) => 0x83,
			ConnectReasonCode::Failure(ConnectionFailureReason::UnsupportedProtocolVersion) => 0x84,
			ConnectReasonCode::Failure(ConnectionFailureReason::ClientIdentifierNotValid) => 0x85,
			ConnectReasonCode::Failure(ConnectionFailureReason::BadUserNameOrPassword) => 0x86,
			ConnectReasonCode::Failure(ConnectionFailureReason::NotAuthorized) => 0x87,
			ConnectReasonCode::Failure(ConnectionFailureReason::ServerUnavailable) => 0x88,
			ConnectReasonCode::Failure(ConnectionFailureReason::ServerBusy) => 0x89,
			ConnectReasonCode::Failure(ConnectionFailureReason::Banned) => 0x8A,
			ConnectReasonCode::Failure(ConnectionFailureReason::BadAuthenticationMethod) => 0x8C,
			ConnectReasonCode::Failure(ConnectionFailureReason::TopicNameInvalid) => 0x90,
			ConnectReasonCode::Failure(ConnectionFailureReason::PacketTooLarge) => 0x95,
			ConnectReasonCode::Failure(ConnectionFailureReason::QuotaExceeded) => 0x97,
			ConnectReasonCode::Failure(ConnectionFailureReason::PayloadFormatInvalid) => 0x99,
			ConnectReasonCode::Failure(ConnectionFailureReason::RetainNotSupported) => 0x9A,
			ConnectReasonCode::Failure(ConnectionFailureReason::QoSNotSupported) => 0x9B,
			ConnectReasonCode::Failure(ConnectionFailureReason::UseAnotherServer) => 0x9C,
			ConnectReasonCode::Failure(ConnectionFailureReason::ServerMoved) => 0x9D,
			ConnectReasonCode::Failure(ConnectionFailureReason::ConnectionRateExceeded) => 0x9F,
			ConnectReasonCode::Failure(ConnectionFailureReason::Other(code)) => code,
		}
	}
}

/// A tokio decoder of MQTT-format strings.
///
/// Strings are prefixed with a two-byte big-endian length and are encoded as utf-8.
///
/// Ref: 1.5.3 UTF-8 encoded strings
#[derive(Debug)]
pub enum Utf8StringDecoder {
	Empty,
	HaveLength(usize),
}

impl Default for Utf8StringDecoder {
	fn default() -> Self {
		Utf8StringDecoder::Empty
	}
}

impl tokio_codec::Decoder for Utf8StringDecoder {
	type Item = String;
	type Error = DecodeError;

	fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		loop {
			match self {
				Utf8StringDecoder::Empty => {
					let len = match src.try_get_u16_be() {
						Ok(len) => len as usize,
						Err(_) => return Ok(None),
					};
					*self = Utf8StringDecoder::HaveLength(len);
				},

				Utf8StringDecoder::HaveLength(len) => {
					if src.len() < *len {
						return Ok(None);
					}

					let s = match std::str::from_utf8(&src.split_to(*len)) {
						Ok(s) => s.to_string(),
						Err(err) => return Err(DecodeError::StringNotUtf8(err)),
					};
					*self = Utf8StringDecoder::Empty;
					return Ok(Some(s));
				},
			}
		}
	}
}

fn encode_utf8_str<B>(item: &str, dst: &mut B) -> Result<(), EncodeError> where B: ByteBuf {
	let len = item.len();
	dst.put_u16_be_bytes(len.try_into().map_err(|_| EncodeError::StringTooLarge(len))?);

	dst.put_slice_bytes(item.as_bytes());

	Ok(())
}

/// A tokio decoder for MQTT-format variable-byte integers.
///
/// These numbers are encoded with a variable-length scheme that uses the MSB of each byte as a continuation bit.
///
/// Ref: 1.5.5 Variable Byte Integer
#[derive(Debug)]
pub struct VariableByteIntegerDecoder {
	result: usize,
	num_bytes_read: usize,
}

impl Default for VariableByteIntegerDecoder {
	fn default() -> Self {
		VariableByteIntegerDecoder {
			result: 0,
			num_bytes_read: 0,
		}
	}
}

impl tokio_codec::Decoder for VariableByteIntegerDecoder {
	type Item = usize;
	type Error = DecodeError;

	fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		loop {
			let encoded_byte = match src.try_get_u8() {
				Ok(encoded_byte) => encoded_byte,
				Err(_) => return Ok(None),
			};

			self.result |= ((encoded_byte & 0x7F) as usize) << (self.num_bytes_read * 7);
			self.num_bytes_read += 1;

			if encoded_byte & 0x80 == 0 {
				let result = self.result;
				*self = Default::default();
				return Ok(Some(result));
			}

			if self.num_bytes_read == 4 {
				return Err(DecodeError::VariableByteIntegerTooHigh);
			}
		}
	}
}

pub(crate) fn encode_variable_byte_integer<B>(mut item: usize, dst: &mut B) -> Result<(), EncodeError> where B: ByteBuf {
	dst.reserve_bytes(4 * std::mem::size_of::<u8>());

	let original = item;
	let mut num_bytes_written = 0_usize;

	loop {
		#[allow(clippy::cast_possible_truncation)]
		let mut encoded_byte = (item & 0x7F) as u8;

		item >>= 7;

		if item > 0 {
			encoded_byte |= 0x80;
		}

		dst.put_u8_bytes(encoded_byte);
		num_bytes_written += 1;

		if item == 0 {
			break;
		}

		if num_bytes_written == 4 {
			return Err(EncodeError::VariableByteIntegerTooHigh(original));
		}
	}

	Ok(())
}

/// A packet identifier. Two-byte unsigned integer that cannot be zero.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacketIdentifier(u16);

impl PacketIdentifier {
	/// Returns the largest value that is a valid packet identifier.
	pub const fn max_value() -> Self {
		PacketIdentifier(u16::max_value())
	}

	/// Convert the given raw packet identifier into this type.
	pub fn new(raw: u16) -> Option<Self> {
		match raw {
			0 => None,
			raw => Some(PacketIdentifier(raw)),
		}
	}

	/// Get the raw packet identifier.
	pub fn get(self) -> u16 {
		self.0
	}
}

impl std::fmt::Display for PacketIdentifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}

impl std::ops::Add<u16> for PacketIdentifier {
	type Output = Self;

	fn add(self, other: u16) -> Self::Output {
		PacketIdentifier(match self.0.wrapping_add(other) {
			0 => 1,
			value => value,
		})
	}
}

impl std::ops::AddAssign<u16> for PacketIdentifier {
	fn add_assign(&mut self, other: u16) {
		*self = *self + other;
	}
}

#[derive(Debug)]
pub enum DecodeError {
	ConnectAuthenticationDataWithoutAuthenticationMethod,
	ConnectReservedSet,
	DuplicateProperty(Property, Property),
	IncompletePacket,
	Io(std::io::Error),
	MalformedProperty(&'static str, Box<dyn std::fmt::Debug + Send>),
	NoTopics,
	PublishDupAtMostOnce,
	StringNotUtf8(std::str::Utf8Error),
	UnexpectedProperty(Property),
	UnrecognizedConnAckFlags(u8),
	UnrecognizedPacket { packet_type: u8, flags: u8, remaining_length: usize },
	UnrecognizedProperty(usize),
	UnrecognizedProtocolLevel(u8),
	UnrecognizedProtocolName(String),
	UnrecognizedQoS(u8),
	VariableByteIntegerTooHigh,
	ZeroPacketIdentifier,
}

impl std::fmt::Display for DecodeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			DecodeError::ConnectAuthenticationDataWithoutAuthenticationMethod =>
				write!(f, "CONNECT packet has authentication data property without authentication method property"),
			DecodeError::ConnectReservedSet => write!(f, "the reserved byte of the CONNECT flags is set"),
			DecodeError::DuplicateProperty(prop1, prop2) => write!(f, "duplicate property in packet: {:?}, {:?}", prop1, prop2),
			DecodeError::IncompletePacket => write!(f, "packet is truncated"),
			DecodeError::Io(err) => write!(f, "I/O error: {}", err),
			DecodeError::MalformedProperty(name, value) => write!(f, "malformed {}: {:?}", name, value),
			DecodeError::NoTopics => write!(f, "expected at least one topic but there were none"),
			DecodeError::PublishDupAtMostOnce => write!(f, "PUBLISH packet has DUP flag set and QoS 0"),
			DecodeError::StringNotUtf8(err) => err.fmt(f),
			DecodeError::UnexpectedProperty(property) => write!(f, "unexpected property in packet: {:?}", property),
			DecodeError::UnrecognizedConnAckFlags(flags) => write!(f, "could not parse CONNACK flags 0x{:02X}", flags),
			DecodeError::UnrecognizedPacket { packet_type, flags, remaining_length } =>
				write!(
					f,
					"could not identify packet with type 0x{:1X}, flags 0x{:1X} and remaining length {}",
					packet_type,
					flags,
					remaining_length,
				),
			DecodeError::UnrecognizedProperty(id) => write!(f, "unexpected property identifier {}", id),
			DecodeError::UnrecognizedProtocolLevel(level) => write!(f, "unexpected protocol level {}", level),
			DecodeError::UnrecognizedProtocolName(name) => write!(f, "unexpected protocol name {:?}", name),
			DecodeError::UnrecognizedQoS(qos) => write!(f, "could not parse QoS 0x{:02X}", qos),
			DecodeError::VariableByteIntegerTooHigh => write!(f, "variable byte integer is too high to be decoded"),
			DecodeError::ZeroPacketIdentifier => write!(f, "packet identifier is 0"),
		}
	}
}

impl std::error::Error for DecodeError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		#[allow(clippy::match_same_arms)]
		match self {
			DecodeError::ConnectAuthenticationDataWithoutAuthenticationMethod => None,
			DecodeError::ConnectReservedSet => None,
			DecodeError::DuplicateProperty(_, _) => None,
			DecodeError::IncompletePacket => None,
			DecodeError::Io(err) => Some(err),
			DecodeError::MalformedProperty(_, _) => None,
			DecodeError::NoTopics => None,
			DecodeError::PublishDupAtMostOnce => None,
			DecodeError::StringNotUtf8(err) => Some(err),
			DecodeError::UnexpectedProperty(_) => None,
			DecodeError::UnrecognizedConnAckFlags(_) => None,
			DecodeError::UnrecognizedPacket { .. } => None,
			DecodeError::UnrecognizedProperty(_) => None,
			DecodeError::UnrecognizedProtocolLevel(_) => None,
			DecodeError::UnrecognizedProtocolName(_) => None,
			DecodeError::UnrecognizedQoS(_) => None,
			DecodeError::VariableByteIntegerTooHigh => None,
			DecodeError::ZeroPacketIdentifier => None,
		}
	}
}

impl From<std::io::Error> for DecodeError {
	fn from(err: std::io::Error) -> Self {
		DecodeError::Io(err)
	}
}

#[derive(Debug)]
pub enum EncodeError {
	Io(std::io::Error),
	KeepAliveTooHigh(std::time::Duration),
	StringTooLarge(usize),
	VariableByteIntegerTooHigh(usize),
	WillTooLarge(usize),
}

impl EncodeError {
	pub fn is_user_error(&self) -> bool {
		#[allow(clippy::match_same_arms)]
		match self {
			EncodeError::Io(_) => false,
			EncodeError::KeepAliveTooHigh(_) => true,
			EncodeError::StringTooLarge(_) => true,
			EncodeError::VariableByteIntegerTooHigh(_) => true,
			EncodeError::WillTooLarge(_) => true,
		}
	}
}

impl std::fmt::Display for EncodeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			EncodeError::Io(err) => write!(f, "I/O error: {}", err),
			EncodeError::KeepAliveTooHigh(keep_alive) => write!(f, "keep-alive {:?} is too high", keep_alive),
			EncodeError::StringTooLarge(len) => write!(f, "string of length {} is too large to be encoded", len),
			EncodeError::VariableByteIntegerTooHigh(len) => write!(f, "integer {} is too high to be encoded as a variable byte integer", len),
			EncodeError::WillTooLarge(len) => write!(f, "will payload of length {} is too large to be encoded", len),
		}
	}
}

impl std::error::Error for EncodeError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		#[allow(clippy::match_same_arms)]
		match self {
			EncodeError::Io(err) => Some(err),
			EncodeError::KeepAliveTooHigh(_) => None,
			EncodeError::StringTooLarge(_) => None,
			EncodeError::VariableByteIntegerTooHigh(_) => None,
			EncodeError::WillTooLarge(_) => None,
		}
	}
}

impl From<std::io::Error> for EncodeError {
	fn from(err: std::io::Error) -> Self {
		EncodeError::Io(err)
	}
}

pub(crate) trait ByteBuf {
	fn reserve_bytes(&mut self, additional: usize);

	fn put_u8_bytes(&mut self, n: u8);

	fn put_u16_be_bytes(&mut self, n: u16);

	fn put_u32_be_bytes(&mut self, n: u32);

	fn put_packet_identifier_bytes(&mut self, packet_identifier: PacketIdentifier) {
		self.put_u16_be_bytes(packet_identifier.0);
	}

	fn put_slice_bytes(&mut self, src: &[u8]);
}

impl ByteBuf for bytes::BytesMut {
	fn reserve_bytes(&mut self, additional: usize) {
		self.reserve(additional);
	}

	fn put_u8_bytes(&mut self, n: u8) {
		self.put_u8(n);
	}

	fn put_u16_be_bytes(&mut self, n: u16) {
		self.put_u16_be(n);
	}

	fn put_u32_be_bytes(&mut self, n: u32) {
		self.put_u32_be(n);
	}

	fn put_slice_bytes(&mut self, src: &[u8]) {
		self.put_slice(src);
	}
}

pub(crate) struct ByteCounter(pub(crate) usize);

impl ByteCounter {
	pub(crate) fn new() -> Self {
		ByteCounter(0)
	}
}

impl ByteBuf for ByteCounter {
	fn reserve_bytes(&mut self, _: usize) {
	}

	fn put_u8_bytes(&mut self, _: u8) {
		self.0 += std::mem::size_of::<u8>();
	}

	fn put_u16_be_bytes(&mut self, _: u16) {
		self.0 += std::mem::size_of::<u16>();
	}

	fn put_u32_be_bytes(&mut self, _: u32) {
		self.0 += std::mem::size_of::<u32>();
	}

	fn put_slice_bytes(&mut self, src: &[u8]) {
		self.0 += src.len();
	}
}

trait BufMutExt {
	fn get_u8(&mut self) -> u8;
	fn get_packet_identifier(&mut self) -> Result<PacketIdentifier, DecodeError>;

	fn try_get_u8(&mut self) -> Result<u8, DecodeError>;
	fn try_get_u16_be(&mut self) -> Result<u16, DecodeError>;
	fn try_get_u32_be(&mut self) -> Result<u32, DecodeError>;
	fn try_get_packet_identifier(&mut self) -> Result<PacketIdentifier, DecodeError>;
}

impl BufMutExt for bytes::BytesMut {
	fn get_u8(&mut self) -> u8 {
		let result = self[0];
		self.advance(std::mem::size_of::<u8>());
		result
	}

	fn get_packet_identifier(&mut self) -> Result<PacketIdentifier, DecodeError> {
		let packet_identifier = self.split_to(std::mem::size_of::<u16>()).into_buf().get_u16_be();
		PacketIdentifier::new(packet_identifier).ok_or(DecodeError::ZeroPacketIdentifier)
	}

	fn try_get_u8(&mut self) -> Result<u8, DecodeError> {
		if self.len() < std::mem::size_of::<u8>() {
			return Err(DecodeError::IncompletePacket);
		}

		let result = self[0];
		self.advance(std::mem::size_of::<u8>());
		Ok(result)
	}

	fn try_get_u16_be(&mut self) -> Result<u16, DecodeError> {
		if self.len() < std::mem::size_of::<u16>() {
			return Err(DecodeError::IncompletePacket);
		}

		Ok(self.split_to(std::mem::size_of::<u16>()).into_buf().get_u16_be())
	}

	fn try_get_u32_be(&mut self) -> Result<u32, DecodeError> {
		if self.len() < std::mem::size_of::<u32>() {
			return Err(DecodeError::IncompletePacket);
		}

		Ok(self.split_to(std::mem::size_of::<u32>()).into_buf().get_u32_be())
	}

	fn try_get_packet_identifier(&mut self) -> Result<PacketIdentifier, DecodeError> {
		if self.len() < std::mem::size_of::<u16>() {
			return Err(DecodeError::IncompletePacket);
		}

		self.get_packet_identifier()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn variable_byte_integer_encode() {
		variable_byte_integer_encode_inner_ok(0x00, &[0x00]);
		variable_byte_integer_encode_inner_ok(0x01, &[0x01]);

		variable_byte_integer_encode_inner_ok(0x7F, &[0x7F]);
		variable_byte_integer_encode_inner_ok(0x80, &[0x80, 0x01]);
		variable_byte_integer_encode_inner_ok(0x3FFF, &[0xFF, 0x7F]);
		variable_byte_integer_encode_inner_ok(0x4000, &[0x80, 0x80, 0x01]);
		variable_byte_integer_encode_inner_ok(0x001F_FFFF, &[0xFF, 0xFF, 0x7F]);
		variable_byte_integer_encode_inner_ok(0x0020_0000, &[0x80, 0x80, 0x80, 0x01]);
		variable_byte_integer_encode_inner_ok(0x0FFF_FFFF, &[0xFF, 0xFF, 0xFF, 0x7F]);

		variable_byte_integer_encode_inner_too_high(0x1000_0000);
		variable_byte_integer_encode_inner_too_high(0xFFFF_FFFF);
		variable_byte_integer_encode_inner_too_high(0xFFFF_FFFF_FFFF_FFFF);
	}

	fn variable_byte_integer_encode_inner_ok(value: usize, expected: &[u8]) {
		// Can encode into an empty buffer
		let mut bytes = bytes::BytesMut::new();
		super::encode_variable_byte_integer(value, &mut bytes).unwrap();
		assert_eq!(&*bytes, expected);

		// Can encode into a partially populated buffer
		let mut bytes: bytes::BytesMut = vec![0x00; 3].into();
		super::encode_variable_byte_integer(value, &mut bytes).unwrap();
		assert_eq!(&bytes[3..], expected);
	}

	fn variable_byte_integer_encode_inner_too_high(value: usize) {
		let mut bytes = bytes::BytesMut::new();
		let err = super::encode_variable_byte_integer(value, &mut bytes).unwrap_err();
		if let super::EncodeError::VariableByteIntegerTooHigh(v) = err {
			assert_eq!(v, value);
		}
		else {
			panic!("{:?}", err);
		}
	}

	#[test]
	fn variable_byte_integer_decode() {
		variable_byte_integer_decode_inner_ok(&[0x00], 0x00);
		variable_byte_integer_decode_inner_ok(&[0x01], 0x01);

		variable_byte_integer_decode_inner_ok(&[0x7F], 0x7F);
		variable_byte_integer_decode_inner_ok(&[0x80, 0x01], 0x80);
		variable_byte_integer_decode_inner_ok(&[0xFF, 0x7F], 0x3FFF);
		variable_byte_integer_decode_inner_ok(&[0x80, 0x80, 0x01], 0x4000);
		variable_byte_integer_decode_inner_ok(&[0xFF, 0xFF, 0x7F], 0x001F_FFFF);
		variable_byte_integer_decode_inner_ok(&[0x80, 0x80, 0x80, 0x01], 0x0020_0000);
		variable_byte_integer_decode_inner_ok(&[0xFF, 0xFF, 0xFF, 0x7F], 0x0FFF_FFFF);

		// Longer-than-necessary encodings are not disallowed by the spec
		variable_byte_integer_decode_inner_ok(&[0x81, 0x00], 0x01);
		variable_byte_integer_decode_inner_ok(&[0x81, 0x80, 0x00], 0x01);
		variable_byte_integer_decode_inner_ok(&[0x81, 0x80, 0x80, 0x00], 0x01);

		variable_byte_integer_decode_inner_too_high(&[0x80, 0x80, 0x80, 0x80]);
		variable_byte_integer_decode_inner_too_high(&[0xFF, 0xFF, 0xFF, 0xFF]);

		variable_byte_integer_decode_inner_incomplete_packet(&[0x80]);
		variable_byte_integer_decode_inner_incomplete_packet(&[0x80, 0x80]);
		variable_byte_integer_decode_inner_incomplete_packet(&[0x80, 0x80, 0x80]);
	}

	fn variable_byte_integer_decode_inner_ok(bytes: &[u8], expected: usize) {
		use tokio_codec::Decoder;

		let mut bytes = bytes::BytesMut::from(bytes);
		let actual = super::VariableByteIntegerDecoder::default().decode(&mut bytes).unwrap().unwrap();
		assert_eq!(actual, expected);
		assert!(bytes.is_empty());
	}

	fn variable_byte_integer_decode_inner_too_high(bytes: &[u8]) {
		use tokio_codec::Decoder;

		let mut bytes = bytes::BytesMut::from(bytes);
		let err = super::VariableByteIntegerDecoder::default().decode(&mut bytes).unwrap_err();
		if let super::DecodeError::VariableByteIntegerTooHigh = err {
		}
		else {
			panic!("{:?}", err);
		}
	}

	fn variable_byte_integer_decode_inner_incomplete_packet(bytes: &[u8]) {
		use tokio_codec::Decoder;

		let mut bytes = bytes::BytesMut::from(bytes);
		assert_eq!(super::VariableByteIntegerDecoder::default().decode(&mut bytes).unwrap(), None);
	}
}
