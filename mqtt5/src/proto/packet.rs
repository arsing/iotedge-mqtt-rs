use std::convert::TryInto;

use bytes::{ Buf, BufMut, IntoBuf };
use tokio_codec::Decoder;

use super::{ BufMutExt, ByteBuf };

/// An MQTT packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
	/// Ref: 3.15 AUTH – Authentication exchange
	Auth(Auth),

	/// Ref: 3.2 CONNACK – Acknowledge connection request
	ConnAck(ConnAck),

	/// Ref: 3.1 CONNECT – Client requests a connection to a Server
	Connect(Connect),

	/// Ref: 3.14 DISCONNECT - Disconnect notification
	Disconnect(Disconnect),

	/// Ref: 3.12 PINGREQ – PING request
	PingReq(PingReq),

	/// Ref: 3.13 PINGRESP – PING response
	PingResp(PingResp),

	/// Ref: 3.4 PUBACK – Publish acknowledgement
	PubAck(PubAck),

	/// Ref: 3.7 PUBCOMP – Publish complete (QoS 2 publish received, part 3)
	PubComp(PubComp),

	/// 3.3 PUBLISH – Publish message
	Publish(Publish),

	/// Ref: 3.5 PUBREC – Publish received (QoS 2 publish received, part 1)
	PubRec(PubRec),

	/// Ref: 3.6 PUBREL – Publish release (QoS 2 publish received, part 2)
	PubRel(PubRel),

	/// Ref: 3.9 SUBACK – Subscribe acknowledgement
	SubAck(SubAck),

	/// Ref: 3.8 SUBSCRIBE - Subscribe to topics
	Subscribe(Subscribe),

	/// Ref: 3.11 UNSUBACK – Unsubscribe acknowledgement
	UnsubAck(UnsubAck),

	/// Ref: 3.10 UNSUBSCRIBE – Unsubscribe from topics
	Unsubscribe(Unsubscribe),
}

/// Metadata about a [`Packet`]
pub(crate) trait PacketMeta: Sized {
	/// The packet type for this kind of packet
	const PACKET_TYPE: u8;

	/// Decodes this packet from the given buffer
	fn decode(flags: u8, src: bytes::BytesMut) -> Result<Self, super::DecodeError>;

	/// Encodes the variable header and payload corresponding to this packet into the given buffer.
	/// The buffer is expected to already have the packet type and body length encoded into it,
	/// and to have reserved enough space to put the bytes of this packet directly into the buffer.
	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf;
}

/// Ref: 3.15 AUTH – Authentication exchange
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auth {
}

impl PacketMeta for Auth {
	const PACKET_TYPE: u8 = 0xF0;

	fn decode(flags: u8, src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		unimplemented!();
	}

	fn encode<B>(&self, _dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		unimplemented!();
	}
}

/// Ref: 3.2 CONNACK – Acknowledge connection request
#[derive(Clone, Eq, PartialEq)]
pub struct ConnAck {
	pub session_present: bool,
	pub reason_code: super::ConnectReasonCode,

	pub assigned_client_identifier: Option<String>,
	pub authentication: Option<Authentication>,
	pub maximum_packet_size: usize,
	pub maximum_qos: QoS,
	pub reason_string: Option<String>,
	pub receive_maximum: usize,
	pub response_information: Option<String>,
	pub retain_available: bool,
	pub server_keep_alive: Option<std::time::Duration>,
	pub server_reference: Option<String>,
	pub session_expiry_interval: std::time::Duration,
	pub shared_subscription_available: bool,
	pub subscription_identifier_available: bool,
	pub topic_alias_maximum: usize,
	pub wildcard_subscription_available: bool,

	pub user_properties: Vec<(String, String)>,
}

impl std::fmt::Debug for ConnAck {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ConnAck")
			.field("session_present", &self.session_present)
			.field("reason_code", &self.reason_code)
			.field("assigned_client_identifier", &self.assigned_client_identifier)
			.field("maximum_packet_size", &self.maximum_packet_size)
			.field("maximum_qos", &self.maximum_qos)
			.field("reason_string", &self.reason_string)
			.field("receive_maximum", &self.receive_maximum)
			.field("response_information", &self.response_information)
			.field("retain_available", &self.retain_available)
			.field("server_keep_alive", &self.server_keep_alive)
			.field("server_reference", &self.server_reference)
			.field("session_expiry_interval", &self.session_expiry_interval)
			.field("shared_subscription_available", &self.shared_subscription_available)
			.field("subscription_identifier_available", &self.subscription_identifier_available)
			.field("topic_alias_maximum", &self.topic_alias_maximum)
			.field("wildcard_subscription_available", &self.wildcard_subscription_available)
			.finish()
	}
}

impl PacketMeta for ConnAck {
	const PACKET_TYPE: u8 = 0x20;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let connack_flags = src.get_u8();
		let session_present = match connack_flags {
			0x00 => false,
			0x01 => true,
			connack_flags => return Err(super::DecodeError::UnrecognizedConnAckFlags(connack_flags)),
		};

		let reason_code: super::ConnectReasonCode = src.get_u8().into();

		let mut assigned_client_identifier = None;
		let mut authentication_method = None;
		let mut authentication_data = None;
		let mut maximum_packet_size = u32::max_value() as usize;
		let mut maximum_qos = QoS::ExactlyOnce;
		let mut reason_string = None;
		let mut receive_maximum = usize::from(u16::max_value());
		let mut response_information = None;
		let mut retain_available = true;
		let mut server_keep_alive = None;
		let mut server_reference = None;
		let mut session_expiry_interval = std::time::Duration::from_secs(0);
		let mut shared_subscription_available = true;
		let mut subscription_identifier_available = true;
		let mut topic_alias_maximum = 0;
		let mut wildcard_subscription_available = true;

		let (properties, user_properties) = decode_properties(&mut src)?;

		for property in properties {
			match property {
				Property::AssignedClientIdentifier(assigned_client_identifier_) => assigned_client_identifier = Some(assigned_client_identifier_),
				Property::AuthenticationMethod(authentication_method_) => authentication_method = Some(authentication_method_),
				Property::AuthenticationData(authentication_data_) => authentication_data = Some(authentication_data_),
				Property::MaximumPacketSize(maximum_packet_size_) => maximum_packet_size = maximum_packet_size_,
				Property::MaximumQoS(maximum_qos_) => maximum_qos = maximum_qos_,
				Property::ReasonString(reason_string_) => reason_string = Some(reason_string_),
				Property::ReceiveMaximum(receive_maximum_) => receive_maximum = receive_maximum_,
				Property::ResponseInformation(response_information_) => response_information = Some(response_information_),
				Property::RetainAvailable(retain_available_) => retain_available = retain_available_,
				Property::ServerKeepAlive(server_keep_alive_) => server_keep_alive = Some(server_keep_alive_),
				Property::ServerReference(server_reference_) => server_reference = Some(server_reference_),
				Property::SessionExpiryInterval(session_expiry_interval_) => session_expiry_interval = session_expiry_interval_,
				Property::SharedSubscriptionAvailable(shared_subscription_available_) => shared_subscription_available = shared_subscription_available_,
				Property::SubscriptionIdentifierAvailable(subscription_identifier_available_) => subscription_identifier_available = subscription_identifier_available_,
				Property::TopicAliasMaximum(topic_alias_maximum_) => topic_alias_maximum = topic_alias_maximum_,
				Property::WildcardSubscriptionAvailable(wildcard_subscription_available_) => wildcard_subscription_available = wildcard_subscription_available_,

				property => return Err(super::DecodeError::UnexpectedProperty(property)),
			}
		}

		let authentication = Authentication::new(authentication_method, authentication_data)?;

		Ok(ConnAck {
			session_present,
			reason_code,

			assigned_client_identifier,
			authentication,
			maximum_packet_size,
			maximum_qos,
			reason_string,
			receive_maximum,
			response_information,
			retain_available,
			server_keep_alive,
			server_reference,
			session_expiry_interval,
			shared_subscription_available,
			subscription_identifier_available,
			topic_alias_maximum,
			wildcard_subscription_available,

			user_properties,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let ConnAck { session_present, reason_code, .. } = self; // TODO
		if *session_present {
			dst.put_u8_bytes(0x01);
		}
		else {
			dst.put_u8_bytes(0x00);
		}

		dst.put_u8_bytes((*reason_code).into());

		// TODO: encode_properties

		Ok(())
	}
}

/// Ref: 3.1 CONNECT – Client requests a connection to a Server
#[derive(Clone, Eq, PartialEq)]
pub struct Connect {
	pub username: Option<String>,
	pub password: Option<String>,
	pub will: Option<Publication>,
	pub client_id: super::ClientId,
	pub keep_alive: std::time::Duration,

	pub authentication: Option<Authentication>,
	pub maximum_packet_size: usize,
	pub receive_maximum: usize,
	pub request_problem_information: Option<bool>,
	pub request_response_information: Option<bool>,
	pub session_expiry_interval: std::time::Duration,
	pub topic_alias_maximum: usize,

	pub user_properties: Vec<(String, String)>,
}

impl std::fmt::Debug for Connect {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Connect")
			.field("username", &self.username)
			.field("will", &self.will)
			.field("client_id", &self.client_id)
			.field("keep_alive", &self.keep_alive)
			.field("maximum_packet_size", &self.maximum_packet_size)
			.field("receive_maximum", &self.receive_maximum)
			.field("request_problem_information", &self.request_problem_information)
			.field("request_response_information", &self.request_response_information)
			.field("session_expiry_interval", &self.session_expiry_interval)
			.field("topic_alias_maximum", &self.topic_alias_maximum)
			.finish()
	}
}

impl PacketMeta for Connect {
	const PACKET_TYPE: u8 = 0x10;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let protocol_name = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;
		if protocol_name != "MQTT" {
			return Err(super::DecodeError::UnrecognizedProtocolName(protocol_name));
		}

		let protocol_level = src.try_get_u8()?;
		if protocol_level != 0x04 {
			return Err(super::DecodeError::UnrecognizedProtocolLevel(protocol_level));
		}

		let connect_flags = src.try_get_u8()?;
		if connect_flags & 0x01 != 0 {
			return Err(super::DecodeError::ConnectReservedSet);
		}

		let keep_alive = std::time::Duration::from_secs(u64::from(src.try_get_u16_be()?));

		let mut authentication_method = None;
		let mut authentication_data = None;
		let mut maximum_packet_size = u32::max_value() as usize;
		let mut receive_maximum = usize::from(u16::max_value());
		let mut request_problem_information = None;
		let mut request_response_information = None;
		let mut session_expiry_interval = std::time::Duration::from_secs(0);
		let mut topic_alias_maximum = 0;

		let (properties, user_properties) = decode_properties(&mut src)?;

		for property in properties {
			match property {
				Property::AuthenticationMethod(authentication_method_) => authentication_method = Some(authentication_method_),
				Property::AuthenticationData(authentication_data_) => authentication_data = Some(authentication_data_),
				Property::MaximumPacketSize(maximum_packet_size_) => maximum_packet_size = maximum_packet_size_,
				Property::ReceiveMaximum(receive_maximum_) => receive_maximum = receive_maximum_,
				Property::RequestProblemInformation(request_problem_information_) => request_problem_information = Some(request_problem_information_),
				Property::RequestResponseInformation(request_response_information_) => request_response_information = Some(request_response_information_),
				Property::SessionExpiryInterval(session_expiry_interval_) => session_expiry_interval = session_expiry_interval_,
				Property::TopicAliasMaximum(topic_alias_maximum_) => topic_alias_maximum = topic_alias_maximum_,

				property => return Err(super::DecodeError::UnexpectedProperty(property)),
			}
		}

		let authentication = Authentication::new(authentication_method, authentication_data)?;

		let client_id = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;
		let client_id =
			if client_id == "" {
				super::ClientId::ServerGenerated
			}
			else if connect_flags & 0x02 == 0 {
				super::ClientId::IdWithExistingSession(client_id)
			}
			else {
				super::ClientId::IdWithCleanSession(client_id)
			};

		let will =
			if connect_flags & 0x04 == 0 {
				None
			}
			else {
				let mut content_type = None;
				let mut correlation_data = None;
				let mut message_expiry_interval = None;
				let mut payload_format = PayloadFormat::Bytes;
				let mut response_topic = None;
				let mut will_delay_interval = std::time::Duration::from_secs(0);

				let (properties, user_properties) = decode_properties(&mut src)?;

				for property in properties {
					match property {
						Property::ContentType(content_type_) => content_type = Some(content_type_),
						Property::CorrelationData(correlation_data_) => correlation_data = Some(correlation_data_),
						Property::MessageExpiryInterval(message_expiry_interval_) => message_expiry_interval = Some(message_expiry_interval_),
						Property::PayloadFormatIndicator(payload_format_) => payload_format = payload_format_,
						Property::ResponseTopic(response_topic_) => response_topic = Some(response_topic_),
						Property::WillDelayInterval(will_delay_interval_) => will_delay_interval = will_delay_interval_,

						property => return Err(super::DecodeError::UnexpectedProperty(property)),
					}
				}

				let topic_name = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;

				let qos = match connect_flags & 0x18 {
					0x00 => QoS::AtMostOnce,
					0x08 => QoS::AtLeastOnce,
					0x10 => QoS::ExactlyOnce,
					qos => return Err(super::DecodeError::UnrecognizedQoS(qos >> 3)),
				};

				let retain = connect_flags & 0x20 != 0;

				let payload_len = usize::from(src.try_get_u16_be()?);
				if src.len() < payload_len {
					return Err(super::DecodeError::IncompletePacket);
				}
				let payload = src.split_to(payload_len).freeze();

				Some(Publication {
					topic_name,
					qos,
					retain,
					payload,

					content_type,
					correlation_data,
					message_expiry_interval,
					payload_format,
					response_topic,
					will_delay_interval,

					user_properties,
				})
			};

		let username =
			if connect_flags & 0x80 == 0 {
				None
			}
			else {
				Some(super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?)
			};

		let password =
			if connect_flags & 0x40 == 0 {
				None
			}
			else {
				Some(super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?)
			};

		Ok(Connect {
			username,
			password,
			will,
			client_id,
			keep_alive,

			authentication,
			maximum_packet_size,
			receive_maximum,
			request_problem_information,
			request_response_information,
			session_expiry_interval,
			topic_alias_maximum,

			user_properties,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let Connect { username, password, will, client_id, keep_alive, .. } = self; // TODO

		super::encode_utf8_str("MQTT", dst)?;

		dst.put_u8_bytes(0x05_u8);

		{
			let mut connect_flags = 0x00_u8;
			if username.is_some() {
				connect_flags |= 0x80;
			}
			if password.is_some() {
				connect_flags |= 0x40;
			}
			if let Some(will) = &will {
				if will.retain {
					connect_flags |= 0x20;
				}
				connect_flags |= match will.qos {
					QoS::AtMostOnce => 0x00,
					QoS::AtLeastOnce => 0x08,
					QoS::ExactlyOnce => 0x10,
				};
				connect_flags |= 0x04;
			}
			match client_id {
				super::ClientId::ServerGenerated |
				super::ClientId::IdWithCleanSession(_) => connect_flags |= 0x02,
				super::ClientId::IdWithExistingSession(_) => (),
			}
			dst.put_u8_bytes(connect_flags);
		}

		dst.put_u16_be_bytes(keep_alive.as_secs().try_into().map_err(|_| super::EncodeError::KeepAliveTooHigh(*keep_alive))?);

		let mut properties = vec![
			Property::MaximumPacketSize(self.maximum_packet_size),
			Property::ReceiveMaximum(self.receive_maximum),
			Property::SessionExpiryInterval(self.session_expiry_interval),
			Property::TopicAliasMaximum(self.topic_alias_maximum),
		];
		if let Some(authentication) = &self.authentication {
			properties.push(Property::AuthenticationMethod(authentication.method.clone()));
			if let Some(authentication_data) = &authentication.data {
				properties.push(Property::AuthenticationData(authentication_data.clone()));
			}
		}
		if let Some(request_problem_information) = self.request_problem_information {
			properties.push(Property::RequestProblemInformation(request_problem_information));
		}
		if let Some(request_response_information) = self.request_response_information {
			properties.push(Property::RequestResponseInformation(request_response_information));
		}

		encode_properties(&properties, &self.user_properties, dst)?;

		match client_id {
			super::ClientId::ServerGenerated => super::encode_utf8_str("", dst)?,
			super::ClientId::IdWithCleanSession(id) |
			super::ClientId::IdWithExistingSession(id) => super::encode_utf8_str(id, dst)?,
		}

		if let Some(will) = will {
			super::encode_utf8_str(&will.topic_name, dst)?;

			let will_len = will.payload.len();
			dst.put_u16_be_bytes(will_len.try_into().map_err(|_| super::EncodeError::WillTooLarge(will_len))?);

			dst.put_slice_bytes(&will.payload);
		}

		if let Some(username) = username {
			super::encode_utf8_str(username, dst)?;
		}

		if let Some(password) = password {
			super::encode_utf8_str(password, dst)?;
		}

		Ok(())
	}
}

/// Ref: 3.14 DISCONNECT - Disconnect notification
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disconnect;

impl PacketMeta for Disconnect {
	const PACKET_TYPE: u8 = 0xE0;

	fn decode(flags: u8, src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || !src.is_empty() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		Ok(Disconnect)
	}

	fn encode<B>(&self, _: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		Ok(())
	}
}

/// Ref: 3.12 PINGREQ – PING request
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingReq;

impl PacketMeta for PingReq {
	const PACKET_TYPE: u8 = 0xC0;

	fn decode(flags: u8, src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || !src.is_empty() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		Ok(PingReq)
	}

	fn encode<B>(&self, _: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		Ok(())
	}
}

/// Ref: 3.13 PINGRESP – PING response
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingResp;

impl PacketMeta for PingResp {
	const PACKET_TYPE: u8 = 0xD0;

	fn decode(flags: u8, src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || !src.is_empty() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		Ok(PingResp)
	}

	fn encode<B>(&self, _: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		Ok(())
	}
}

/// Ref: 3.4 PUBACK – Publish acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubAck {
	pub packet_identifier: super::PacketIdentifier,
}

impl PacketMeta for PubAck {
	const PACKET_TYPE: u8 = 0x40;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || src.len() != std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		Ok(PubAck {
			packet_identifier,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let PubAck { packet_identifier } = self;
		dst.put_packet_identifier_bytes(*packet_identifier);
		Ok(())
	}
}

#[allow(clippy::doc_markdown)]
/// Ref: 3.7 PUBCOMP – Publish complete (QoS 2 publish received, part 3)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubComp {
	pub packet_identifier: super::PacketIdentifier,
}

impl PacketMeta for PubComp {
	const PACKET_TYPE: u8 = 0x70;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || src.len() != std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		Ok(PubComp {
			packet_identifier,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let PubComp { packet_identifier } = self;
		dst.put_packet_identifier_bytes(*packet_identifier);
		Ok(())
	}
}

/// 3.3 PUBLISH – Publish message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publish {
	pub packet_identifier_dup_qos: PacketIdentifierDupQoS,
	pub retain: bool,
	pub topic_name: String,
	pub payload: bytes::Bytes,
}

impl PacketMeta for Publish {
	const PACKET_TYPE: u8 = 0x30;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		let dup = (flags & 0x08) != 0;
		let retain = (flags & 0x01) != 0;

		let topic_name = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;

		let packet_identifier_dup_qos = match (flags & 0x06) >> 1 {
			0x00 if dup => return Err(super::DecodeError::PublishDupAtMostOnce),

			0x00 => PacketIdentifierDupQoS::AtMostOnce,

			0x01 => {
				let packet_identifier = src.try_get_packet_identifier()?;
				PacketIdentifierDupQoS::AtLeastOnce(packet_identifier, dup)
			},

			0x02 => {
				let packet_identifier = src.try_get_packet_identifier()?;
				PacketIdentifierDupQoS::ExactlyOnce(packet_identifier, dup)
			},

			qos => return Err(super::DecodeError::UnrecognizedQoS(qos)),
		};

		let payload = src.freeze();

		Ok(Publish {
			packet_identifier_dup_qos,
			retain,
			topic_name,
			payload,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		#[allow(clippy::unneeded_field_pattern)]
		let Publish { packet_identifier_dup_qos, retain: _, topic_name, payload } = self;

		super::encode_utf8_str(topic_name, dst)?;

		match packet_identifier_dup_qos {
			PacketIdentifierDupQoS::AtMostOnce => (),
			PacketIdentifierDupQoS::AtLeastOnce(packet_identifier, _) |
			PacketIdentifierDupQoS::ExactlyOnce(packet_identifier, _) =>
				dst.put_packet_identifier_bytes(*packet_identifier),
		}

		dst.put_slice_bytes(&payload);

		Ok(())
	}
}

#[allow(clippy::doc_markdown)]
/// Ref: 3.5 PUBREC – Publish received (QoS 2 publish received, part 1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubRec {
	pub packet_identifier: super::PacketIdentifier,
}

impl PacketMeta for PubRec {
	const PACKET_TYPE: u8 = 0x50;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || src.len() != std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		Ok(PubRec {
			packet_identifier,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let PubRec { packet_identifier } = self;
		dst.put_packet_identifier_bytes(*packet_identifier);
		Ok(())
	}
}

#[allow(clippy::doc_markdown)]
/// Ref: 3.6 PUBREL – Publish release (QoS 2 publish received, part 2)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubRel {
	pub packet_identifier: super::PacketIdentifier,
}

impl PacketMeta for PubRel {
	const PACKET_TYPE: u8 = 0x60;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 2 || src.len() != std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		Ok(PubRel {
			packet_identifier,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let PubRel { packet_identifier } = self;
		dst.put_packet_identifier_bytes(*packet_identifier);
		Ok(())
	}
}

/// Ref: 3.9 SUBACK – Subscribe acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubAck {
	pub packet_identifier: super::PacketIdentifier,
	pub qos: Vec<SubAckQos>,
}

impl PacketMeta for SubAck {
	const PACKET_TYPE: u8 = 0x90;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || src.len() < std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		let qos: Result<Vec<_>, _> = src.into_buf().iter().map(|qos| match qos {
			0x00 => Ok(SubAckQos::Success(QoS::AtMostOnce)),
			0x01 => Ok(SubAckQos::Success(QoS::AtLeastOnce)),
			0x02 => Ok(SubAckQos::Success(QoS::ExactlyOnce)),
			0x80 => Ok(SubAckQos::Failure),
			qos => Err(super::DecodeError::UnrecognizedQoS(qos)),
		}).collect();
		let qos = qos?;

		if qos.is_empty() {
			return Err(super::DecodeError::NoTopics);
		}

		Ok(SubAck {
			packet_identifier,
			qos,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let SubAck { packet_identifier, qos } = self;

		dst.put_packet_identifier_bytes(*packet_identifier);

		for &qos in qos {
			dst.put_u8_bytes(qos.into());
		}

		Ok(())
	}
}

/// Ref: 3.8 SUBSCRIBE - Subscribe to topics
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subscribe {
	pub packet_identifier: super::PacketIdentifier,
	pub subscribe_to: Vec<SubscribeTo>,
}

impl PacketMeta for Subscribe {
	const PACKET_TYPE: u8 = 0x80;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 2 || src.len() < std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		let mut subscribe_to = vec![];

		while !src.is_empty() {
			let topic_filter = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;
			let qos = match src.try_get_u8()? {
				0x00 => QoS::AtMostOnce,
				0x01 => QoS::AtLeastOnce,
				0x02 => QoS::ExactlyOnce,
				qos => return Err(super::DecodeError::UnrecognizedQoS(qos)),
			};
			subscribe_to.push(SubscribeTo { topic_filter, qos });
		}

		if subscribe_to.is_empty() {
			return Err(super::DecodeError::NoTopics);
		}

		Ok(Subscribe {
			packet_identifier,
			subscribe_to,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let Subscribe { packet_identifier, subscribe_to } = self;

		dst.put_packet_identifier_bytes(*packet_identifier);

		for SubscribeTo { topic_filter, qos } in subscribe_to {
			super::encode_utf8_str(topic_filter, dst)?;
			dst.put_u8_bytes((*qos).into());
		}

		Ok(())
	}
}

/// Ref: 3.11 UNSUBACK – Unsubscribe acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsubAck {
	pub packet_identifier: super::PacketIdentifier,
}

impl PacketMeta for UnsubAck {
	const PACKET_TYPE: u8 = 0xB0;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 0 || src.len() != std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		Ok(UnsubAck {
			packet_identifier,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let UnsubAck { packet_identifier } = self;
		dst.put_packet_identifier_bytes(*packet_identifier);
		Ok(())
	}
}

/// Ref: 3.10 UNSUBSCRIBE – Unsubscribe from topics
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unsubscribe {
	pub packet_identifier: super::PacketIdentifier,
	pub unsubscribe_from: Vec<String>,
}

impl PacketMeta for Unsubscribe {
	const PACKET_TYPE: u8 = 0xA0;

	fn decode(flags: u8, mut src: bytes::BytesMut) -> Result<Self, super::DecodeError> {
		if flags != 2 || src.len() < std::mem::size_of::<u16>() {
			return Err(super::DecodeError::UnrecognizedPacket { packet_type: Self::PACKET_TYPE, flags, remaining_length: src.len() });
		}

		let packet_identifier = src.get_packet_identifier()?;

		let mut unsubscribe_from = vec![];

		while !src.is_empty() {
			unsubscribe_from.push(super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?);
		}

		if unsubscribe_from.is_empty() {
			return Err(super::DecodeError::NoTopics);
		}

		Ok(Unsubscribe {
			packet_identifier,
			unsubscribe_from,
		})
	}

	fn encode<B>(&self, dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
		let Unsubscribe { packet_identifier, unsubscribe_from } = self;

		dst.put_packet_identifier_bytes(*packet_identifier);

		for unsubscribe_from in unsubscribe_from {
			super::encode_utf8_str(unsubscribe_from, dst)?;
		}

		Ok(())
	}
}

#[allow(clippy::doc_markdown)]
/// A combination of the packet identifier, dup flag and QoS that only allows valid combinations of these three properties.
/// Used in [`Packet::Publish`]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketIdentifierDupQoS {
	AtMostOnce,
	AtLeastOnce(super::PacketIdentifier, bool),
	ExactlyOnce(super::PacketIdentifier, bool),
}

/// A subscription request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeTo {
	pub topic_filter: String,
	pub qos: QoS,
}

/// The level of reliability for a publication
///
/// Ref: 4.3 Quality of Service levels and protocol flows
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QoS {
	AtMostOnce,
	AtLeastOnce,
	ExactlyOnce,
}

impl From<QoS> for u8 {
	fn from(qos: QoS) -> Self {
		match qos {
			QoS::AtMostOnce => 0x00,
			QoS::AtLeastOnce => 0x01,
			QoS::ExactlyOnce => 0x02,
		}
	}
}

#[allow(clippy::doc_markdown)]
/// QoS returned in a SUBACK packet. Either one of the [`QoS`] values, or an error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubAckQos {
	Success(QoS),
	Failure,
}

impl From<SubAckQos> for u8 {
	fn from(qos: SubAckQos) -> Self {
		match qos {
			SubAckQos::Success(qos) => qos.into(),
			SubAckQos::Failure => 0x80,
		}
	}
}

/// A message that can be published to the server
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
	pub topic_name: String,
	pub qos: QoS,
	pub retain: bool,
	pub payload: bytes::Bytes,

	pub content_type: Option<String>,
	pub correlation_data: Option<bytes::BytesMut>,
	pub message_expiry_interval: Option<std::time::Duration>,
	pub payload_format: PayloadFormat,
	pub response_topic: Option<String>,
	pub will_delay_interval: std::time::Duration,

	pub user_properties: Vec<(String, String)>,
}

/// A tokio codec that encodes and decodes MQTT packets.
///
/// Ref: 2 MQTT Control Packet format
#[derive(Debug, Default)]
pub struct PacketCodec {
	decoder_state: PacketDecoderState,
}

#[derive(Debug)]
pub enum PacketDecoderState {
	Empty,
	HaveFirstByte { first_byte: u8, remaining_length: super::VariableByteIntegerDecoder },
	HaveFixedHeader { first_byte: u8, remaining_length: usize },
}

impl Default for PacketDecoderState {
	fn default() -> Self {
		PacketDecoderState::Empty
	}
}

impl tokio_codec::Decoder for PacketCodec {
	type Item = Packet;
	type Error = super::DecodeError;

	fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		let (first_byte, src) = loop {
			match &mut self.decoder_state {
				PacketDecoderState::Empty => {
					let first_byte = match src.try_get_u8() {
						Ok(first_byte) => first_byte,
						Err(_) => return Ok(None),
					};
					self.decoder_state = PacketDecoderState::HaveFirstByte { first_byte, remaining_length: Default::default() };
				},

				PacketDecoderState::HaveFirstByte { first_byte, remaining_length } => match remaining_length.decode(src)? {
					Some(remaining_length) => self.decoder_state = PacketDecoderState::HaveFixedHeader { first_byte: *first_byte, remaining_length },
					None => return Ok(None),
				},

				PacketDecoderState::HaveFixedHeader { first_byte, remaining_length } => {
					if src.len() < *remaining_length {
						return Ok(None);
					}

					let first_byte = *first_byte;
					let src = src.split_to(*remaining_length);
					self.decoder_state = PacketDecoderState::Empty;
					break (first_byte, src);
				},
			}
		};

		let packet_type = first_byte & 0xF0;
		let flags = first_byte & 0x0F;
		match packet_type {
			Auth::PACKET_TYPE => Ok(Some(Packet::Auth(Auth::decode(flags, src)?))),
			ConnAck::PACKET_TYPE => Ok(Some(Packet::ConnAck(ConnAck::decode(flags, src)?))),
			Connect::PACKET_TYPE => Ok(Some(Packet::Connect(Connect::decode(flags, src)?))),
			Disconnect::PACKET_TYPE => Ok(Some(Packet::Disconnect(Disconnect::decode(flags, src)?))),
			PingReq::PACKET_TYPE => Ok(Some(Packet::PingReq(PingReq::decode(flags, src)?))),
			PingResp::PACKET_TYPE => Ok(Some(Packet::PingResp(PingResp::decode(flags, src)?))),
			PubAck::PACKET_TYPE => Ok(Some(Packet::PubAck(PubAck::decode(flags, src)?))),
			PubComp::PACKET_TYPE => Ok(Some(Packet::PubComp(PubComp::decode(flags, src)?))),
			Publish::PACKET_TYPE => Ok(Some(Packet::Publish(Publish::decode(flags, src)?))),
			PubRec::PACKET_TYPE => Ok(Some(Packet::PubRec(PubRec::decode(flags, src)?))),
			PubRel::PACKET_TYPE => Ok(Some(Packet::PubRel(PubRel::decode(flags, src)?))),
			SubAck::PACKET_TYPE => Ok(Some(Packet::SubAck(SubAck::decode(flags, src)?))),
			Subscribe::PACKET_TYPE => Ok(Some(Packet::Subscribe(Subscribe::decode(flags, src)?))),
			UnsubAck::PACKET_TYPE => Ok(Some(Packet::UnsubAck(UnsubAck::decode(flags, src)?))),
			Unsubscribe::PACKET_TYPE => Ok(Some(Packet::Unsubscribe(Unsubscribe::decode(flags, src)?))),
			packet_type => Err(super::DecodeError::UnrecognizedPacket { packet_type, flags, remaining_length: src.len() }),
		}
	}
}

impl tokio_codec::Encoder for PacketCodec {
	type Item = Packet;
	type Error = super::EncodeError;

	fn encode(&mut self, item: Self::Item, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
		dst.reserve(std::mem::size_of::<u8>() + 4 * std::mem::size_of::<u8>());

		match &item {
			Packet::Auth(packet) => encode_packet(packet, 0, dst),
			Packet::ConnAck(packet) => encode_packet(packet, 0, dst),
			Packet::Connect(packet) => encode_packet(packet, 0, dst),
			Packet::Disconnect(packet) => encode_packet(packet, 0, dst),
			Packet::PingReq(packet) => encode_packet(packet, 0, dst),
			Packet::PingResp(packet) => encode_packet(packet, 0, dst),
			Packet::PubAck(packet) => encode_packet(packet, 0, dst),
			Packet::PubComp(packet) => encode_packet(packet, 0, dst),
			Packet::Publish(packet) => {
				let mut flags = match packet.packet_identifier_dup_qos {
					PacketIdentifierDupQoS::AtMostOnce => 0x00,
					PacketIdentifierDupQoS::AtLeastOnce(_, true) => 0x0A,
					PacketIdentifierDupQoS::AtLeastOnce(_, false) => 0x02,
					PacketIdentifierDupQoS::ExactlyOnce(_, true) => 0x0C,
					PacketIdentifierDupQoS::ExactlyOnce(_, false) => 0x04,
				};
				if packet.retain {
					flags |= 0x01;
				};
				encode_packet(packet, flags, dst)
			},
			Packet::PubRec(packet) => encode_packet(packet, 0, dst),
			Packet::PubRel(packet) => encode_packet(packet, 0x02, dst),
			Packet::SubAck(packet) => encode_packet(packet, 0, dst),
			Packet::Subscribe(packet) => encode_packet(packet, 0x02, dst),
			Packet::UnsubAck(packet) => encode_packet(packet, 0, dst),
			Packet::Unsubscribe(packet) => encode_packet(packet, 0x02, dst),
		}
	}
}

fn encode_packet<P>(packet: &P, flags: u8, dst: &mut bytes::BytesMut) -> Result<(), super::EncodeError> where P: PacketMeta {
	let mut counter = super::ByteCounter::new();
	packet.encode(&mut counter)?;
	let body_len = counter.0;

	dst.reserve(
		std::mem::size_of::<u8>() + // packet type
		4 * std::mem::size_of::<u8>() + // remaining length
		body_len);

	dst.put_u8(<P as PacketMeta>::PACKET_TYPE | flags);
	super::encode_variable_byte_integer(body_len, dst)?;
	packet.encode(dst)?;

	Ok(())
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Property {
	AssignedClientIdentifier(String),
	AuthenticationData(bytes::BytesMut),
	AuthenticationMethod(String),
	ContentType(String),
	CorrelationData(bytes::BytesMut),
	MaximumPacketSize(usize),
	MaximumQoS(QoS),
	MessageExpiryInterval(std::time::Duration),
	PayloadFormatIndicator(PayloadFormat),
	ReasonString(String),
	ReceiveMaximum(usize),
	RequestProblemInformation(bool),
	RequestResponseInformation(bool),
	ResponseInformation(String),
	ResponseTopic(String),
	RetainAvailable(bool),
	ServerKeepAlive(std::time::Duration),
	ServerReference(String), // TODO: Newtype?
	SessionExpiryInterval(std::time::Duration),
	SharedSubscriptionAvailable(bool),
	SubscriptionIdentifier(usize),
	SubscriptionIdentifierAvailable(bool),
	TopicAlias(u16), // TODO: Newtype?
	TopicAliasMaximum(usize),
	WildcardSubscriptionAvailable(bool),
	WillDelayInterval(std::time::Duration),
}

#[derive(Clone, Eq, PartialEq)]
pub struct Authentication {
	method: String,
	data: Option<bytes::BytesMut>,
}

impl Authentication {
	fn new(method: Option<String>, data: Option<bytes::BytesMut>) -> Result<Option<Self>, super::DecodeError> {
		match (method, data) {
			(Some(method), data) => Ok(Some(Authentication { method, data })),
			(None, Some(_)) => Err(super::DecodeError::ConnectAuthenticationDataWithoutAuthenticationMethod),
			(None, None) => Ok(None),
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PayloadFormat {
	Bytes,
	Utf8,
}

fn decode_properties(src: &mut bytes::BytesMut) -> Result<
	(impl Iterator<Item = Property>, Vec<(String, String)>),
	super::DecodeError,
> {
	let property_length = super::VariableByteIntegerDecoder::default().decode(src)?.ok_or(super::DecodeError::IncompletePacket)?;
	if src.len() < property_length {
		return Err(super::DecodeError::IncompletePacket);
	}
	let mut src = src.split_to(usize::from(property_length));

	let mut properties: std::collections::HashMap<_, _> = Default::default();
	let mut user_properties = vec![];

	while !src.is_empty() {
		let id = super::VariableByteIntegerDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;
		let property = match id {
			0x01 => {
				let payload_format = match src.try_get_u8()? {
					0 => PayloadFormat::Bytes,
					1 => PayloadFormat::Utf8,
					payload_format => return Err(super::DecodeError::MalformedProperty("payload format", Box::new(payload_format))),
				};
				Property::PayloadFormatIndicator(payload_format)
			},

			0x02 => {
				let message_expiry_interval = src.try_get_u32_be()?;
				let message_expiry_interval = std::time::Duration::from_secs(u64::from(message_expiry_interval));
				Property::MessageExpiryInterval(message_expiry_interval)
			},

			0x03 => {
				let content_type = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?.into();
				Property::ContentType(content_type)
			},

			0x08 => {
				let response_topic = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?.into();
				Property::ResponseTopic(response_topic)
			},

			0x09 => {
				let correlation_data_length = usize::from(src.try_get_u16_be()?);
				if src.len() < correlation_data_length {
					return Err(super::DecodeError::IncompletePacket);
				}
				let correlation_data = src.split_to(correlation_data_length);
				Property::CorrelationData(correlation_data)
			},

			0x0B => {
				let subscription_identifier = super::VariableByteIntegerDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;
				Property::SubscriptionIdentifier(subscription_identifier)
			},

			0x11 => {
				let session_expiry_interval = src.try_get_u32_be()?;
				let session_expiry_interval = std::time::Duration::from_secs(u64::from(session_expiry_interval));
				Property::SessionExpiryInterval(session_expiry_interval)
			},

			0x12 => {
				let assigned_client_identifier = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?.into();
				Property::AssignedClientIdentifier(assigned_client_identifier)
			},

			0x13 => {
				let server_keep_alive = src.try_get_u32_be()?;
				let server_keep_alive = std::time::Duration::from_secs(u64::from(server_keep_alive));
				Property::ServerKeepAlive(server_keep_alive)
			},

			0x15 => {
				let authentication_method = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?.into();
				Property::AuthenticationMethod(authentication_method)
			},

			0x16 => {
				let authentication_data_length = usize::from(src.try_get_u16_be()?);
				if src.len() < authentication_data_length {
					return Err(super::DecodeError::IncompletePacket);
				}
				let authentication_data = src.split_to(authentication_data_length);
				Property::AuthenticationData(authentication_data)
			},

			0x17 => {
				let request_problem_information = match src.try_get_u8()? {
					0x00 => false,
					0x01 => true,
					request_problem_information =>
						return Err(super::DecodeError::MalformedProperty("request problem information", Box::new(request_problem_information))),
				};
				Property::RequestProblemInformation(request_problem_information)
			},

			0x18 => {
				let will_delay_interval = src.try_get_u32_be()?;
				let will_delay_interval = std::time::Duration::from_secs(u64::from(will_delay_interval));
				Property::WillDelayInterval(will_delay_interval)
			},

			0x19 => {
				let request_response_information = match src.try_get_u8()? {
					0x00 => false,
					0x01 => true,
					request_response_information =>
						return Err(super::DecodeError::MalformedProperty("request response information", Box::new(request_response_information))),
				};
				Property::RequestResponseInformation(request_response_information)
			},

			0x1A => {
				let response_information = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?.into();
				Property::ResponseInformation(response_information)
			},

			0x1C => {
				let server_reference = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?.into();
				Property::ServerReference(server_reference)
			},

			0x1F => {
				let reason_string = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?.into();
				Property::ReasonString(reason_string)
			},

			0x21 => {
				let receive_maximum = usize::from(src.try_get_u16_be()?);
				if receive_maximum == 0 {
					unimplemented!(); // TODO
				}
				Property::ReceiveMaximum(receive_maximum)
			},

			0x22 => {
				let topic_alias_maximum = usize::from(src.try_get_u16_be()?);
				Property::TopicAliasMaximum(topic_alias_maximum)
			},

			0x23 => {
				let topic_alias = src.try_get_u16_be()?;
				Property::TopicAlias(topic_alias)
			},

			0x24 => {
				let qos = match src.try_get_u8()? {
					0x00 => QoS::AtMostOnce,
					0x01 => QoS::AtLeastOnce,
					0x02 => QoS::ExactlyOnce,
					qos => return Err(super::DecodeError::UnrecognizedQoS(qos)),
				};
				Property::MaximumQoS(qos)
			},

			0x25 => {
				let retain_available = match src.try_get_u8()? {
					0x00 => false,
					0x01 => true,
					retain_available =>
						return Err(super::DecodeError::MalformedProperty("retail available", Box::new(retain_available))),
				};
				Property::RetainAvailable(retain_available)
			},

			0x26 => {
				let key = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;
				let value = super::Utf8StringDecoder::default().decode(&mut src)?.ok_or(super::DecodeError::IncompletePacket)?;
				user_properties.push((key, value));
				continue;
			},

			0x27 => {
				let maximum_packet_size = src.try_get_u32_be()? as usize;
				Property::MaximumPacketSize(maximum_packet_size)
			},

			0x28 => {
				let wildcard_subscription_available = match src.try_get_u8()? {
					0x00 => false,
					0x01 => true,
					wildcard_subscription_available =>
						return Err(super::DecodeError::MalformedProperty("wildcard subscription available", Box::new(wildcard_subscription_available))),
				};
				Property::WildcardSubscriptionAvailable(wildcard_subscription_available)
			},

			0x29 => {
				let subscription_identifier_available = match src.try_get_u8()? {
					0x00 => false,
					0x01 => true,
					subscription_identifier_available =>
						return Err(super::DecodeError::MalformedProperty("subscription identifier available", Box::new(subscription_identifier_available))),
				};
				Property::SubscriptionIdentifierAvailable(subscription_identifier_available)
			},

			0x2A => {
				let shared_subscription_available = match src.try_get_u8()? {
					0x00 => false,
					0x01 => true,
					shared_subscription_available =>
						return Err(super::DecodeError::MalformedProperty("shared subscription available", Box::new(shared_subscription_available))),
				};
				Property::SharedSubscriptionAvailable(shared_subscription_available)
			},

			id => return Err(super::DecodeError::UnrecognizedProperty(id)),
		};

		match properties.entry(std::mem::discriminant(&property)) {
			std::collections::hash_map::Entry::Occupied(entry) => {
				let existing_property = entry.remove();
				return Err(super::DecodeError::DuplicateProperty(existing_property, property));
			},

			std::collections::hash_map::Entry::Vacant(entry) => entry.insert(property),
		};
	}

	let properties = properties.into_iter().map(|(_, v)| v);

	Ok((properties, user_properties))
}

fn encode_properties<B>(properties: &[Property], user_properties: &[(String, String)], dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
	let mut counter = super::ByteCounter::new();
	encode_properties_inner(properties, user_properties, &mut counter)?;
	let body_len = counter.0;

	dst.reserve_bytes(
		4 * std::mem::size_of::<u8>() + // remaining length
		body_len);

	super::encode_variable_byte_integer(body_len, dst)?;
	encode_properties_inner(properties, user_properties, dst)?;

	Ok(())
}

fn encode_properties_inner<B>(properties: &[Property], user_properties: &[(String, String)], dst: &mut B) -> Result<(), super::EncodeError> where B: ByteBuf {
	for property in properties {
		match property {
			Property::AssignedClientIdentifier(assigned_client_identifier) => {
				super::encode_variable_byte_integer(0x12, dst)?;
				super::encode_utf8_str(assigned_client_identifier, dst)?;
			},

			Property::AuthenticationData(authentication_data) => {
				super::encode_variable_byte_integer(0x16, dst)?;
				dst.put_u16_be_bytes(authentication_data.len().try_into().unwrap()); // TODO
				dst.put_slice_bytes(authentication_data);
			},

			Property::AuthenticationMethod(authentication_method) => {
				super::encode_variable_byte_integer(0x15, dst)?;
				super::encode_utf8_str(authentication_method, dst)?;
			},

			Property::ContentType(content_type) => {
				super::encode_variable_byte_integer(0x03, dst)?;
				super::encode_utf8_str(content_type, dst)?;
			},

			Property::CorrelationData(correlation_data) => {
				super::encode_variable_byte_integer(0x09, dst)?;
				dst.put_u16_be_bytes(correlation_data.len().try_into().unwrap()); // TODO
				dst.put_slice_bytes(correlation_data);
			},

			Property::MaximumPacketSize(maximum_packet_size) => {
				let maximum_packet_size: u32 = (*maximum_packet_size).try_into().unwrap(); // TODO
				if maximum_packet_size != u32::max_value() {
					super::encode_variable_byte_integer(0x27, dst)?;
					dst.put_u32_be_bytes(maximum_packet_size);
				}
			},

			Property::MaximumQoS(maximum_qos) => {
				super::encode_variable_byte_integer(0x24, dst)?;
				dst.put_u8_bytes((*maximum_qos).into());
			},

			Property::MessageExpiryInterval(message_expiry_interval) => {
				super::encode_variable_byte_integer(0x02, dst)?;
				dst.put_u32_be_bytes(message_expiry_interval.as_secs().try_into().unwrap()); // TODO
			},

			Property::PayloadFormatIndicator(payload_format) =>
				match payload_format {
					PayloadFormat::Bytes => (),
					PayloadFormat::Utf8 => {
						super::encode_variable_byte_integer(0x01, dst)?;
						dst.put_u8_bytes(1);
					},
				},

			Property::ReasonString(reason_string) => {
				super::encode_variable_byte_integer(0x1F, dst)?;
				super::encode_utf8_str(reason_string, dst)?;
			},

			Property::ReceiveMaximum(receive_maximum) => {
				let receive_maximum: u16 = (*receive_maximum).try_into().unwrap(); // TODO
				if receive_maximum == 0 {
					unimplemented!(); // TODO: Err
				}
				else if receive_maximum != u16::max_value() {
					super::encode_variable_byte_integer(0x21, dst)?;
					dst.put_u16_be_bytes(receive_maximum);
				}
			},

			Property::RequestProblemInformation(request_problem_information) =>
				if !request_problem_information {
					super::encode_variable_byte_integer(0x17, dst)?;
					dst.put_u8_bytes(0);
				},

			Property::RequestResponseInformation(request_response_information) =>
				if *request_response_information {
					super::encode_variable_byte_integer(0x19, dst)?;
					dst.put_u8_bytes(1);
				},

			Property::ResponseInformation(response_information) => {
				super::encode_variable_byte_integer(0x1A, dst)?;
				super::encode_utf8_str(response_information, dst)?;
			},

			Property::ResponseTopic(response_topic) => {
				super::encode_variable_byte_integer(0x08, dst)?;
				super::encode_utf8_str(response_topic, dst)?;
			},

			Property::RetainAvailable(retain_available) =>
				if !retain_available {
					super::encode_variable_byte_integer(0x25, dst)?;
					dst.put_u8_bytes(0);
				},

			Property::ServerKeepAlive(server_keep_alive) => {
				super::encode_variable_byte_integer(0x13, dst)?;
				dst.put_u32_be_bytes(server_keep_alive.as_secs().try_into().unwrap()); // TODO
			},

			Property::ServerReference(server_reference) => {
				super::encode_variable_byte_integer(0x1C, dst)?;
				super::encode_utf8_str(server_reference, dst)?;
			},

			Property::SessionExpiryInterval(session_expiry_interval) => {
				let session_expiry_interval: u32 = session_expiry_interval.as_secs().try_into().unwrap(); // TODO
				if session_expiry_interval != 0 {
					super::encode_variable_byte_integer(0x11, dst)?;
					dst.put_u32_be_bytes(session_expiry_interval);
				}
			},

			Property::SharedSubscriptionAvailable(shared_subscription_available) =>
				if !shared_subscription_available {
					super::encode_variable_byte_integer(0x2A, dst)?;
					dst.put_u8_bytes(0);
				},

			Property::SubscriptionIdentifier(subscription_identifier) => {
				super::encode_variable_byte_integer(0x0B, dst)?;
				super::encode_variable_byte_integer(*subscription_identifier, dst)?;
			},

			Property::SubscriptionIdentifierAvailable(subscription_identifier_available) =>
				if !subscription_identifier_available {
					super::encode_variable_byte_integer(0x29, dst)?;
					dst.put_u8_bytes(0);
				},

			Property::TopicAlias(topic_alias) => {
				super::encode_variable_byte_integer(0x23, dst)?;
				dst.put_u16_be_bytes(*topic_alias);
			},

			Property::TopicAliasMaximum(topic_alias_maximum) =>
				if *topic_alias_maximum != 0 {
					super::encode_variable_byte_integer(0x22, dst)?;
					dst.put_u16_be_bytes((*topic_alias_maximum).try_into().unwrap()); // TODO
				},

			Property::WildcardSubscriptionAvailable(wildcard_subscription_available) =>
				if !wildcard_subscription_available {
					super::encode_variable_byte_integer(0x28, dst)?;
					dst.put_u8_bytes(0);
				},

			Property::WillDelayInterval(will_delay_interval) => {
				super::encode_variable_byte_integer(0x18, dst)?;
				dst.put_u32_be_bytes(will_delay_interval.as_secs().try_into().unwrap()); // TODO
			},
		}
	}

	for (key, value) in user_properties {
		dst.put_u8_bytes(0x26);
		super::encode_utf8_str(key, dst)?;
		super::encode_utf8_str(value, dst)?;
	}

	Ok(())
}
