/*!
 * This crate contains an implementation of an MQTT 3.1.1 client.
 */

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::cyclomatic_complexity,
	clippy::default_trait_access,
	clippy::large_enum_variant,
	clippy::module_name_repetitions,
	clippy::pub_enum_variant_names,
	clippy::similar_names,
	clippy::single_match_else,
	clippy::too_many_arguments,
	clippy::use_self,
)]

mod client;
pub use self::client::{
	Client,
	Error,
	Event,
	IoSource,
	PublishError,
	PublishHandle,
	ReceivedPublication,
	ShutdownError,
	ShutdownHandle,
	SubscriptionUpdateEvent,
	UpdateSubscriptionError,
	UpdateSubscriptionHandle,
};

mod logging_framed;

pub mod proto;
