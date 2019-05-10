pub(crate) fn duration_from_secs_str(s: &str) -> Result<std::time::Duration, <u64 as std::str::FromStr>::Err> {
	Ok(std::time::Duration::from_secs(s.parse()?))
}

pub(crate) fn qos_from_str(s: &str) -> Result<mqtt5::proto::QoS, String> {
	match s {
		"0" | "AtMostOnce" => Ok(mqtt5::proto::QoS::AtMostOnce),
		"1" | "AtLeastOnce" => Ok(mqtt5::proto::QoS::AtLeastOnce),
		"2" | "ExactlyOnce" => Ok(mqtt5::proto::QoS::ExactlyOnce),
		s => Err(format!("unrecognized QoS {:?}: must be one of 0, 1, 2, AtMostOnce, AtLeastOnce, ExactlyOnce", s)),
	}
}
