use std::fmt;
use std::{convert::TryFrom, str::FromStr};

use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::json;

use bitcoin::{Transaction, Txid};

use teos_common::appointment::Locator;
use teos_common::TowerId;

/// Errors related to the `registertower` command.
#[derive(Debug)]
pub enum RegisterError {
    InvalidId(String),
    InvalidHost(String),
    InvalidPort(String),
    InvalidFormat(String),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RegisterError::InvalidId(x) => write!(f, "{x}"),
            RegisterError::InvalidHost(x) => write!(f, "{x}"),
            RegisterError::InvalidPort(x) => write!(f, "{x}"),
            RegisterError::InvalidFormat(x) => write!(f, "{x}"),
        }
    }
}

/// Parameters related to the `registertower` command.
#[derive(Debug, Serialize)]
pub struct RegisterParams {
    pub tower_id: TowerId,
    pub host: Option<String>,
    pub port: Option<u16>,
}

impl RegisterParams {
    fn new(tower_id: &str, host: Option<&str>, port: Option<u64>) -> Result<Self, RegisterError> {
        let mut params = RegisterParams::from_id(tower_id)?;

        if host.is_some() {
            params = params.with_host(host.unwrap())?
        }

        if port.is_some() {
            params = params.with_port(port.unwrap())?
        }

        Ok(params)
    }

    fn from_id(tower_id: &str) -> Result<Self, RegisterError> {
        Ok(Self {
            tower_id: TowerId::from_str(tower_id)
                .map_err(|_| RegisterError::InvalidId("Invalid tower id".to_owned()))?,
            host: None,
            port: None,
        })
    }

    fn with_host(self, host: &str) -> Result<Self, RegisterError> {
        if host.is_empty() {
            Err(RegisterError::InvalidHost("hostname is empty".to_owned()))
        } else if host.contains(' ') {
            Err(RegisterError::InvalidHost(
                "hostname contains white spaces".to_owned(),
            ))
        } else {
            Ok(Self {
                host: Some(String::from(host)),
                ..self
            })
        }
    }

    fn with_port(self, port: u64) -> Result<Self, RegisterError> {
        if port > u16::MAX as u64 {
            Err(RegisterError::InvalidPort(format!(
                "port must be a 16-byte integer. Received: {port}"
            )))
        } else {
            Ok(Self {
                port: Some(port as u16),
                ..self
            })
        }
    }
}

impl TryFrom<serde_json::Value> for RegisterParams {
    type Error = RegisterError;

    // clippy-fix: We are getting more than just the first item, so this clippy check does not make sense here
    #[allow(clippy::get_first)]
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => {
                let s = s.trim();
                let mut v = s.split('@');
                let tower_id = v.next().unwrap();

                match v.next() {
                    Some(x) => {
                        let mut v = x.split(':');
                        let host = v.next();
                        let port = if let Some(p) = v.next() {
                            p.parse()
                                .map(Some)
                                .map_err(|_| RegisterError::InvalidPort(format!("Port is not a number: {p}")))?
                        } else {
                            None
                        };

                        RegisterParams::new(tower_id, host, port)
                    }
                    None => RegisterParams::from_id(tower_id),
                }
            },
            serde_json::Value::Array(mut a) => {
                let param_count = a.len();

                match param_count {
                    1 => RegisterParams::try_from(a.pop().unwrap()),
                    2 | 3 => {
                        let tower_id = a.get(0).unwrap().as_str().ok_or_else(|| RegisterError::InvalidId("tower_id must be a string".to_string()))?;
                        let host = Some(a.get(1).unwrap().as_str().ok_or_else(|| RegisterError::InvalidHost("host must be a string".to_string()))?);
                        let port = if let Some(p) = a.get(2) {
                            Some(p.as_u64().ok_or_else(|| RegisterError::InvalidPort(format!("port must be a number. Received: {p}")))?)
                        } else {
                            None
                        };

                        RegisterParams::new(tower_id, host, port)
                    }
                    _ => Err(RegisterError::InvalidFormat(format!("Unexpected request format. The request needs 1-3 parameters. Received: {param_count}"))),
                }
            },
            serde_json::Value::Object(mut m) => {
                let allowed_keys = ["tower_id", "host", "port"];
                let param_count = m.len();

                 if m.is_empty() || param_count > allowed_keys.len() {
                    Err(RegisterError::InvalidFormat(format!("Unexpected request format. The request needs 1-3 parameters. Received: {param_count}")))
                 } else if !m.contains_key(allowed_keys[0]){
                    Err(RegisterError::InvalidId(format!("{} is mandatory", allowed_keys[0])))
                 } else if !m.iter().all(|(k, _)| allowed_keys.contains(&k.as_str())) {
                    Err(RegisterError::InvalidFormat("Invalid named parameter found in request".to_owned()))
                 } else {
                    let mut params = Vec::with_capacity(allowed_keys.len());
                    for k in allowed_keys {
                        if let Some(v) = m.remove(k) {
                            params.push(v);
                        }
                    }

                    RegisterParams::try_from(json!(params))
                }
            },
            _ => Err(RegisterError::InvalidFormat(
                format!("Unexpected request format. Expected: 'tower_id[@host][:port]' or 'tower_id [host] [port]'. Received: '{value}'"),
            )),
        }
    }
}

/// Errors related to the `getappointment` command.
#[derive(Debug)]
pub enum GetAppointmentError {
    InvalidId(String),
    InvalidLocator(String),
    InvalidFormat(String),
}

impl std::fmt::Display for GetAppointmentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GetAppointmentError::InvalidId(x) => write!(f, "{x}"),
            GetAppointmentError::InvalidLocator(x) => write!(f, "{x}"),
            GetAppointmentError::InvalidFormat(x) => write!(f, "{x}"),
        }
    }
}

/// Parameters related to the `getappointment` command.
#[derive(Debug)]
pub struct GetAppointmentParams {
    pub tower_id: TowerId,
    pub locator: Locator,
}

impl TryFrom<serde_json::Value> for GetAppointmentParams {
    type Error = GetAppointmentError;

    // clippy-fix: We are getting more than just the first item, so this clippy check does not make sense here
    #[allow(clippy::get_first)]
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Array(a) => {
                let param_count = a.len();
                if param_count != 2 {
                    Err(GetAppointmentError::InvalidFormat(format!(
                        "Unexpected request format. The request needs 2 parameter. Received: {param_count}"
                    )))
                } else {
                    let tower_id = if let Some(s) = a.get(0).unwrap().as_str() {
                        TowerId::from_str(s).map_err(|_| {
                            GetAppointmentError::InvalidId("Invalid tower id".to_owned())
                        })
                    } else {
                        Err(GetAppointmentError::InvalidId(
                            "tower_id must be a hex encoded string".to_owned(),
                        ))
                    }?;

                    let locator = if let Some(s) = a.get(1).unwrap().as_str() {
                        Locator::from_hex(s).map_err(|_| {
                            GetAppointmentError::InvalidLocator("Invalid locator".to_owned())
                        })
                    } else {
                        Err(GetAppointmentError::InvalidLocator(
                            "locator must be a hex encoded string".to_owned(),
                        ))
                    }?;

                    Ok(Self { tower_id, locator })
                }
            }
            serde_json::Value::Object(mut m) => {
                let allowed_keys = ["tower_id", "locator"];

                if m.len() > allowed_keys.len() {
                    return Err(GetAppointmentError::InvalidFormat(
                        "Invalid named argument found in request".to_owned(),
                    ));
                }

                // DISCUSS: There may be a more idiomatic way of doing this
                for k in allowed_keys.iter() {
                    if !m.contains_key(*k) {
                        return Err(GetAppointmentError::InvalidFormat(format!(
                            "{k} is mandatory"
                        )));
                    }
                }

                let mut params = Vec::with_capacity(allowed_keys.len());
                for k in allowed_keys {
                    if let Some(v) = m.remove(k) {
                        params.push(v);
                    }
                }
                GetAppointmentParams::try_from(json!(params))
            }
            _ => Err(GetAppointmentError::InvalidFormat(format!(
                "Unexpected request format. Expected: tower_id locator. Received: '{value}'"
            ))),
        }
    }
}

// Errors related to `getregistrationreceipt` command
#[derive(Debug)]
pub enum GetRegistrationReceiptError {
    InvalidId(String),
    InvalidFormat(String),
}

impl std::fmt::Display for GetRegistrationReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GetRegistrationReceiptError::InvalidId(x) => write!(f, "{x}"),
            GetRegistrationReceiptError::InvalidFormat(x) => write!(f, "{x}"),
        }
    }
}

// Parameters related to the `getregistrationreceipt` command
#[derive(Debug)]
pub struct GetRegistrationReceiptParams {
    pub tower_id: TowerId,
    pub subscription_start: Option<u32>,
    pub subscription_expiry: Option<u32>,
}

impl TryFrom<serde_json::Value> for GetRegistrationReceiptParams {
    type Error = GetRegistrationReceiptError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Array(a) => {
                let param_count = a.len();
                if param_count == 2 {
                    Err(GetRegistrationReceiptError::InvalidFormat((
                        "Both ends of boundary (subscription_start and subscription_expiry) are required.").to_string()
                    ))
                } else if param_count != 1 && param_count != 3 {
                    Err(GetRegistrationReceiptError::InvalidFormat(format!(
                        "Unexpected request format. The request needs 1 or 3 parameter. Received: {param_count}"
                    )))
                } else {
                    let tower_id = if let Some(s) = a.get(0).unwrap().as_str() {
                        TowerId::from_str(s).map_err(|_| {
                            GetRegistrationReceiptError::InvalidId("Invalid tower id".to_owned())
                        })
                    } else {
                        Err(GetRegistrationReceiptError::InvalidId(
                            "tower_id must be a hex encoded string".to_owned(),
                        ))
                    }?;

                    let (subscription_start, subscription_expiry) = if let (Some(start), Some(expire)) = (a.get(1), a.get(2)){
                        let start = start.as_i64().ok_or_else(|| {
                            GetRegistrationReceiptError::InvalidFormat(
                                "Subscription_start must be a positive integer".to_owned(),
                            )
                        })?;

                        let expire = expire.as_i64().ok_or_else(|| {
                            GetRegistrationReceiptError::InvalidFormat(
                                "Subscription_expire must be a positive integer".to_owned(),
                            )
                        })?;

                        if start >= 0 && expire > start {
                            (Some(start as u32), Some(expire as u32))
                        } else {
                            return Err(GetRegistrationReceiptError::InvalidFormat(
                                "subscription_start must be a positive integer and subscription_expire must be a positive integer greater than subscription_start".to_owned(),
                            ));
                        }
                    } else {
                        (None, None)
                    };

                    Ok(
                        Self {
                            tower_id,
                            subscription_start,
                            subscription_expiry,
                        }
                    )
                }
            },
            serde_json::Value::Object(mut m) => {
                let allowed_keys = ["tower_id", "subscription_start", "subscription_expiry"];
                let param_count = m.len();

                 if m.is_empty() || param_count > allowed_keys.len() {
                    Err(GetRegistrationReceiptError::InvalidFormat(format!("Unexpected request format. The request needs 1-3 parameters. Received: {param_count}")))
                 } else if !m.contains_key(allowed_keys[0]){
                    Err(GetRegistrationReceiptError::InvalidId(format!("{} is mandatory", allowed_keys[0])))
                 } else if !m.iter().all(|(k, _)| allowed_keys.contains(&k.as_str())) {
                    Err(GetRegistrationReceiptError::InvalidFormat("Invalid named parameter found in request".to_owned()))
                 } else {
                    let mut params = Vec::with_capacity(allowed_keys.len());
                    for k in allowed_keys {
                        if let Some(v) = m.remove(k) {
                            params.push(v);
                        }
                    }

                    GetRegistrationReceiptParams::try_from(json!(params))
                }
            },
            _ => Err(GetRegistrationReceiptError::InvalidFormat(format!(
                "Unexpected request format. Expected: tower_id [subscription_start] [subscription_expire]. Received: '{value}'"
            ))),
        }
    }
}

/// Data associated with a commitment revocation. Represents the data sent by CoreLN through the `commitment_revocation` hook.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitmentRevocation {
    pub channel_id: String,
    #[serde(rename(deserialize = "commitnum"))]
    pub commit_num: u32,
    pub commitment_txid: Txid,
    #[serde(deserialize_with = "crate::ser::deserialize_tx")]
    pub penalty_tx: Transaction,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    const VALID_ID: &str = "020dea894c967319407265764aba31bdef75d463f96800f34dd6df61380d82dfc0";

    mod register_command {
        use super::*;

        #[test]
        fn test_from_id() {
            // The tower id should be a valid id, otherwise the params construction will fail
            let params = RegisterParams::from_id(VALID_ID).unwrap();
            assert!(params.host.is_none());
            assert!(params.port.is_none());

            // Any incorrectly formatted id will make it fail
            assert!(matches!(
                RegisterParams::from_id(""),
                Err(RegisterError::InvalidId(..))
            ));
        }

        #[test]
        fn test_with_host() {
            // Any properly formatted host should work
            let params = RegisterParams::from_id(VALID_ID).unwrap();
            let host = "myhost";
            assert_eq!(params.with_host(host).unwrap().host, Some(host.to_owned()));

            // Host must not be empty not have spaces
            assert!(matches!(
                RegisterParams::from_id(VALID_ID).unwrap().with_host(""),
                Err(RegisterError::InvalidHost(..))
            ));
            assert!(matches!(
                RegisterParams::from_id(VALID_ID)
                    .unwrap()
                    .with_host("myhost "),
                Err(RegisterError::InvalidHost(..))
            ));
        }

        #[test]
        fn test_with_port() {
            let mut params = RegisterParams::from_id(VALID_ID).unwrap();

            // Any 16-bytes value will do for the port
            let port = 6677;
            params = params.with_port(port).unwrap();
            assert_eq!(params.port, Some(port as u16));

            // Going over u16::MAX will make this fail
            let port = u16::MAX as u64 + 1;
            assert!(matches!(
                params.with_port(port),
                Err(RegisterError::InvalidPort(..))
            ));
        }

        #[test]
        fn test_try_from_json_string() {
            let ok = [
                format!("{VALID_ID}@host:80"),
                format!("{VALID_ID}@host"),
                VALID_ID.to_string(),
            ];
            let wrong_id = ["", "id@host:80", "@host:80", "@:80"];
            let wrong_host = [
                format!("{VALID_ID}@"),
                format!("{VALID_ID}@ "),
                format!("{VALID_ID}@ host"),
                format!("{VALID_ID}@:80"),
            ];
            let wrong_port = [format!("{VALID_ID}@host:"), format!("{VALID_ID}@host:port")];

            for s in ok {
                let v = serde_json::Value::Array(vec![serde_json::Value::String(s.to_string())]);
                let p = RegisterParams::try_from(v);
                assert!(matches!(p, Ok(..)));
            }

            for s in wrong_id {
                let v = serde_json::Value::Array(vec![serde_json::Value::String(s.to_string())]);
                let p = RegisterParams::try_from(v);
                assert!(matches!(p, Err(RegisterError::InvalidId(..))));
            }

            for s in wrong_host {
                let v = serde_json::Value::Array(vec![serde_json::Value::String(s.to_string())]);
                let p = RegisterParams::try_from(v);
                assert!(matches!(p, Err(RegisterError::InvalidHost(..))));
            }

            for s in wrong_port {
                let v = serde_json::Value::Array(vec![serde_json::Value::String(s.to_string())]);
                let p = RegisterParams::try_from(v);
                assert!(matches!(p, Err(RegisterError::InvalidPort(..))));
            }
        }

        #[test]
        fn test_try_from_json_array() {
            let id = json!(VALID_ID);
            let number_id = json!(0);

            let host = json!("host");
            let number_host = json!(1);

            let port = json!(80);
            let string_port = json!("80");

            for v in [vec![&id, &host, &port], vec![&id, &host], vec![&id]] {
                let p = RegisterParams::try_from(json!(v));
                assert!(matches!(p, Ok(..)));
            }

            // Wrong id
            let p = RegisterParams::try_from(json!(vec![&number_id, &host, &port]));
            assert!(matches!(p, Err(RegisterError::InvalidId(..))));

            // Wrong host
            let p = RegisterParams::try_from(json!(vec![&id, &number_host, &port]));
            assert!(matches!(p, Err(RegisterError::InvalidHost(..))));

            // Wrong port
            let p = RegisterParams::try_from(json!(vec![&id, &host, &string_port]));
            assert!(matches!(p, Err(RegisterError::InvalidPort(..))));

            // Wrong param count (params should be 1-3)
            let p = RegisterParams::try_from(json!(vec![&id, &host, &port, &id]));
            assert!(matches!(p, Err(RegisterError::InvalidFormat(..))));
        }

        #[test]
        fn test_try_from_json_dict() {
            let id = json!(VALID_ID);
            let host = json!("host");
            let port = json!(80);

            for v in [
                HashMap::from([("tower_id", &id), ("host", &host), ("port", &port)]),
                HashMap::from([("tower_id", &id), ("host", &host)]),
                HashMap::from([("tower_id", &id)]),
            ] {
                let p = RegisterParams::try_from(json!(v));
                assert!(matches!(p, Ok(..)));
            }

            // Id key missing
            let p =
                RegisterParams::try_from(json!(HashMap::from([("host", &host), ("port", &port)])));
            assert!(matches!(p, Err(RegisterError::InvalidId(..))));

            // Wrong id key
            let p = RegisterParams::try_from(json!(HashMap::from([
                ("wrong_tower_id", &id),
                ("tower_id", &id),
                ("host", &host),
                ("port", &port)
            ])));
            assert!(matches!(p, Err(RegisterError::InvalidFormat(..))));

            // Wrong host key
            let p = RegisterParams::try_from(json!(HashMap::from([
                ("tower_id", &id),
                ("wrong_host", &host),
                ("port", &port)
            ])));
            assert!(matches!(p, Err(RegisterError::InvalidFormat(..))));

            // Wrong port key
            let p = RegisterParams::try_from(json!(HashMap::from([
                ("tower_id", &id),
                ("host", &host),
                ("wrong_port", &port)
            ])));
            assert!(matches!(p, Err(RegisterError::InvalidFormat(..))));

            // Wrong param count (params should be 1-3)
            let p = RegisterParams::try_from(json!(HashMap::from([
                ("tower_id", &id),
                ("host", &host),
                ("port", &port),
                ("another_param", &json!(0))
            ])));
            assert!(matches!(p, Err(RegisterError::InvalidFormat(..))));
        }

        #[test]
        fn test_try_from_other_json() {
            // Unexpected json object (it must be either String or Array)
            let p = RegisterParams::try_from(json!(true));
            assert!(matches!(p, Err(RegisterError::InvalidFormat(..))));
        }
    }

    mod get_appointment_command {
        use super::*;

        #[test]
        fn test_try_from_array() {
            let id = json!(VALID_ID);
            let wrong_id =
                json!("050dea894c967319407265764aba31bdef75d463f96800f34dd6df61380d82dfc0");
            let number_id = json!(0);

            let locator = json!("c69517f00d9482e6b1c41639f9bdfd5c");
            let wrong_locator =
                json!("c69517f00d9482e6b1c41639f9bdfd5cc69517f00d9482e6b1c41639f9bdfd5c");
            let number_locator = json!(1);

            // Valid params
            let p = GetAppointmentParams::try_from(json!(vec![&id, &locator]));
            assert!(matches!(p, Ok(..)));

            // Wrong params
            // Id is a hex string but the format is wrong (wrong prefix)
            let p = GetAppointmentParams::try_from(json!(vec![&wrong_id, &locator]));
            assert!(matches!(p, Err(GetAppointmentError::InvalidId(..))));
            // Ud is not a hex string
            let p = GetAppointmentParams::try_from(json!(vec![&number_id, &wrong_locator]));
            assert!(matches!(p, Err(GetAppointmentError::InvalidId(..))));

            // Locator is a hex string but not properly formatted (wrong length)
            let p = GetAppointmentParams::try_from(json!(vec![&id, &wrong_locator]));
            assert!(matches!(p, Err(GetAppointmentError::InvalidLocator(..))));
            // Locator is not a hex string
            let p = GetAppointmentParams::try_from(json!(vec![&id, &number_locator]));
            assert!(matches!(p, Err(GetAppointmentError::InvalidLocator(..))));
        }

        #[test]
        fn test_try_from_dict() {
            let id = json!(VALID_ID);
            let locator = json!("c69517f00d9482e6b1c41639f9bdfd5c");

            // Valid params
            let p = GetAppointmentParams::try_from(json!(HashMap::from([
                ("tower_id", &id),
                ("locator", &locator)
            ])));
            assert!(matches!(p, Ok(..)));

            // Wrong keys
            let p = GetAppointmentParams::try_from(json!(HashMap::from([
                ("wrong_tower_id", &id),
                ("locator", &locator)
            ])));
            assert!(matches!(p, Err(GetAppointmentError::InvalidFormat(..))));

            let p = GetAppointmentParams::try_from(json!(HashMap::from([
                ("tower_id", &id),
                ("wrong_locator", &locator)
            ])));
            assert!(matches!(p, Err(GetAppointmentError::InvalidFormat(..))));

            // Too many parameters
            let p = GetAppointmentParams::try_from(json!(HashMap::from([
                ("tower_id", &id),
                ("locator", &locator),
                ("another_param", &json!(0))
            ])));
            assert!(matches!(p, Err(GetAppointmentError::InvalidFormat(..))));
        }

        #[test]
        fn test_try_from_other_json() {
            // Unexpected json object (it must be either String or Array)
            let p = RegisterParams::try_from(json!(true));
            assert!(matches!(p, Err(RegisterError::InvalidFormat(..))));
        }

        #[test]
        fn test_wrong_param_count() {
            // The param count for get_appointment must be 2.
            let params_vec = [vec![], vec![1], vec![1, 2, 3]];

            for params in params_vec {
                let p = GetAppointmentParams::try_from(json!(params));
                assert!(matches!(p, Err(..)));
            }
        }
    }
}
