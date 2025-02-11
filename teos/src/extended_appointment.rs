//! Logic related to appointments handled by the tower.

use std::array::TryFromSliceError;
use std::convert::TryInto;
use std::fmt;

use bitcoin::hashes::{ripemd160, Hash};

use teos_common::appointment::{Appointment, Locator};
use teos_common::UserId;

/// Unique identifier used to identify appointments.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct UUID([u8; 20]);

impl UUID {
    /// Creates a new [UUID].
    ///
    /// The [UUID]s are created as the `RIPEMD160(locator || user_id)`. This makes it easy to retrieve an [ExtendedAppointment] from the tower
    /// when a user requests it without having to perform lookups based on the [Locator], and match what [UUID] belongs to what user (if any).
    /// Therefore, it provides a hard-to-forge id while reducing the tower lookups and the required data to be stored (no reverse maps).
    pub fn new(locator: Locator, user_id: UserId) -> Self {
        let mut uuid_data = locator.to_vec();
        uuid_data.extend(user_id.0.serialize());
        UUID(ripemd160::Hash::hash(&uuid_data).to_byte_array())
    }

    /// Serializes the [UUID] returning its byte representation.
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Builds a [UUID] from its byte representation.
    pub fn from_slice(data: &[u8]) -> Result<Self, TryFromSliceError> {
        data.try_into().map(Self)
    }
}

impl std::fmt::Display for UUID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// An extended version of the appointment hold by the tower.
///
/// The [Appointment] is extended in terms of data, that is, it provides further information only relevant to the tower.
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct ExtendedAppointment {
    /// The underlying appointment extended by [ExtendedAppointment].
    pub inner: Appointment,
    /// The user this [Appointment] belongs to.
    pub user_id: UserId,
    /// The signature provided by the user when handing the [Appointment].
    pub user_signature: String,
    /// The block where the [Appointment] is started to be watched at by the [Watcher](crate::watcher::Watcher).
    pub start_block: u32,
}

impl ExtendedAppointment {
    /// Create a new [ExtendedAppointment].
    pub fn new(
        inner: Appointment,
        user_id: UserId,
        user_signature: String,
        start_block: u32,
    ) -> Self {
        ExtendedAppointment {
            inner,
            user_id,
            user_signature,
            start_block,
        }
    }

    /// Gets the underlying appointment's locator.
    pub fn locator(&self) -> Locator {
        self.inner.locator
    }

    /// Gets the underlying appointment's encrypted data blob
    pub fn encrypted_blob(&self) -> &Vec<u8> {
        &self.inner.encrypted_blob
    }

    /// Gets the underlying appointment's `to_self_delay`
    pub fn to_self_delay(&self) -> u32 {
        self.inner.to_self_delay
    }

    pub fn uuid(&self) -> UUID {
        UUID::new(self.inner.locator, self.user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::generate_uuid;

    #[test]
    fn test_uuid_ser_deser() {
        let original_uuid = generate_uuid();
        assert_eq!(
            UUID::from_slice(&original_uuid.to_vec()).unwrap(),
            original_uuid
        );
    }
}
