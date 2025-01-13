#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct PairingFailed(u8);

impl PairingFailed {
    /// The user input of passkey failed, for example, the user cancelled the operation.
    pub const PASSKEY_ENTRY_FAILED: Self = Self(0x01);

    /// The OOB data is not available.
    pub const OOB_NOT_AVAILABLE: Self = Self(0x02);

    /// The pairing procedure cannot be performed as authentication requirements cannot be met due
    /// to IO capabilities of one or both devices.
    pub const AUTHENTICATION_REQUIREMENTS: Self = Self(0x03);

    /// The confirm value does not match the calculated compare value.
    pub const CONFIRM_VALUE_FAILED: Self = Self(0x04);

    /// Pairing is not supported by the device.
    pub const PAIRING_NOT_SUPPORTED: Self = Self(0x05);

    /// The resultant encryption key size is not long enough for the security requirements of this
    /// device.
    pub const ENCRYPTION_KEY_SIZE: Self = Self(0x06);

    /// The SMP command received is not supported on this device.
    pub const COMMAND_NOT_SUPPORTED: Self = Self(0x07);

    /// Pairing failed due to an unspecified reason.
    pub const UNSPECIFIED_REASON: Self = Self(0x08);

    /// Pairing or authentication procedure is disallowed because too little time has elapsed since
    /// last pairing request or security request.
    pub const REPEATED_ATTEMPTS: Self = Self(0x09);

    /// The Invalid Parameters error code indicates that the command length is invalid or that a
    /// parameter is outside of the specified range.
    pub const INVALID_PARAMETERS: Self = Self(0x0A);

    /// Indicates to the remote device that the DHKey Check value received doesn’t match the one
    /// calculated by the local device.
    pub const DHKEY_CHECK_FAILED: Self = Self(0x0B);

    /// Indicates that the confirm values in the numeric comparison protocol do not match.
    pub const NUMERIC_COMPARISON_FAILED: Self = Self(0x0C);

    /// Indicates that the pairing over the LE transport failed due to a Pairing Request sent over
    /// the BR/EDR transport in progress.
    pub const BR_EDR_PAIRING_IN_PROGRESS: Self = Self(0x0D);

    /// Indicates that the BR/EDR Link Key generated on the BR/EDR transport cannot be used to
    /// derive and distribute keys for the LE transport or the LE LTK generated on the LE transport
    /// cannot be used to derive a key for the BR/EDR transport.
    pub const CROSS_TRANSPORT_KEY_DERIVATION_GENERATION_NOT_ALLOWED: Self = Self(0x0E);

    /// Indicates that the device chose not to accept a distributed key.
    pub const KEY_REJECTED: Self = Self(0x0F);

    pub const fn as_u8(&self) -> u8 {
        self.0
    }

    pub const fn from_u8(byte: u8) -> Self {
        Self(byte)
    }

    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
        match slice {
            &[reason] => Some(Self::from_u8(reason)),
            _ => None,
        }
    }
}
