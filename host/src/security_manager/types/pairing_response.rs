use core::mem::transmute;

use super::{AuthReq, IoCapability, OobDataFlag};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C, packed)]
pub struct PairingResponse {
    pub io_capability: IoCapability,
    pub oob_data_flag: OobDataFlag,
    pub auth_req: AuthReq,
    pub maximum_encryption_key_size: u8,
    pub initiator_key_distribution: u8,
    pub responder_key_distribution: u8,
}

impl PairingResponse {
    pub const fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        // SAFETY: [u8] has alignment 1
        unsafe { transmute(self) }
    }

    pub fn from_bytes(bytes: [u8; size_of::<Self>()]) -> Self {
        // SAFETY:Self is repr(C, packed) and all fields are valid for all bit patterns
        unsafe { transmute(bytes) }
    }

    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
        let array_ref: &[u8; size_of::<Self>()] = slice.try_into().ok()?;
        Some(Self::from_bytes(*array_ref))
    }
}
