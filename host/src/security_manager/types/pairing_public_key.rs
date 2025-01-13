#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C, packed)]
pub struct PairingPublicKey {
    pub public_key_x: [u8; 32], // TODO: fancier types?
    pub public_key_y: [u8; 32], // TODO: fancier types?
}

impl PairingPublicKey {
    pub const fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        // SAFETY: [u8] has alignment 1
        unsafe { core::mem::transmute(self) }
    }

    pub fn from_bytes(bytes: [u8; size_of::<Self>()]) -> Self {
        // SAFETY:Self is repr(C, packed) and all fields are valid for all bit patterns
        unsafe { core::mem::transmute(bytes) }
    }

    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
        let array_ref: &[u8; size_of::<Self>()] = slice.try_into().ok()?;
        Some(Self::from_bytes(*array_ref))
    }
}
