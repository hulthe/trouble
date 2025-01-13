#[repr(transparent)]
pub struct PairingRandom(pub [u8; 16]);

impl PairingRandom {
    pub const fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; size_of::<Self>()]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
        let array_ref: &[u8; size_of::<Self>()] = slice.try_into().ok()?;
        Some(Self::from_bytes(*array_ref))
    }
}
