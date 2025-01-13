use bitfield_struct::bitfield;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C, packed)]
pub struct PairingRequest {
    pub io_capability: IoCapability,
    pub oob_data_flag: OobDataFlag,
    pub auth_req: u8,
    pub maximum_encryption_key_size: u8,
    pub initiator_key_distribution: u8,
    pub responder_key_distribution: u8,
}

impl PairingRequest {
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

/// The I/O capability of a device. For example whether it has a display/keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct IoCapability(u8);

impl IoCapability {
    /// The device has a display, but no input capability.
    pub const DISPLAY_ONLY: IoCapability = IoCapability(0x00);

    /// The device has a display, and a yes/no input capability.
    pub const DISPLAY_YES_NO: IoCapability = IoCapability(0x01);

    /// The device has no display, but it has a keyboard.
    pub const KEYBOARD_ONLY: IoCapability = IoCapability(0x02);

    /// The device has no inputs and no outputs.
    pub const NO_INPUT_NO_OUTPUT: IoCapability = IoCapability(0x03);

    /// The device has a keyboard and a display.
    pub const KEYBOARD_DISPLAY: IoCapability = IoCapability(0x04);

    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct OobDataFlag(u8);

impl OobDataFlag {
    pub const AUTH_DATA_NOT_PRESENT: OobDataFlag = OobDataFlag(0x00);
    pub const AUTH_DATA_PRESENT: OobDataFlag = OobDataFlag(0x01);

    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

#[bitfield(u8)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AuthReq {
    #[bits(2)]
    pub bonding_flags: u8,
    #[bits(1)]
    pub mitm: bool,
    #[bits(1)]
    pub sc: bool,
    #[bits(1)]
    pub keypress: bool,
    #[bits(1)]
    pub ct2: bool,
    #[bits(2)]
    pub rfu: u8,
}
