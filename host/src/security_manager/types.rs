use duplicate::duplicate_item;

mod pairing_public_key;
pub use pairing_public_key::PairingPublicKey;

mod pairing_random_data;
pub use pairing_random_data::PairingRandom;

mod pairing_request;
pub use pairing_request::{AuthReq, IoCapability, OobDataFlag, PairingRequest};

mod pairing_response;
pub use pairing_response::PairingResponse;

mod pairing_confirm;
pub use pairing_confirm::PairingConfirm;

mod pairing_failed;
pub use pairing_failed::PairingFailed;

mod pairing_dhkey_check;
pub use pairing_dhkey_check::PairingDhKeyCheck;

#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct SmCommand<D> {
    pub code: SmCode,
    pub data: D,
}

impl<D> SmCommand<D>
where
    SmCommand<D>: ValidSmCommand<Data = D>,
{
    pub fn new(data: D) -> Self {
        Self { code: Self::CODE, data }
    }
}

pub(crate) trait ValidSmCommand: Sized {
    /// Size of this type, in bytes.
    const LEN: usize;

    /// The code value that identifies this command.
    const CODE: SmCode;

    /// The type for the data of this command.
    type Data: Sized;

    /// Return the byte-slice representation self.
    fn as_slice(&self) -> &[u8];

    /// Try to convert a slice of data to Self.
    ///
    /// This will validate the `code` field, and the length of the slice.
    fn try_from_slice(slice: &[u8]) -> Option<Self> {
        let (&code, data) = slice.split_first()?;

        if SmCode::from_u8(code) != Self::CODE {
            return None;
        }

        Self::try_from_data_slice(data)
    }

    /// Try to convert a slice of data to Self.
    ///
    /// This will only validate the length of the slice.
    /// The data must NOT include the `code` field.
    fn try_from_data_slice(slice: &[u8]) -> Option<Self>;
}

/// Security Manager Code.
///
/// Determines the type of an SMP command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct SmCode(u8);

impl SmCode {
    pub const PAIRING_REQUEST: SmCode = SmCode(0x01);
    pub const PAIRING_RESPONSE: SmCode = SmCode(0x02);
    pub const PAIRING_CONFIRM: SmCode = SmCode(0x03);
    pub const PAIRING_RANDOM: SmCode = SmCode(0x04);
    pub const PAIRING_FAILED: SmCode = SmCode(0x05);
    pub const ENCRYPTION_INFORMATION: SmCode = SmCode(0x06);
    pub const CENTRAL_IDENTIFICATION: SmCode = SmCode(0x07);
    pub const IDENTITY_INFORMATION: SmCode = SmCode(0x08);
    pub const IDENTITY_ADDRESS_INFORMATION: SmCode = SmCode(0x09);
    pub const SIGNING_INFORMATION: SmCode = SmCode(0x0a);
    pub const SECURITY_REQUEST: SmCode = SmCode(0x0b);
    pub const PAIRING_PUBLIC_KEY: SmCode = SmCode(0x0c);
    pub const PAIRING_DHKEY_CHECK: SmCode = SmCode(0x0d);
    pub const PAIRING_KEYPRESS_NOTIFICATION: SmCode = SmCode(0x0e);

    pub const fn as_u8(&self) -> u8 {
        self.0
    }

    pub const fn from_u8(byte: u8) -> Self {
        Self(byte)
    }
}

#[duplicate_item(
    code_value DataType;
    [SmCode::PAIRING_REQUEST]               [PairingRequest];
    [SmCode::PAIRING_RESPONSE]              [PairingResponse];
    [SmCode::PAIRING_CONFIRM]               [PairingConfirm];
    [SmCode::PAIRING_RANDOM]                [PairingRandom];
    [SmCode::PAIRING_FAILED]                [PairingFailed];
    //[SmCode::ENCRYPTION_INFORMATION]        [];
    //[SmCode::CENTRAL_IDENTIFICATION]        [];
    //[SmCode::IDENTITY_INFORMATION]          [];
    //[SmCode::IDENTITY_ADDRESS_INFORMATION]  [];
    //[SmCode::SIGNING_INFORMATION]           [];
    //[SmCode::SECURITY_REQUEST]              [];
    [SmCode::PAIRING_PUBLIC_KEY]            [PairingPublicKey];
    [SmCode::PAIRING_DHKEY_CHECK]           [PairingDhKeyCheck];
    //[SmCode::PAIRING_KEYPRESS_NOTIFICATION] [];
)]
impl ValidSmCommand for SmCommand<DataType> {
    const LEN: usize = size_of::<Self>();
    const CODE: SmCode = code_value;

    type Data = DataType;

    fn as_slice(&self) -> &[u8] {
        // SAFETY: [u8] has alignment 1
        unsafe { core::mem::transmute::<&Self, &[u8; Self::LEN]>(self) }
    }

    fn try_from_data_slice(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
        Some(unsafe { core::mem::transmute(*bytes) })
    }
}

//impl SmCommand<DataType> {
//    pub const fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
//        // SAFETY: [u8] has alignment 1
//        unsafe { core::mem::transmute(self) }
//    }
//
//    pub fn from_bytes(bytes: [u8; size_of::<Self>()]) -> Self {
//        // SAFETY:Self is repr(C, packed) and all fields are valid for all bit patterns
//        unsafe { core::mem::transmute(bytes) }
//    }
//
//    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
//        let array_ref: &[u8; size_of::<Self>()] = slice.try_into().ok()?;
//        Some(Self::from_bytes(*array_ref))
//    }
//}
