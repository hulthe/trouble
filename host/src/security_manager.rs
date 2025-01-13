use core::{fmt::Debug, mem};

use bt_hci::{controller::Controller, param::ConnHandle, AsHciBytes};
use embedded_io::Write;
use rand_core::CryptoRngCore;
use types::{
    AuthReq, IoCapability, OobDataFlag, PairingConfirm, PairingDhKeyCheck, PairingFailed, PairingPublicKey,
    PairingRandom, PairingRequest, PairingResponse, SmCode, SmCommand, ValidSmCommand,
};

use crate::{
    crypto::{Check, Confirm, DHKey, IoCap, MacKey, Nonce, PublicKey, SecretKey, LTK},
    host::BleHost,
    packet_pool::AllocId,
    pdu::Pdu,
    types::l2cap::{L2capHeader, L2CAP_CID_SM},
    Address, Error,
};

mod types;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SecurityManagerError {
    PasskeyEntryFailed = 1,
    OobNotAvailable,
    AuthenticationRequirements,
    ConfirmValueFailed,
    PairingNotSupported,
    EncryptionKeySize,
    CommandNotSupported,
    UnspecifiedReason,
    RepeatedAttempts,
    InvalidParameters,
    DHKeyCheckFailed,
    NumericComparisonFailed,
    BrEdrPairingInProgress,
    GenerationNotAllowed,
    KeyRejected,
}

fn make_auth_req() -> AuthReq {
    AuthReq::new()
        .with_bonding_flags(1)
        .with_mitm(true)
        .with_sc(true)
        .with_keypress(false)
        .with_ct2(true)
}

/// Security manager that handles SM packet
#[derive(Debug)]
pub struct SecurityManager {
    /// The I/O capability of this device. For example whether it has a display/keyboard.
    io_capability: IoCapability,

    pairing: PairingState,
}

pub struct SecurityManagerHandle<'a, 'h, C, R> {
    // TODO: docs
    pub sm: &'a mut SecurityManager,
    pub rng: &'a mut R,
    pub host: &'a BleHost<'h, C>,
    pub local_address: Address,
    pub peer_address: Address,
    pub handle: ConnHandle,
}

// TODO: name?
struct PeerKeyData {
    pka: PublicKey,
    pkb: PublicKey,
    skb: SecretKey,
    confirm: Confirm,
    nb: Nonce,
    dh_key: DHKey,
}

enum PairingState {
    /// No pairing has been initiated.
    None,

    /// Pairing Step 1. We've received a [PairingRequest]
    ReceivedPairingRequest {
        /// Contains data received from the peer who initiated the peering.
        pairing_request: PairingRequest,
    },

    /// Pairing Step 2. We've received a [PairingPublicKey]
    ReceivedPublicKey {
        /// Contains data received from the peer who initiated the peering.
        pairing_request: PairingRequest,
        keys: PeerKeyData,
    },

    /// Pairing Step 3. We've received a [PairingRandom]
    ReceivedRandomData {
        pairing_request: PairingRequest,
        keys: PeerKeyData,
        mac_key: MacKey,
        ltk: LTK,
        eb: Check,
        na: Nonce,
    },

    /// We are paired.
    Paired {},
}

impl PairingState {
    pub fn take(&mut self) -> Self {
        let mut take = Self::None;
        mem::swap(self, &mut take);
        take
    }
}

impl SecurityManager {
    pub const fn new() -> Self {
        Self {
            io_capability: IoCapability::DISPLAY_ONLY,
            pairing: PairingState::None,
        }
    }

    pub fn with_context<'a, 'h, C: Controller, R: CryptoRngCore>(
        &'a mut self,
        host: &'a BleHost<'h, C>,
        rng: &'a mut R,
        local_address: Address,
        peer_address: Address,
        handle: ConnHandle,
    ) -> SecurityManagerHandle<'a, 'h, C, R> {
        SecurityManagerHandle {
            sm: self,
            host,
            rng,
            local_address,
            peer_address,
            handle,
        }
    }
}

impl<C: Controller, R: CryptoRngCore> SecurityManagerHandle<'_, '_, C, R> {
    /// Handle packet
    pub(crate) fn handle(&mut self, payload: &[u8]) -> Result<(), Error> {
        let Some((&command, data)) = payload.split_first() else {
            warn!("[SecurityManager] received empty message");
            return Err(Error::InvalidValue);
        };

        let command = SmCode::from_u8(command);

        // Happy path - pairing:
        // Receive PAIRING_REQUEST     [01, 01, 00, 2d, 10, 0d, 0f]
        // Send    PAIRING_RESPONSE    [02, 01, 00, 2d, 10, 00, 00]
        // Receive PAIRING_PUBLIC_KEY  [0c, 15, bf, 1f, 93, 24, 0c, 8f, 04, 60, 2e, ce, 7a, a3, 94, 75, d2, 77, f9, 4c, e7, 2e, 03, 9c, 5f, 3d, 7e, 58, 42, 61, 7b, ad, 6e, f6, d9, 9d, 55, 4b, a3, ff, 28, 87, 98, e2, aa, 2e, bd, ba, ac, ed, 2a, d8, 86, e0, 3c, bc, 41, 14, 00, 07, d7, 62, a3, 34, fa]
        // Send    PAIRING_PUBLIC_KEY  [c, 1d, 1d, d3, 62, 6a, 59, c6, 6f, e4, d9, d8, 97, 2b, 25, 7a, b2, 96, b9, a8, 69, 55, a4, 98, cb, ef, 25, a5, 45, e6, 85, 6e, 89, 90, 8b, 18, e3, 85, 3, 18, 9c, 21, 16, e9, 1f, 80, d7, 6b, b0, c6, 8e, 76, b4, c2, a2, 56, 30, e6, ad, 86, ae, 99, 88, ba, 31]
        // Send    PAIRING_CONFIRM     [3, e1, 6f, c3, 1f, 25, 45, 7d, aa, f4, 17, 3f, 4d, 73, 48, fc, ac]
        // Receive PAIRING_RANDOM      [04, fc, 91, 93, 03, 5d, 7c, 11, 6f, 1e, d5, 08, 07, ec, 31, fe, 39]
        // Send    PAIRING_RANDOM      [4, e4, 88, 5c, 35, 62, 10, 52, b3, ca, 6, 5f, ed, d5, 99, c4, ea]
        // Receive PAIRING_DHKEY_CHECK [0d, c0, a4, 92, 84, c0, 41, e0, d6, 4b, 5d, b7, ad, 9f, 58, 92, 74]
        // Send    PAIRING_DHKEY_CHECK [d, 5, 1e, 10, 71, 76, ba, 5d, d1, 5, 77, d7, 6a, 33, e5, ab, e9]
        // Done. We are paired. Then what? Is traffic automatically encrypted? Doesn't seem likely.

        // Simple LE non-legacy
        //
        // Central sends Pairing Request
        // Periphe sends Pairing Response
        // Central sends Public Key
        // Periphe sends Public Key
        // Both generates DH Key
        //
        // Then there are a few different options depending on device IoCapabilities
        //
        // At some point...
        // Central sends Pairing Random
        // Periphe sends Pairing Random

        match command {
            SmCode::PAIRING_REQUEST => self.handle_pairing_request(data),
            SmCode::PAIRING_RANDOM => self.handle_pairing_random(data),
            SmCode::PAIRING_FAILED => self.handle_pairing_failed(data),
            SmCode::PAIRING_PUBLIC_KEY => self.handle_pairing_public_key(data),
            SmCode::PAIRING_DHKEY_CHECK => self.handle_pairing_dhkey_check(data),
            _ => {
                // handle FAILURE
                error!("[SecurityManager] Unknown command {}", command);
                return Err(Error::InvalidValue);
            }
        }
    }

    /// Encode a Security Manager command in L2CAP(i think?) (TODO)
    fn encode_sm_data<'a>(&self, data: &[u8], mut target: &'a mut [u8]) -> Result<usize, Error> {
        let header = L2capHeader {
            // TODO: do we need to subtract by 4?
            length: data.len().try_into().map_err(|_| Error::Other)?,
            channel: L2CAP_CID_SM,
        };

        target.write_all(header.as_hci_bytes()).map_err(|_| Error::Other)?;
        target.write_all(data).map_err(|_| Error::Other)?;
        Ok(header.as_hci_bytes().len() + data.len())

        //// TODO: remove this
        //target.copy_from_slice(&[
        //    0x0, 0x0, // len set later
        //    0x6, 0x0, // channel 6
        //]);
        //target[4..data.len() + 4].copy_from_slice(data);
        //let len = data.len() - 4;
        //target[0] = (len & 0xff) as u8;
        //target[1] = ((len >> 8) & 0xff) as u8;
        //&target[..data.len() + 4]
    }

    fn write_command(&self, command: &impl ValidSmCommand) -> Result<(), Error> {
        let alloc_id = AllocId::from_channel(L2CAP_CID_SM);
        let mut packet = self.host.rx_pool.alloc(alloc_id).ok_or(Error::OutOfMemory)?;
        let len = self
            .encode_sm_data(command.as_slice(), packet.as_mut())
            .inspect_err(|_| error!("[SecurityManager] Failed to encode packet. This is a bug."))?;

        let packet = Pdu::new(packet, len);
        self.host
            .outbound
            .try_send((self.handle, packet))
            .map_err(|_| Error::OutOfMemory)?;

        Ok(())
    }

    fn write_error<T>(&self, error: SecurityManagerError) -> Result<T, Error> {
        let command = PairingFailed::from_u8(error as u8); // TODO: are the numbers correct, mason?
        self.write_command(&SmCommand::new(command))?;
        Err(error.into())
    }

    fn handle_pairing_request(&mut self, data: &[u8]) -> Result<(), Error> {
        let Some(data) = PairingRequest::try_from_slice(data) else {
            warn!("[SecurityManager] Failed to decode PairingRequest message");
            return Err(Error::InvalidValue);
        };

        debug!("[SecurityManager] Handle pairing request");

        let PairingState::None = self.sm.pairing else {
            // TODO: Print PairingState kind (but not the data)
            warn!("[SecurityManager] Received PairingRequest, but we are in the wrong pairing state");
            return self
                // TODO: error kind
                .write_error(SecurityManagerError::UnspecifiedReason);
        };

        self.sm.pairing = PairingState::ReceivedPairingRequest { pairing_request: data };

        let response = SmCommand::new(PairingResponse {
            io_capability: self.sm.io_capability,
            oob_data_flag: OobDataFlag::AUTH_DATA_NOT_PRESENT,
            auth_req: make_auth_req(),
            maximum_encryption_key_size: 0x10, // TODO
            initiator_key_distribution: 0,     // TODO
            responder_key_distribution: 0,     // TODO
        });
        self.write_command(&response)
    }

    fn handle_pairing_public_key(&mut self, pka: &[u8]) -> Result<(), Error> {
        debug!("[SecurityManager] Handle pairing public key");
        debug!("[SecurityManager] key len = {} {:02x?}", pka.len(), pka);
        let pka = PublicKey::from_bytes(pka);

        let PairingState::ReceivedPairingRequest { pairing_request } = self.sm.pairing.take() else {
            // TODO: Print PairingState kind (but not the data)
            warn!("[SecurityManager] Received PairingPublicKey, but we are in the wrong pairing state");
            return self
                // TODO: error kind
                .write_error(SecurityManagerError::UnspecifiedReason);
        };

        // Send the local public key before validating the remote key to allow
        // parallel computation of DHKey. No security risk in doing so.

        let skb = SecretKey::new(self.rng);
        let pkb = skb.public_key();

        self.write_command(&SmCommand::new(PairingPublicKey {
            public_key_x: pkb.x.as_le_bytes(),
            public_key_y: pkb.y.as_le_bytes(),
        }))?;

        let Some(dh_key) = skb.dh_key(pka) else {
            // TODO: is this ok?
            self.write_command(&SmCommand::new(PairingFailed::DHKEY_CHECK_FAILED))?;

            return Err(SecurityManagerError::DHKeyCheckFailed.into());
        };

        // SUBTLE: The order of these send/recv ops is important. See last
        // paragraph of Section 2.3.5.6.2.
        let nb = Nonce::new(self.rng);
        let confirm = nb.f4(pkb.x(), pka.x(), 0);

        self.write_command(&SmCommand::new(PairingConfirm(confirm.0.to_le_bytes())))?;

        self.sm.pairing = PairingState::ReceivedPublicKey {
            pairing_request,
            keys: PeerKeyData {
                pka,
                pkb,
                skb,
                confirm,
                nb,
                dh_key,
            },
        };

        Ok(())
    }

    fn handle_pairing_random(&mut self, data: &[u8]) -> Result<(), Error> {
        let Some(data) = PairingRandom::try_from_slice(data) else {
            warn!("[SecurityManager] Failed to decode PairingRandom message");
            return Err(Error::InvalidValue);
        };

        debug!("[SecurityManager] Handle pairing random");
        debug!("[SecurityManager] Got pairing random: {:02x?}", data);

        let PairingState::ReceivedPublicKey { pairing_request, keys } = self.sm.pairing.take() else {
            // TODO: Print PairingState kind (but not the data)
            warn!("[SecurityManager] Received PairingPublicKey, but we are in the wrong pairing state");
            return self
                // TODO: error kind
                .write_error(SecurityManagerError::UnspecifiedReason);
        };

        let PeerKeyData {
            pka,
            pkb,
            skb,
            confirm,
            nb,
            dh_key,
        } = &keys;

        // TODO: Do checking

        let random = nb.0.to_le_bytes();
        self.write_command(&SmCommand::new(PairingRandom(random)))?;

        // TODO: this can't be right? why copy nb to na and then add nb again?
        let na = Nonce(u128::from_le_bytes(random));
        let vb = na.g2(pka.x(), pkb.x(), &nb);

        // TODO: if IoCapability includes input, we should wait for confirmation from user
        // TODO: if IoCapability includes output, we should display pin
        // if not okay send a pairing-failed assume it's correct or the user will cancel on central
        info!("Pairing code is {}", vb.0);
        // if let Some(pin_callback) = pin_callback {
        // pin_callback(vb.0);
        // }

        // Authentication stage 2 and long term key calculation
        // ([Vol 3] Part H, Section 2.3.5.6.5 and C.2.2.4).

        let ra = 0;
        trace!("peer_address = {:02x?}", self.peer_address);
        trace!("local_address = {:02x?}", self.local_address);

        let auth_req = make_auth_req();
        let oob_data = false;
        let io_cap = self.sm.io_capability.as_u8();
        let iob = IoCap::new(auth_req.into(), false, io_cap);

        let (mac_key, ltk) = dh_key.f5(na, *nb, self.peer_address, self.local_address);
        let eb = mac_key.f6(*nb, na, ra, iob, self.local_address, self.peer_address);

        self.sm.pairing = PairingState::ReceivedRandomData {
            pairing_request,
            keys,
            mac_key,
            ltk,
            eb,
            na,
        };

        Ok(())
    }

    fn handle_pairing_dhkey_check(&mut self, ea: &[u8]) -> Result<(), Error> {
        debug!("[SecurityManager] Handle pairing dhkey check");
        debug!("[SecurityManager] Got ea: {:02x?}", ea);

        let PairingState::ReceivedRandomData {
            pairing_request,
            keys,
            mac_key,
            ltk,
            eb,
            na,
        } = self.sm.pairing.take()
        else {
            // TODO: Print PairingState kind (but not the data)
            warn!("[SecurityManager] Received PairingPublicKey, but we are in the wrong pairing state");
            return self
                // TODO: error kind
                .write_error(SecurityManagerError::UnspecifiedReason);
        };

        let PeerKeyData {
            pka,
            pkb,
            skb,
            confirm,
            nb,
            dh_key,
        } = &keys;

        let ioa = IoCap::new(
            pairing_request.auth_req,
            pairing_request.oob_data_flag.as_u8() != 0,
            pairing_request.io_capability.as_u8(),
        );
        let computed_ea = mac_key
            .f6(na, *nb, 0, ioa, self.peer_address, self.local_address)
            .0
            .to_le_bytes();

        if ea != computed_ea {
            warn!("[SecurityManager] DH check failed");
            return Err(SecurityManagerError::DHKeyCheckFailed.into());
        }

        self.write_command(&SmCommand::new(PairingDhKeyCheck {
            dhkey_check: eb.0.to_le_bytes(),
        }))?;
        Ok(())
    }

    fn handle_pairing_failed(&mut self, data: &[u8]) -> Result<(), Error> {
        let Some(reason) = PairingFailed::try_from_slice(data) else {
            warn!("[SecurityManager] Failed to decode PairingFailed message");
            return Err(Error::InvalidValue);
        };

        self.sm.pairing = PairingState::None;

        Ok(())
    }
}

impl Debug for PairingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::ReceivedPairingRequest { .. } => f.debug_tuple("ReceivedPairingRequest").field(&..).finish(),
            Self::ReceivedPublicKey { .. } => f.debug_tuple("ReceivedPublicKey").field(&..).finish(),
            Self::ReceivedRandomData { .. } => f.debug_tuple("ReceivedRandomData").field(&..).finish(),
            Self::Paired {} => f.debug_tuple("Paired").field(&..).finish(),
        }
    }
}
