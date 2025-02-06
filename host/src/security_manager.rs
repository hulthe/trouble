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

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    /// Their public key.
    pka: PublicKey,

    /// Our public key.
    pkb: PublicKey,

    /// Our secret key.
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
            io_capability: IoCapability::DISPLAY_YES_NO,
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
        debug!("[SecurityManager] handle({:x})", payload);
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
        let Some(pairing_request) = PairingRequest::try_from_slice(data) else {
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

        let response = SmCommand::new(PairingResponse {
            io_capability: self.sm.io_capability,
            oob_data_flag: OobDataFlag::AUTH_DATA_NOT_PRESENT,
            auth_req: make_auth_req(),
            maximum_encryption_key_size: 0x10, // TODO
            initiator_key_distribution: 0,     // TODO
            responder_key_distribution: 0,     // TODO
        });
        self.write_command(&response)?;

        self.sm.pairing = PairingState::ReceivedPairingRequest { pairing_request };

        Ok(())
    }

    fn handle_pairing_public_key(&mut self, pka: &[u8]) -> Result<(), Error> {
        debug!("[SecurityManager] Handle pairing public key");
        debug!("[SecurityManager] key len = {} {:x}", pka.len(), pka);
        //let Some(pka) = PairingPublicKey::try_from_slice(pka) else {
        //    return self
        //        // TODO: error kind
        //        .write_error(SecurityManagerError::UnspecifiedReason);
        //};
        let pka = PublicKey::from_bytes(pka); // TODO: make this less panicky

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
            // TODO: is this the correct error?
            return self.write_error(SecurityManagerError::KeyRejected);
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
        let Some(PairingRandom(random)) = PairingRandom::try_from_slice(data) else {
            warn!("[SecurityManager] Failed to decode PairingRandom message");
            return Err(Error::InvalidValue);
        };

        debug!("[SecurityManager] Handle pairing random");
        debug!("[SecurityManager] Got pairing random: {:x}", data);

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

        self.write_command(&SmCommand::new(PairingRandom(nb.0.to_le_bytes())))?;

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

        let ra = 0; // TODO
        debug!("peer_address = {:x}", self.peer_address);
        debug!("local_address = {:x}", self.local_address);

        let auth_req = make_auth_req();
        let oob_data = false;
        let io_cap = self.sm.io_capability.as_u8();
        let iob = IoCap::new(auth_req.into(), false, io_cap);

        debug!("peer_address = {:x}", self.peer_address);
        debug!("local_address = {:x}", self.local_address);
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
        debug!("[SecurityManager] Got ea: {:x}", ea);

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
        debug!("[SecurityManager] pairing_request: {:x}", pairing_request);
        debug!("[SecurityManager] ioa: {:x}", ioa);
        let expected_ea = mac_key
            .f6(na, *nb, 0, ioa, self.peer_address, self.local_address)
            .0
            .to_le_bytes();

        if ea != expected_ea {
            warn!("[SecurityManager] DH check failed");
            debug!("[SecurityManager] received: {:x}", ea);
            debug!("[SecurityManager] expected: {:x}", expected_ea);
            debug!("[SecurityManager] mac_key: {:x}", mac_key.0 .0.as_slice());
            debug!("[SecurityManager] keys.pka: {:x}", pka);
            debug!("[SecurityManager] keys.pkb: {:x}", pkb);
            debug!("[SecurityManager] keys.skb: {:x}", skb.0.to_bytes().as_slice());
            debug!("[SecurityManager] keys.confirm: {:x}", confirm.0);
            debug!("[SecurityManager]      na: {:x}", na);
            debug!("[SecurityManager] keys.nb: {:x}", nb);
            debug!(
                "[SecurityManager] keys.dh_key: {:x}",
                dh_key.0.raw_secret_bytes().as_slice()
            );
            self.write_command(&SmCommand::new(PairingFailed::DHKEY_CHECK_FAILED))?;
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

#[cfg(test)]
mod tests {
    extern crate std;
    use core::{convert::Infallible, future::pending};
    use std::println;
    use std::vec::Vec;

    use bt_hci::{controller::ExternalController, transport::SerialTransport};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embedded_io::ErrorType;
    use futures::{executor::block_on, select, FutureExt};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Core, ChaCha8Rng};
    use tokio::task::yield_now;

    use crate::{packet_pool::Qos, HostResources};

    use super::*;

    const L2CAP_MTU: usize = 1017;
    const CONNECTIONS_MAX: usize = 1;
    const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

    type Resources<C> = HostResources<C, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>;

    #[test]
    fn pairing() {
        let mut input = Vec::<&[u8]>::new();

        //DEBUG - decoding SM packet [01, 01, 00, 2d, 10, 0d, 0f]
        input.push(&[0x01, 0x01, 0x00, 0x2d, 0x10, 0x0d, 0x0f]);

        //DEBUG - writing sm command [2, 1, 0, 2d, 10, 0, 0]
        //DEBUG - decoding SM packet [0c, 45, 97, f4, 9f, cd, 51, fd, d5, a1, 29, 63, e5, 19, 36, 34, 03, da, 8f, 78, 1c, 7a, 0b, cb, f9, 0f, 75, a9, bf, d7, 1a, eb, 52, 6b, f1, 0c, 23, 17, da, 73, 8e, 36, 2a, 3c, 90, 87, f7, cd, 62, a3, c3, c9, 79, eb, 6f, 9e, ef, d6, da, a2, e7, 21, 22, 1d, 7d]
        input.push(&[
            0x0c, 0x45, 0x97, 0xf4, 0x9f, 0xcd, 0x51, 0xfd, 0xd5, 0xa1, 0x29, 0x63, 0xe5, 0x19, 0x36, 0x34, 0x03, 0xda,
            0x8f, 0x78, 0x1c, 0x7a, 0x0b, 0xcb, 0xf9, 0x0f, 0x75, 0xa9, 0xbf, 0xd7, 0x1a, 0xeb, 0x52, 0x6b, 0xf1, 0x0c,
            0x23, 0x17, 0xda, 0x73, 0x8e, 0x36, 0x2a, 0x3c, 0x90, 0x87, 0xf7, 0xcd, 0x62, 0xa3, 0xc3, 0xc9, 0x79, 0xeb,
            0x6f, 0x9e, 0xef, 0xd6, 0xda, 0xa2, 0xe7, 0x21, 0x22, 0x1d, 0x7d,
        ]);
        //DEBUG - writing sm command [c, 81, b3, 32, ed, e0, e5, ae, ca, 41, a4, 44, 3c, 7d, 78, 6b, a9, f8, ae, e2, 62, a5, ec, c4, 6d, f2, 31, 3f, cc, d, 6e, 38, 6e, de, e, 66, c9, 63, db, ed, 9b, 9d, 4f, 6e, c, 52, f4, 1e, 4f, 25, 9d, bc, 1e, 1e, dc, f3, 1e, 53, 72, 20, ca, 1a, f4, 42, 89]
        //DEBUG - writing sm command [3, d1, 83, 7, ec, 80, 1d, be, 18, 61, b1, f5, e8, 58, 52, be, 96]
        //DEBUG - decoding SM packet [04, cb, 26, 87, 27, d1, 95, 3d, d3, 67, 32, c3, 21, 9c, 8d, 05, 33]
        input.push(&[
            0x04, 0xcb, 0x26, 0x87, 0x27, 0xd1, 0x95, 0x3d, 0xd3, 0x67, 0x32, 0xc3, 0x21, 0x9c, 0x8d, 0x05, 0x33,
        ]);
        //DEBUG - writing sm command [4, 8d, 1a, a7, c2, 4a, db, e0, 52, b4, 9f, ca, 57, 81, 26, 3e, f1]
        //DEBUG - decoding SM packet [0d, 0d, bf, de, 9e, 32, cb, 07, ae, f9, 33, 18, f4, 85, dd, ec, 56]
        input.push(&[
            0x0d, 0x0d, 0xbf, 0xde, 0x9e, 0x32, 0xcb, 0x07, 0xae, 0xf9, 0x33, 0x18, 0xf4, 0x85, 0xdd, 0xec, 0x56,
        ]);
        //DEBUG - writing sm command [d, d6, 4e, c9, 73, 28, 61, 67, b6, 6d, 23, c1, b3, f7, bf, 92, fd]

        let mut writer = Vec::<u8>::new();
        let controller =
            ExternalController::<_, 10>::new(SerialTransport::<NoopRawMutex, _, _>::new(PendingReader, &mut writer));
        let mut resources = Resources::new(Qos::None);
        let local_address = Address::random([0x41, 0x5A, 0xE3, 0x1E, 0x83, 0xE7]);
        let peer_address = Address::random([0x41, 0xaa, 0xaa, 0xaa, 0xaa, 0xe7]);
        let (stack, _bt_peripheral, _central, mut runner) = crate::new(controller, &mut resources)
            .set_random_address(local_address)
            .build();

        // TODO: set up a connection _stack.host.connections;

        let rng = ChaCha8Core::seed_from_u64(0x1234567891011);
        let rng = ChaCha8Rng::from(rng);

        let mut rng2 = rng.clone();
        let run_test = async {
            for sm_command in input {
                //let handle = stack.host.connections.handle(0);
                let handle = ConnHandle::new(0);
                let connections = &stack.host.connections;
                connections
                    .connect(
                        handle,
                        peer_address.kind,
                        peer_address.addr,
                        bt_hci::param::LeConnRole::Central,
                    )
                    .expect("HUHHUH??");
                let conn = connections.accept(bt_hci::param::LeConnRole::Central, &[]).await;
                println!("wat wat wat wat wat wat wat wat wat {:?}", conn.handle());
                stack
                    .host
                    .connections
                    .with_connected_handle(handle, |conn| {
                        conn.security_manager
                            .with_context(stack.host, &mut rng2, local_address, peer_address, handle)
                            .handle(sm_command)
                    })
                    .expect("unga bunga");

                yield_now().await;
            }
        };

        block_on(async {
            select! {
                r = runner.run(rng).fuse() => {
                    panic!("runner exited: {r:?}");
                }

                _ = run_test.fuse() => {
                    panic!("done?");
                }
            }
        });
    }

    struct PendingReader;

    impl ErrorType for PendingReader {
        type Error = Infallible;
    }

    impl embedded_io_async::Read for PendingReader {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            pending().await
        }
    }
}
