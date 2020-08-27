// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::joining::Joining;
use crate::{
    comm::Comm,
    error::Result,
    id::{FullId, P2pNode},
    messages::{BootstrapResponse, Message, Variant, VerifyStatus},
    relocation::{RelocatePayload, SignedRelocateDetails},
    rng::MainRng,
    section::EldersInfo,
    time::Duration,
};
use fxhash::FxHashSet;
use std::{iter, net::SocketAddr};
use xor_name::Prefix;

/// Time after which bootstrap is cancelled (and possibly retried).
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

// The bootstrapping stage - node is trying to find the section to join.
pub(crate) struct Bootstrapping {
    // Using `FxHashSet` for deterministic iteration order.
    pending_requests: FxHashSet<SocketAddr>,
    relocate_details: Option<SignedRelocateDetails>,
    full_id: FullId,
    rng: MainRng,
    comm: Comm,
}

impl Bootstrapping {
    pub fn new(
        relocate_details: Option<SignedRelocateDetails>,
        full_id: FullId,
        rng: MainRng,
        comm: Comm,
    ) -> Self {
        Self {
            pending_requests: Default::default(),
            relocate_details,
            full_id,
            rng,
            comm,
        }
    }

    pub async fn process_message(
        &mut self,
        sender: SocketAddr,
        msg: Message,
    ) -> Result<Option<Joining>> {
        match msg.variant() {
            Variant::BootstrapResponse(response) => {
                msg.verify(iter::empty())
                    .and_then(VerifyStatus::require_full)?;

                match self
                    .handle_bootstrap_response(
                        msg.src().to_sender_node(Some(sender))?,
                        response.clone(),
                    )
                    .await?
                {
                    Some(JoinParams {
                        elders_info,
                        section_key,
                        relocate_payload,
                    }) => {
                        let joining = Joining::new(
                            self.comm.clone(),
                            elders_info,
                            section_key,
                            relocate_payload,
                            self.full_id.clone(),
                        )
                        .await?;

                        Ok(Some(joining))
                    }
                    None => Ok(None),
                }
            }

            Variant::NeighbourInfo { .. }
            | Variant::UserMessage(_)
            | Variant::BouncedUntrustedMessage(_)
            | Variant::DKGMessage { .. }
            | Variant::DKGOldElders { .. } => {
                debug!("Unknown message from {}: {:?} ", sender, msg);
                Ok(None)
            }

            Variant::NodeApproval(_)
            | Variant::EldersUpdate { .. }
            | Variant::Promote { .. }
            | Variant::NotifyLagging { .. }
            | Variant::Relocate(_)
            | Variant::MessageSignature(_)
            | Variant::BootstrapRequest(_)
            | Variant::JoinRequest(_)
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::Ping
            | Variant::BouncedUnknownMessage { .. }
            | Variant::Vote { .. } => {
                debug!("Useless message from {}: {:?}", sender, msg);
                Ok(None)
            }
        }
    }

    pub async fn handle_bootstrap_response(
        &mut self,
        sender: P2pNode,
        response: BootstrapResponse,
    ) -> Result<Option<JoinParams>> {
        // TODO: do we really need to keep track of which peers we are trying to bootstrap to?
        // Ignore messages from peers we didn't send `BootstrapRequest` to.
        /*if !self.pending_requests.contains(sender.peer_addr()) {
            debug!(
                "Ignoring BootstrapResponse from unexpected peer: {}",
                sender,
            );
            //TODO?? core.transport.disconnect(*sender.peer_addr());
            return Ok(None);
        }*/

        match response {
            BootstrapResponse::Join {
                elders_info,
                section_key,
            } => {
                info!(
                    "Joining a section {:?} (given by {:?})",
                    elders_info, sender
                );

                let relocate_payload = self.join_section(&elders_info)?;
                Ok(Some(JoinParams {
                    elders_info,
                    section_key,
                    relocate_payload,
                }))
            }
            BootstrapResponse::Rebootstrap(new_conn_infos) => {
                info!(
                    "Bootstrapping redirected to another set of peers: {:?}",
                    new_conn_infos
                );
                self.reconnect_to_new_section(new_conn_infos).await?;
                Ok(None)
            }
        }
    }

    pub async fn send_bootstrap_request(&mut self, dst: SocketAddr) -> Result<()> {
        let xorname = match &self.relocate_details {
            Some(details) => *details.destination(),
            None => *self.full_id.public_id().name(),
        };

        debug!("Sending BootstrapRequest to {}.", dst);
        self.comm
            .send_direct_message(&self.full_id, &dst, Variant::BootstrapRequest(xorname))
            .await
    }

    async fn reconnect_to_new_section(&mut self, new_conn_infos: Vec<SocketAddr>) -> Result<()> {
        // TODO???
        /*for addr in self.pending_requests.drain() {
            core.transport.disconnect(addr);
        }*/

        for conn_info in new_conn_infos {
            self.send_bootstrap_request(conn_info).await?;
        }

        Ok(())
    }

    fn join_section(&mut self, elders_info: &EldersInfo) -> Result<Option<RelocatePayload>> {
        let relocate_details = self.relocate_details.take();
        let destination = match &relocate_details {
            Some(details) => *details.destination(),
            None => *self.full_id.public_id().name(),
        };
        let old_full_id = self.full_id.clone();

        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            elders_info.prefix.bit_count() + extra_split_count,
            destination,
        );

        if !name_prefix.matches(self.full_id.public_id().name()) {
            let new_full_id = FullId::within_range(&mut self.rng, &name_prefix.range_inclusive());
            info!("Changing name to {}.", new_full_id.public_id().name());
            self.full_id = new_full_id;
        }

        if let Some(details) = relocate_details {
            let payload = RelocatePayload::new(details, self.full_id.public_id(), &old_full_id)?;
            Ok(Some(payload))
        } else {
            Ok(None)
        }
    }
}

pub(crate) struct JoinParams {
    pub elders_info: EldersInfo,
    pub section_key: bls::PublicKey,
    pub relocate_payload: Option<RelocatePayload>,
}
