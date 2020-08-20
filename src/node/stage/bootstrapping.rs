// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    core::Core,
    error::Result,
    id::{FullId, P2pNode},
    messages::{BootstrapResponse, Message, MessageStatus, Variant, VerifyStatus},
    relocation::{RelocatePayload, SignedRelocateDetails},
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
}

impl Bootstrapping {
    pub fn new(relocate_details: Option<SignedRelocateDetails>) -> Self {
        Self {
            pending_requests: Default::default(),
            relocate_details,
        }
    }

    pub fn decide_message_status(&self, msg: &Message) -> Result<MessageStatus> {
        match msg.variant() {
            Variant::BootstrapResponse(_) => {
                verify_message(msg)?;
                Ok(MessageStatus::Useful)
            }

            Variant::NeighbourInfo { .. }
            | Variant::UserMessage(_)
            | Variant::BouncedUntrustedMessage(_)
            | Variant::DKGMessage { .. }
            | Variant::DKGOldElders { .. } => Ok(MessageStatus::Unknown),

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
            | Variant::Vote { .. } => Ok(MessageStatus::Useless),
        }
    }

    pub async fn handle_bootstrap_response(
        &mut self,
        core: &mut Core,
        sender: P2pNode,
        response: BootstrapResponse,
    ) -> Result<Option<JoinParams>> {
        // Ignore messages from peers we didn't send `BootstrapRequest` to.
        if !self.pending_requests.contains(sender.peer_addr()) {
            debug!(
                "Ignoring BootstrapResponse from unexpected peer: {}",
                sender,
            );
            //TODO?? core.transport.disconnect(*sender.peer_addr());
            return Ok(None);
        }

        match response {
            BootstrapResponse::Join {
                elders_info,
                section_key,
            } => {
                info!(
                    "Joining a section {:?} (given by {:?})",
                    elders_info, sender
                );

                let relocate_payload = self.join_section(core, &elders_info)?;
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
                self.reconnect_to_new_section(core, new_conn_infos).await?;
                Ok(None)
            }
        }
    }

    pub async fn send_bootstrap_request(&mut self, core: &mut Core, dst: SocketAddr) -> Result<()> {
        //let token = core.timer.schedule(BOOTSTRAP_TIMEOUT);
        //let _ = self.timeout_tokens.insert(token, dst);

        let xorname = match &self.relocate_details {
            Some(details) => *details.destination(),
            None => *core.name(),
        };

        debug!("Sending BootstrapRequest to {}.", dst);
        core.send_direct_message(&dst, Variant::BootstrapRequest(xorname))
            .await
    }

    async fn reconnect_to_new_section(
        &mut self,
        core: &mut Core,
        new_conn_infos: Vec<SocketAddr>,
    ) -> Result<()> {
        // TODO???
        /*for addr in self.pending_requests.drain() {
            core.transport.disconnect(addr);
        }*/

        for conn_info in new_conn_infos {
            self.send_bootstrap_request(core, conn_info).await?;
        }

        Ok(())
    }

    fn join_section(
        &mut self,
        core: &mut Core,
        elders_info: &EldersInfo,
    ) -> Result<Option<RelocatePayload>> {
        let relocate_details = self.relocate_details.take();
        let destination = match &relocate_details {
            Some(details) => *details.destination(),
            None => *core.name(),
        };
        let old_full_id = core.full_id().clone();

        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            elders_info.prefix.bit_count() + extra_split_count,
            destination,
        );

        if !name_prefix.matches(core.name()) {
            let new_full_id = FullId::within_range(core.rng_mut(), &name_prefix.range_inclusive());
            info!("Changing name to {}.", new_full_id.public_id().name());
            core.set_full_id(new_full_id);
        }

        if let Some(details) = relocate_details {
            let payload = RelocatePayload::new(details, core.id(), &old_full_id)?;
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

fn verify_message(msg: &Message) -> Result<()> {
    msg.verify(iter::empty())
        .and_then(VerifyStatus::require_full)
}
