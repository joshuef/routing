// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved;
mod bootstrapping;
mod joining;

use self::{approved::Approved, bootstrapping::Bootstrapping, joining::Joining};
use crate::{
    comm::Comm,
    consensus::{self, Proof, Proven},
    error::{Result, RoutingError},
    event::Event,
    id::{FullId, P2pNode},
    messages::{Message, Variant},
    network_params::NetworkParams,
    rng::MainRng,
    section::{member_info, EldersInfo, MemberState, SectionKeyShare, SharedState, MIN_AGE},
    TransportConfig,
};
use bytes::Bytes;
use quic_p2p::IncomingConnections;
use serde::Serialize;
use std::{iter, net::SocketAddr};
use xor_name::Prefix;

#[cfg(feature = "mock_base")]
pub use self::{bootstrapping::BOOTSTRAP_TIMEOUT, joining::JOIN_TIMEOUT};

// Type to represent the various stages a node goes through during its lifetime.
#[allow(clippy::large_enum_variant)]
enum State {
    Bootstrapping(Bootstrapping),
    Joining(Joining),
    Approved(Approved),
    Terminated,
}

pub(crate) struct Stage {
    state: State,
    comm: Comm,
}

impl Stage {
    // Create the approved stage for the first node in the network.
    pub async fn first_node(
        transport_config: TransportConfig,
        full_id: FullId,
        network_params: NetworkParams,
        mut rng: MainRng,
    ) -> Result<Self> {
        let comm = Comm::new(transport_config).await?;
        let connection_info = comm.our_connection_info()?;
        let p2p_node = P2pNode::new(*full_id.public_id(), connection_info);

        let secret_key_set = consensus::generate_secret_key_set(&mut rng, 1);
        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        // Note: `ElderInfo` is normally signed with the previous key, but as we are the first node
        // of the network there is no previous key. Sign with the current key instead.
        let elders_info = create_first_elders_info(&public_key_set, &secret_key_share, p2p_node)?;
        let shared_state =
            create_first_shared_state(&public_key_set, &secret_key_share, elders_info)?;

        let section_key_share = SectionKeyShare {
            public_key_set,
            index: 0,
            secret_key_share,
        };

        let state = Approved::new(
            comm.clone(),
            shared_state,
            0,
            Some(section_key_share),
            full_id,
            network_params,
            rng,
        )?;

        Ok(Self {
            state: State::Approved(state),
            comm,
        })
    }

    pub async fn bootstrap(
        transport_config: TransportConfig,
        full_id: FullId,
        network_params: NetworkParams,
        rng: MainRng,
    ) -> Result<Self> {
        let (mut comm, mut connection) = Comm::from_bootstrapping(transport_config).await?;

        debug!(
            "Sending BootstrapRequest to {}",
            connection.remote_address()
        );
        comm.send_direct_message_on_conn(
            &full_id,
            &mut connection,
            Variant::BootstrapRequest(*full_id.public_id().name()),
        )
        .await?;

        let state = Bootstrapping::new(None, full_id.clone(), rng, comm.clone(), network_params);

        Ok(Self {
            state: State::Bootstrapping(state),
            comm,
        })
    }

    pub fn approved(&self) -> Option<&Approved> {
        match &self.state {
            State::Approved(stage) => Some(&stage),
            _ => None,
        }
    }

    pub fn approved_mut(&mut self) -> Option<&mut Approved> {
        // FIXME!!!!!!!!
        match &self.state {
            State::Approved(stage) => None, //Some(&mut stage),
            _ => None,
        }
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        match self.state {
            State::Bootstrapping(_) | State::Joining(_) | State::Approved(_) => {
                self.comm.our_connection_info()
            }
            State::Terminated => Err(RoutingError::InvalidState),
        }
    }

    pub fn listen_events(&mut self) -> Result<IncomingConnections> {
        match self.state {
            State::Bootstrapping(_) | State::Joining(_) | State::Approved(_) => {
                self.comm.listen_events()
            }
            State::Terminated => Err(RoutingError::InvalidState),
        }
    }

    pub async fn send_message_to_target(
        &mut self,
        recipient: &SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        match self.state {
            State::Bootstrapping(_) | State::Joining(_) | State::Approved(_) => {
                self.comm.send_message_to_target(recipient, msg).await
            }
            State::Terminated => Err(RoutingError::InvalidState),
        }
    }

    /// Process a message accordng to ccurrent stage.
    /// This function may return an Event that needs to be reported to the user.
    pub async fn process_message(
        &mut self,
        sender: SocketAddr,
        msg: Message,
    ) -> Result<Option<Event>> {
        match &mut self.state {
            State::Bootstrapping(stage) => {
                if let Some(joining) = stage.process_message(sender, msg).await? {
                    self.state = State::Joining(joining);
                }

                Ok(None)
            }
            State::Joining(stage) => {
                let (new_state, event_to_relay) = stage.process_message(sender, msg).await?;
                if let Some(approved) = new_state {
                    self.state = State::Approved(approved);
                }

                Ok(event_to_relay)
            }
            State::Approved(stage) => {
                let (new_state, event_to_relay) = stage.process_message(sender, msg).await?;
                if let Some(bootstrapping) = new_state {
                    self.state = State::Bootstrapping(bootstrapping);
                }

                Ok(event_to_relay)
            }
            State::Terminated => Err(RoutingError::InvalidState),
        }
    }
    /// Returns whether this node is running or has been terminated.
    pub fn is_running(&self) -> bool {
        match self.state {
            State::Bootstrapping(_) | State::Joining(_) | State::Approved(_) => true,
            State::Terminated => false,
        }
    }

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix> {
        match &self.state {
            State::Bootstrapping(_) | State::Joining(_) | State::Terminated => None,
            State::Approved(stage) => Some(stage.shared_state.our_prefix()),
        }
    }
}

// Create `EldersInfo` for the first node.
fn create_first_elders_info(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    p2p_node: P2pNode,
) -> Result<Proven<EldersInfo>> {
    let name = *p2p_node.name();
    let node = (name, p2p_node);
    let elders_info = EldersInfo::new(iter::once(node).collect(), Prefix::default());
    let proof = create_first_proof(pk_set, sk_share, &elders_info)?;
    Ok(Proven::new(elders_info, proof))
}

fn create_first_shared_state(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    elders_info: Proven<EldersInfo>,
) -> Result<SharedState> {
    let mut shared_state = SharedState::new(elders_info.proof.public_key, elders_info);

    for p2p_node in shared_state.sections.our().elders.values() {
        let proof = create_first_proof(
            pk_set,
            sk_share,
            &member_info::to_sign(p2p_node.name(), MemberState::Joined),
        )?;
        shared_state
            .our_members
            .add(p2p_node.clone(), MIN_AGE, proof);
    }

    Ok(shared_state)
}

fn create_first_proof<T: Serialize>(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    payload: &T,
) -> Result<Proof> {
    let bytes = bincode::serialize(payload)?;
    let signature_share = sk_share.sign(&bytes);
    let signature = pk_set
        .combine_signatures(iter::once((0, &signature_share)))
        .map_err(|_| RoutingError::InvalidSignatureShare)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}
