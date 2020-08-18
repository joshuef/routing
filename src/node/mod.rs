// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod event_stream;
mod stage;
#[cfg(all(test, feature = "mock"))]
mod tests;

#[cfg(feature = "mock_base")]
pub use self::stage::{BOOTSTRAP_TIMEOUT, JOIN_TIMEOUT};

pub use self::event_stream::EventStream;
use self::stage::{Approved, Bootstrapping, JoinParams, Joining, RelocateParams, Stage};
use crate::{
    core::Core,
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    log_utils,
    messages::{EldersUpdate, Message, MessageStatus, Variant},
    network_params::NetworkParams,
    //relocation::SignedRelocateDetails,
    rng::{self, MainRng},
    section::SectionProofChain,
    section::SharedState,
    TransportConfig,
};

use bytes::Bytes;
use itertools::Itertools;
use std::net::SocketAddr;
use xor_name::{Prefix, XorName};

#[cfg(all(test, feature = "mock"))]
use crate::{
    consensus::{ConsensusEngine, DkgResult},
    section::SectionKeyShare,
};
#[cfg(feature = "mock_base")]
use {crate::section::EldersInfo, std::collections::BTreeSet};

/// Node configuration.
pub struct NodeConfig {
    /// If true, configures the node to start a new network instead of joining an existing one.
    pub first: bool,
    /// The ID of the node or `None` for randomly generated one.
    pub full_id: Option<FullId>,
    /// Configuration for the underlying network transport.
    pub transport_config: TransportConfig,
    /// Global network parameters. Must be identical for all nodes in the network.
    pub network_params: NetworkParams,
    /// Random number generator to be used by the node. Can be used to achieve repeatable tests by
    /// providing a pre-seeded RNG. By default uses a random seed provided by the OS.
    pub rng: MainRng,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            first: false,
            full_id: None,
            transport_config: TransportConfig::default(),
            network_params: NetworkParams::default(),
            rng: rng::new(),
        }
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full
/// routing node.
///
/// A node is a part of the network that can route messages and be a member of a section or group
/// location. Its methods can be used to send requests and responses as either an individual
/// `Node` or as a part of a section or group location. Their `src` argument indicates that
/// role, and can be any [`SrcLocation`](enum.SrcLocation.html).
pub struct Node {
    core: Core,
    stage: Stage,
}

impl Node {
    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    /// Create new node using the given config.
    ///
    /// Returns the node itself, the user event receiver and the client network
    /// event receiver.
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let first = config.first;
        let mut core = Core::new(config)?;

        let stage = if first {
            match Approved::first(&mut core) {
                Ok(stage) => {
                    info!("{} Started a new network as a seed node.", core.name());
                    Stage::Approved(stage)
                }
                Err(error) => {
                    error!(
                        "{} Failed to start the first node: {:?}",
                        core.name(),
                        error
                    );
                    Stage::Terminated
                }
            }
        } else {
            info!("{} Bootstrapping a new node.", core.name());
            core.bootstrap().await?;
            Stage::Bootstrapping(Bootstrapping::new(None))
        };

        Ok(Self { stage, core })
    }

    /// Starts listening for events returning a stream where to read them from.
    pub fn listen_events(&self) -> Result<EventStream> {
        self.core.listen_events()
    }

    /// Pauses the node in order to be upgraded and/or restarted.
    /// Returns `InvalidState` error if the node is not a member of any section yet.
    /*pub fn pause(self) -> Result<PausedState> {
        if let Stage::Approved(stage) = self.stage {
            info!("Pause");

            let state = stage.pause(self.core);

            Ok(state)
        } else {
            Err(RoutingError::InvalidState)
        }
    }

    /// Resume previously paused node.
    pub fn resume(mut state: PausedState) -> (Self, Receiver<Event>) {
        let (timer_tx, timer_rx) = crossbeam_channel::unbounded();
        let transport_rx = state
            .transport_rx
            .take()
            .expect("PausedState is incomplete");
        let (user_event_tx, user_event_rx) = crossbeam_channel::unbounded();

        let (stage, core) = Approved::resume(state, timer_tx, user_event_tx);

        info!("Resume");

        let node = Self {
            stage: Stage::Approved(stage),
            core,
            timer_rx,
            timer_rx_idx: 0,
            transport_rx,
            transport_rx_idx: 0,
        };

        (node, user_event_rx)
    }
    */

    /// Returns whether this node is running or has been terminated.
    pub fn is_running(&self) -> bool {
        !matches!(self.stage, Stage::Terminated)
    }

    /// Returns the `PublicId` of this node.
    pub fn id(&self) -> &PublicId {
        self.core.id()
    }

    /// The name of this node.
    pub fn name(&self) -> &XorName {
        self.id().name()
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.core.our_connection_info()
    }

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix> {
        if let Stage::Approved(stage) = &self.stage {
            Some(stage.shared_state.our_prefix())
        } else {
            None
        }
    }

    /// Finds out if the given XorName matches our prefix. Returns error if we don't have a prefix
    /// because we haven't joined any section yet.
    pub fn matches_our_prefix(&self, name: &XorName) -> Result<bool> {
        if let Some(prefix) = self.our_prefix() {
            Ok(prefix.matches(name))
        } else {
            Err(RoutingError::InvalidState)
        }
    }

    /// Returns whether the node is Elder.
    pub fn is_elder(&self) -> bool {
        self.stage
            .approved()
            .map(|stage| {
                stage
                    .shared_state
                    .sections
                    .our()
                    .elders
                    .contains_key(self.core.name())
            })
            .unwrap_or(false)
    }

    /// Returns the information of all the current section elders.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.stage
            .approved()
            .into_iter()
            .flat_map(|stage| stage.shared_state.sections.our_elders())
    }

    /// Returns the elders of our section sorted by their distance to `name` (closest first).
    pub fn our_elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<&P2pNode> {
        self.our_elders()
            .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
            .collect()
    }

    /// Returns the information of all the current section adults.
    pub fn our_adults(&self) -> impl Iterator<Item = &P2pNode> {
        self.stage
            .approved()
            .into_iter()
            .flat_map(|stage| stage.shared_state.our_adults())
    }

    /// Returns the adults of our section sorted by their distance to `name` (closest first).
    /// If we are not elder or if there are no adults in the section, returns empty vec.
    pub fn our_adults_sorted_by_distance_to(&self, name: &XorName) -> Vec<&P2pNode> {
        self.our_adults()
            .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
            .collect()
    }

    /// Checks whether the given location represents self.
    pub fn in_dst_location(&self, dst: &DstLocation) -> bool {
        match &self.stage {
            Stage::Bootstrapping(_) | Stage::Joining(_) => match dst {
                DstLocation::Node(name) => name == self.core.name(),
                DstLocation::Section(_) => false,
                DstLocation::Direct => true,
                DstLocation::Client(_) => false,
            },
            Stage::Approved(stage) => {
                dst.contains(self.core.name(), stage.shared_state.our_prefix())
            }
            Stage::Terminated => false,
        }
    }

    /// Vote for a user-defined event.
    /// Returns `InvalidState` error if we are not an elder.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) -> Result<()> {
        let our_id = self.core.id();
        if let Some(stage) = self
            .stage
            .approved_mut()
            .filter(|stage| stage.is_our_elder(our_id))
        {
            stage.vote_for_user_event(event);
            Ok(())
        } else {
            Err(RoutingError::InvalidState)
        }
    }

    /// Send a message.
    pub async fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<(), RoutingError> {
        if let DstLocation::Direct = dst {
            return Err(RoutingError::BadLocation);
        }

        let _log_ident = self.set_log_ident();

        match &mut self.stage {
            Stage::Bootstrapping(_) | Stage::Joining(_) | Stage::Terminated => {
                Err(RoutingError::InvalidState)
            }
            Stage::Approved(stage) => {
                stage
                    .send_routing_message(
                        &mut self.core,
                        src,
                        dst,
                        Variant::UserMessage(content),
                        None,
                    )
                    .await
            }
        }
    }

    /// Send a message to a client peer.
    pub async fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        self.core.send_message_to_target(&peer_addr, msg).await
    }

    /// Disconnect form a client peer.
    pub fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<()> {
        // TODO: remove funciton??
        // self.core.transport.disconnect(peer_addr);
        Ok(())
    }

    /// Returns the current BLS public key set or `RoutingError::InvalidState` if we are not joined
    /// yet.
    pub fn public_key_set(&self) -> Result<&bls::PublicKeySet> {
        self.stage
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| &share.public_key_set)
            .ok_or(RoutingError::InvalidState)
    }

    /// Returns the current BLS secret key share or `RoutingError::InvalidState` if we are not
    /// elder.
    pub fn secret_key_share(&self) -> Result<&bls::SecretKeyShare> {
        self.stage
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| &share.secret_key_share)
            .ok_or(RoutingError::InvalidState)
    }

    /// Returns our section proof chain, or `None` if we are not joined yet.
    pub fn our_history(&self) -> Option<&SectionProofChain> {
        self.stage
            .approved()
            .map(|stage| &stage.shared_state.our_history)
    }

    /// Returns our index in the current BLS group or `RoutingError::InvalidState` if section key was
    /// not generated yet.
    pub fn our_index(&self) -> Result<usize> {
        self.stage
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| share.index)
            .ok_or(RoutingError::InvalidState)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Input handling
    ////////////////////////////////////////////////////////////////////////////

    async fn handle_connection_failure(&mut self, addr: SocketAddr) -> Result<()> {
        if let Stage::Approved(stage) = &mut self.stage {
            stage
                .handle_connection_failure(&mut self.core, addr)
                .await?;
        } else {
            trace!("ConnectionFailure from {}", addr);
        }

        Ok(())
    }

    async fn handle_new_message(&mut self, sender: SocketAddr, bytes: Bytes) {
        let msg = match Message::from_bytes(&bytes) {
            Ok(msg) => msg,
            Err(error) => {
                debug!("Failed to deserialize message: {:?}", error);
                return;
            }
        };

        if let Err(error) = self.try_handle_message(sender, msg).await {
            debug!("Failed to handle message: {:?}", error);
        }
    }

    // TODO: handle lost peer???
    /*fn handle_unsent_message(&mut self, addr: SocketAddr, msg: Bytes, msg_token: Token) {
        match self.core.handle_unsent_message(addr, msg, msg_token) {
            PeerStatus::Normal => (),
            PeerStatus::Lost => self.handle_peer_lost(addr),
        }
    }*/

    async fn handle_timeout(&mut self, token: u64) -> Result<()> {
        // TODO???
        /*if self.core.transport.handle_timeout(token) {
            return;
        }*/

        match &mut self.stage {
            Stage::Bootstrapping(stage) => stage.handle_timeout(&mut self.core, token),
            Stage::Joining(stage) => {} //stage.handle_timeout(&mut self.core, token).await?,
            Stage::Approved(stage) => stage.handle_timeout(&mut self.core, token).await?,
            Stage::Terminated => {}
        }

        Ok(())
    }

    fn handle_peer_lost(&mut self, peer_addr: SocketAddr) {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.handle_peer_lost(&self.core, peer_addr);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    async fn try_handle_message(&mut self, sender: SocketAddr, msg: Message) -> Result<()> {
        trace!("try handle message {:?}", msg);

        self.try_relay_message(&msg).await?;

        if !self.in_dst_location(msg.dst()) {
            return Ok(());
        }

        // TODO: filter messages which are already handled???
        /*if self.core.msg_filter.contains_incoming(&msg) {
            trace!("not handling message - already handled: {:?}", msg);
            return Ok(());
        }*/

        match self.decide_message_status(&msg)? {
            MessageStatus::Useful => {
                //self.core.msg_filter.insert_incoming(&msg);
                self.handle_message(sender, msg).await
            }
            MessageStatus::Untrusted => {
                debug!("Untrusted message from {}: {:?} ", sender, msg);
                self.handle_untrusted_message(sender, msg).await
            }
            MessageStatus::Unknown => {
                debug!("Unknown message from {}: {:?} ", sender, msg);
                //self.handle_unknown_message(sender, msg).await
                Ok(())
            }
            MessageStatus::Useless => {
                debug!("Useless message from {}: {:?}", sender, msg);
                Ok(())
            }
        }
    }

    async fn try_relay_message(&mut self, msg: &Message) -> Result<()> {
        if !self.in_dst_location(msg.dst()) || msg.dst().is_section() {
            // Relay closer to the destination or broadcast to the rest of our section.
            self.relay_message(msg).await
        } else {
            Ok(())
        }
    }

    async fn relay_message(&mut self, msg: &Message) -> Result<()> {
        match &mut self.stage {
            Stage::Approved(stage) => stage.relay_message(&mut self.core, msg).await,
            Stage::Bootstrapping(_) | Stage::Joining(_) | Stage::Terminated => Ok(()),
        }
    }

    fn decide_message_status(&self, msg: &Message) -> Result<MessageStatus> {
        match &self.stage {
            Stage::Bootstrapping(stage) => stage.decide_message_status(msg),
            Stage::Joining(stage) => stage.decide_message_status(msg),
            Stage::Approved(stage) => stage.decide_message_status(self.core.id(), msg),
            Stage::Terminated => Ok(MessageStatus::Useless),
        }
    }

    async fn handle_message(&mut self, sender: SocketAddr, msg: Message) -> Result<()> {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.update_section_knowledge(&mut self.core, &msg).await?;
        }

        Ok(())
    }

    /*async fn dispatch_message(&mut self, sender: Option<SocketAddr>, msg: Message) -> Result<()> {
        trace!("Got {:?}", msg);

        match &mut self.stage {
            Stage::Bootstrapping(stage) => match msg.variant() {
                Variant::BootstrapResponse(response) => {
                    if let Some(params) = stage
                        .handle_bootstrap_response(
                            &mut self.core,
                            msg.src().to_sender_node(sender)?,
                            response.clone(),
                        )
                        .await?
                    {
                        self.join(params).await?;
                    }
                }
                _ => unreachable!(),
            },
            Stage::Joining(stage) => match msg.variant() {
                Variant::BootstrapResponse(BootstrapResponse::Join {
                    elders_info,
                    section_key,
                }) => {
                    stage
                        .handle_bootstrap_response(
                            &mut self.core,
                            msg.src().to_sender_node(sender)?,
                            elders_info.clone(),
                            *section_key,
                        )
                        .await?
                }
                Variant::NodeApproval(payload) => {
                    let connect_type = stage.connect_type();
                    let msg_backlog = stage.take_message_backlog();
                    let section_key = *msg.proof_chain_last_key()?;

                    self.approve(connect_type, msg_backlog, section_key, payload.clone())?
                }
                _ => unreachable!(),
            },
            Stage::Approved(stage) => match msg.variant() {
                Variant::NeighbourInfo { elders_info, .. } => {
                    msg.dst().check_is_section()?;
                    stage.handle_neighbour_info(
                        &mut self.core,
                        elders_info.value.clone(),
                        *msg.proof_chain_last_key()?,
                    )?;
                }
                Variant::EldersUpdate(payload) => {
                    let section_key = *msg.proof_chain_last_key()?;
                    stage.handle_elders_update(&mut self.core, section_key, payload.clone())?
                }
                Variant::Promote {
                    shared_state,
                    parsec_version,
                } => {
                    stage
                        .handle_promote(&mut self.core, shared_state.clone(), *parsec_version)
                        .await?
                }
                Variant::NotifyLagging {
                    shared_state,
                    parsec_version,
                } => {
                    stage
                        .handle_lagging(&mut self.core, shared_state.clone(), *parsec_version)
                        .await?
                }
                Variant::Relocate(_) => {
                    msg.src().check_is_section()?;
                    let signed_relocate = SignedRelocateDetails::new(msg)?;
                    if let Some(params) = stage.handle_relocate(&mut self.core, signed_relocate) {
                        self.relocate(params).await?;
                    }
                }
                Variant::MessageSignature(accumulating_msg) => {
                    let result = stage
                        .handle_message_signature(
                            &mut self.core,
                            *accumulating_msg.clone(),
                            *msg.src().as_node()?,
                        )
                        .await;
                    if let Some(addr) = sender {
                        stage
                            .check_lagging(&mut self.core, &addr, &accumulating_msg.proof_share)
                            .await?;
                    }
                    result?
                }
                Variant::BootstrapRequest(name) => {
                    stage
                        .handle_bootstrap_request(
                            &mut self.core,
                            msg.src().to_sender_node(sender)?,
                            *name,
                        )
                        .await?
                }
                Variant::JoinRequest(join_request) => {
                    stage
                        .handle_join_request(
                            &mut self.core,
                            msg.src().to_sender_node(sender)?,
                            *join_request.clone(),
                        )
                        .await?
                }
                Variant::ParsecRequest(version, request) => {
                    stage
                        .handle_parsec_request(
                            &mut self.core,
                            *version,
                            request.clone(),
                            msg.src().to_sender_node(sender)?,
                        )
                        .await?;
                }
                Variant::ParsecResponse(version, response) => {
                    stage
                        .handle_parsec_response(
                            &mut self.core,
                            *version,
                            response.clone(),
                            *msg.src().as_node()?,
                        )
                        .await?;
                }
                Variant::UserMessage(content) => {
                    self.core.send_event(Event::MessageReceived {
                        content: content.clone(),
                        src: msg.src().src_location(),
                        dst: *msg.dst(),
                    });
                }
                Variant::BouncedUntrustedMessage(message) => stage
                    .handle_bounced_untrusted_message(
                        &mut self.core,
                        msg.src().to_sender_node(sender)?,
                        *msg.dst_key(),
                        *message.clone(),
                    ),
                Variant::BouncedUnknownMessage { src_key, message } => stage
                    .handle_bounced_unknown_message(
                        &mut self.core,
                        msg.src().to_sender_node(sender)?,
                        message.clone(),
                        src_key,
                    ),
                Variant::DKGMessage {
                    participants,
                    section_key_index,
                    message,
                } => {
                    stage
                        .handle_dkg_message(
                            &mut self.core,
                            participants.clone(),
                            *section_key_index,
                            message.clone(),
                            *msg.src().as_node()?,
                        )
                        .await?;
                }
                Variant::DKGOldElders {
                    participants,
                    section_key_index,
                    public_key_set,
                } => {
                    stage
                        .handle_dkg_old_elders(
                            &mut self.core,
                            participants.clone(),
                            *section_key_index,
                            public_key_set.clone(),
                            *msg.src().as_node()?,
                        )
                        .await?;
                }
                Variant::Vote {
                    content,
                    proof_share,
                } => {
                    let result = stage
                        .handle_unordered_vote(&mut self.core, content.clone(), proof_share.clone())
                        .await;
                    if let Some(addr) = sender {
                        stage
                            .check_lagging(&mut self.core, &addr, proof_share)
                            .await?;
                    }

                    result?
                }
                Variant::NodeApproval(_) | Variant::BootstrapResponse(_) | Variant::Ping => {
                    unreachable!()
                }
            },
            Stage::Terminated => unreachable!(),
        }

        Ok(())
    }*/

    async fn handle_untrusted_message(&mut self, sender: SocketAddr, msg: Message) -> Result<()> {
        match &self.stage {
            Stage::Approved(stage) => {
                stage
                    .handle_untrusted_message(&mut self.core, Some(sender), msg)
                    .await
            }
            Stage::Bootstrapping(_) | Stage::Joining(_) | Stage::Terminated => unreachable!(),
        }
    }

    /*async fn handle_unknown_message(&mut self, sender: SocketAddr, msg: Message) -> Result<()> {
        match &mut self.stage {
            Stage::Bootstrapping(stage) => stage.handle_unknown_message(sender, msg),
            Stage::Joining(stage) => stage.handle_unknown_message(sender, msg),
            Stage::Approved(stage) => {
                stage
                    .handle_unknown_message(&mut self.core, Some(sender), msg.to_bytes())
                    .await?
            }
            Stage::Terminated => (),
        }

        Ok(())
    }*/

    ////////////////////////////////////////////////////////////////////////////
    // Transitions
    ////////////////////////////////////////////////////////////////////////////

    // Transition from Bootstrapping to Joining
    async fn join(&mut self, params: JoinParams) -> Result<()> {
        let JoinParams {
            elders_info,
            section_key,
            relocate_payload,
        } = params;

        self.stage = Stage::Joining(
            Joining::new(&mut self.core, elders_info, section_key, relocate_payload).await?,
        );

        Ok(())
    }

    // Transition from Joining to Approved
    fn approve(
        &mut self,
        connect_type: Connected,
        section_key: bls::PublicKey,
        elders_update: EldersUpdate,
    ) -> Result<()> {
        info!(
            "This node has been approved to join the network at {:?}!",
            elders_update.elders_info.value.prefix,
        );

        let shared_state = SharedState::new(section_key, elders_update.elders_info);
        let stage = Approved::new(
            &mut self.core,
            shared_state,
            elders_update.parsec_version,
            None,
        )?;
        self.stage = Stage::Approved(stage);

        self.core.send_event(Event::Connected(connect_type));

        Ok(())
    }

    // Transition from Approved to Bootstrapping on relocation
    async fn relocate(&mut self, params: RelocateParams) -> Result<()> {
        let RelocateParams {
            conn_infos,
            details,
        } = params;

        let mut stage = Bootstrapping::new(Some(details));

        for conn_info in conn_infos {
            stage
                .send_bootstrap_request(&mut self.core, conn_info)
                .await?;
        }

        self.stage = Stage::Bootstrapping(stage);
        Ok(())
    }

    fn set_log_ident(&self) -> log_utils::Guard {
        use std::fmt::Write;
        log_utils::set_ident(|buffer| match &self.stage {
            Stage::Bootstrapping(_) => write!(buffer, "{}(?) ", self.name()),
            Stage::Joining(stage) => write!(
                buffer,
                "{}({:b}?) ",
                self.name(),
                stage.target_section_elders_info().prefix,
            ),
            Stage::Approved(stage) => {
                if stage.is_our_elder(self.core.id()) {
                    write!(
                        buffer,
                        "{}({:b}v{}!) ",
                        self.core.name(),
                        stage.shared_state.our_prefix(),
                        stage.shared_state.our_history.last_key_index()
                    )
                } else {
                    write!(
                        buffer,
                        "{}({:b}) ",
                        self.core.name(),
                        stage.shared_state.our_prefix()
                    )
                }
            }
            Stage::Terminated => write!(buffer, "[terminated]"),
        })
    }
}

#[cfg(feature = "mock_base")]
impl Node {
    /// Returns whether the node is approved member of a section.
    pub fn is_approved(&self) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.is_ready(&self.core))
            .unwrap_or(false)
    }

    /// Indicates if there are any pending observations in the parsec object
    pub fn has_unpolled_observations(&self) -> bool {
        self.stage
            .approved()
            .map(|stage| {
                stage
                    .consensus_engine
                    .parsec_map()
                    .has_unpolled_observations()
            })
            .unwrap_or(false)
    }

    /// Returns the version of the latest Parsec instance of this node.
    pub fn parsec_last_version(&self) -> u64 {
        self.stage
            .approved()
            .map(|stage| stage.consensus_engine.parsec_version())
            .unwrap_or(0)
    }

    /// Checks whether the given location represents self.
    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        src.contains(self.core.name())
    }

    /// Returns the info about our neighbour sections.
    pub fn neighbour_sections(&self) -> impl Iterator<Item = &EldersInfo> {
        self.shared_state()
            .into_iter()
            .flat_map(|state| state.sections.neighbours())
    }

    /// Returns the info about our sections or `None` if we are not joined yet.
    pub fn our_section(&self) -> Option<&EldersInfo> {
        self.shared_state().map(|state| state.sections.our())
    }

    /// Returns the prefixes of all sections known to us
    pub fn prefixes(&self) -> BTreeSet<Prefix> {
        self.shared_state()
            .map(|state| state.sections.prefixes().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the elders in our and neighbouring sections.
    pub fn known_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.shared_state()
            .into_iter()
            .flat_map(|state| state.sections.elders())
    }

    /// Returns whether the given peer is an elder known to us.
    pub fn is_peer_elder(&self, name: &XorName) -> bool {
        self.shared_state()
            .map(|state| state.is_peer_elder(name))
            .unwrap_or(false)
    }

    /// Returns whether the given peer is an elder of our section.
    pub fn is_peer_our_elder(&self, name: &XorName) -> bool {
        self.shared_state()
            .map(|state| state.is_peer_our_elder(name))
            .unwrap_or(false)
    }

    /// Returns the members in our section and elders we know.
    pub fn known_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.shared_state()
            .into_iter()
            .flat_map(|state| state.known_nodes())
    }

    /// Returns whether the given `XorName` is a member of our section.
    pub fn is_peer_our_member(&self, name: &XorName) -> bool {
        self.shared_state()
            .map(|state| state.our_members.contains(name))
            .unwrap_or(false)
    }

    /// Returns their knowledge
    pub fn get_their_knowledge(&self, prefix: &Prefix) -> u64 {
        self.shared_state()
            .map(|state| state.sections.knowledge_by_section(prefix))
            .unwrap_or(0)
    }

    /// If our section is the closest one to `name`, returns all names in our section *including
    /// ours*, otherwise returns `None`.
    pub fn close_names(&self, name: &XorName) -> Option<Vec<XorName>> {
        let state = self.shared_state()?;
        if state.our_prefix().matches(name) {
            Some(
                state
                    .sections
                    .our_elders()
                    .map(|p2p_node| *p2p_node.name())
                    .collect(),
            )
        } else {
            None
        }
    }

    /// Returns the number of elders this node is using.
    pub fn elder_size(&self) -> usize {
        self.core.network_params().elder_size
    }

    /// Size at which our section splits. Since this is configurable, this method is used to
    /// obtain it.
    pub fn recommended_section_size(&self) -> usize {
        self.core.network_params().recommended_section_size
    }

    /// Provide a SectionProofSlice that proves the given signature to the given destination.
    pub fn prove(&self, target: &DstLocation) -> Option<SectionProofChain> {
        self.shared_state().map(|state| state.prove(target, None))
    }

    /// If this node is elder and `name` belongs to a member of our section, returns the age
    /// counter of that member. Otherwise returns `None`.
    pub fn member_age_counter(&self, name: &XorName) -> Option<u32> {
        self.stage
            .approved()
            .filter(|stage| stage.is_our_elder(self.core.id()))
            .and_then(|stage| stage.shared_state.our_members.get(name))
            .map(|info| info.age_counter_value())
    }

    /// Returns the latest BLS public key of our section or `None` if we are not joined yet.
    pub fn section_key(&self) -> Option<&bls::PublicKey> {
        self.stage
            .approved()
            .map(|stage| stage.shared_state.our_history.last_key())
    }

    pub(crate) fn shared_state(&self) -> Option<&SharedState> {
        self.stage.approved().map(|stage| &stage.shared_state)
    }
}

#[cfg(all(test, feature = "mock"))]
impl Node {
    // Create new node which is already an approved member of a section.
    pub(crate) fn approved(
        config: NodeConfig,
        shared_state: SharedState,
        parsec_version: u64,
        section_key_share: Option<SectionKeyShare>,
    ) -> (Self, Receiver<Event>, Receiver<TransportEvent>) {
        let (timer_tx, timer_rx) = crossbeam_channel::unbounded();
        let (transport_tx, transport_node_rx, transport_client_rx) = transport_channels();
        let (user_event_tx, user_event_rx) = crossbeam_channel::unbounded();

        let mut core = Core::new(config, timer_tx, transport_tx, user_event_tx);

        let stage =
            Approved::new(&mut core, shared_state, parsec_version, section_key_share).unwrap();
        let stage = Stage::Approved(stage);

        let node = Self {
            stage,
            core,
            timer_rx,
            timer_rx_idx: 0,
            transport_rx: transport_node_rx,
            transport_rx_idx: 0,
        };

        (node, user_event_rx, transport_client_rx)
    }

    pub(crate) fn consensus_engine(&self) -> Result<&ConsensusEngine> {
        if let Some(stage) = self.stage.approved() {
            Ok(&stage.consensus_engine)
        } else {
            Err(RoutingError::InvalidState)
        }
    }

    pub(crate) fn consensus_engine_mut(&mut self) -> Result<&mut ConsensusEngine> {
        if let Some(stage) = self.stage.approved_mut() {
            Ok(&mut stage.consensus_engine)
        } else {
            Err(RoutingError::InvalidState)
        }
    }

    // Simulate DKG completion
    pub(crate) fn handle_dkg_result_event(
        &mut self,
        participants: &BTreeSet<PublicId>,
        section_key_index: u64,
        dkg_result: &DkgResult,
    ) -> Result<()> {
        if let Some(stage) = self.stage.approved_mut() {
            stage.handle_dkg_result_event(
                &mut self.core,
                participants,
                section_key_index,
                dkg_result,
            )
        } else {
            Err(RoutingError::InvalidState)
        }
    }
}
