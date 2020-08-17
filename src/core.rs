// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::{Result, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    location::DstLocation,
    message_filter::MessageFilter,
    messages::{Message, QueuedMessage, Variant},
    network_params::NetworkParams,
    node::{event_stream::EventStream, NodeConfig},
    quic_p2p::OurType,
    rng::MainRng,
    timer::Timer,
};
use bytes::Bytes;
use crossbeam_channel::Sender;
use hex_fmt::HexFmt;
use quic_p2p::QuicP2p;
use std::{collections::VecDeque, net::SocketAddr};
use xor_name::XorName;

// Core components of the node.
pub(crate) struct Core {
    pub network_params: NetworkParams,
    pub full_id: FullId,
    pub quic_p2p: QuicP2p,
    pub msg_filter: MessageFilter,
    pub msg_queue: VecDeque<QueuedMessage>,
    pub timer: Timer,
    pub rng: MainRng,
    user_event_tx: Sender<Event>,
}

impl Core {
    pub fn new(
        mut config: NodeConfig,
        timer_tx: Sender<u64>,
        user_event_tx: Sender<Event>,
    ) -> Result<Self> {
        let mut rng = config.rng;
        let full_id = config.full_id.unwrap_or_else(|| FullId::gen(&mut rng));

        config.transport_config.our_type = OurType::Node;
        let quic_p2p =
            QuicP2p::with_config(Some(config.transport_config), Default::default(), true)?;

        Ok(Self {
            network_params: config.network_params,
            full_id,
            quic_p2p,
            msg_filter: Default::default(),
            msg_queue: Default::default(),
            timer: Timer::new(timer_tx),
            rng,
            user_event_tx,
        })
    }

    /*    pub fn resume(
            network_params: NetworkParams,
            full_id: FullId,
            transport: Transport,
            msg_filter: MessageFilter,
            msg_queue: VecDeque<QueuedMessage>,
            timer_tx: Sender<u64>,
            user_event_tx: Sender<Event>,
        ) -> Self {
            Self {
                network_params,
                full_id,
                transport,
                msg_filter,
                msg_queue,
                timer: Timer::new(timer_tx),
                rng: rng::new(),
                user_event_tx,
            }
        }
    */
    /// Starts listening for events returning a stream where to read them from.
    pub fn listen_events(&self) -> Result<EventStream> {
        let incoming_conns = self.quic_p2p.listen()?;
        Ok(EventStream::new(incoming_conns))
    }

    pub fn id(&self) -> &PublicId {
        self.full_id.public_id()
    }

    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.quic_p2p.our_endpoint().map_err(|err| {
            debug!("Failed to retrieve our connection info: {:?}", err);
            err.into()
        })
    }

    pub async fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) {
        if conn_infos.len() < delivery_group_size {
            warn!(
                "Less than delivery_group_size valid targets! delivery_group_size = {}; targets = {:?}; msg = {:10}",
                delivery_group_size,
                conn_infos,
                HexFmt(&msg)
            );
        }

        trace!(
            "Sending message with token to {:?}",
            &conn_infos[..delivery_group_size.min(conn_infos.len())]
        );

        // initially only send to delivery_group_size targets
        for addr in conn_infos.iter().take(delivery_group_size) {
            // NetworkBytes is refcounted and cheap to clone.
            self.send_message_to_target(addr, msg.clone()).await;
        }
    }

    pub async fn send_message_to_target(
        &mut self,
        recipient: &SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        // TODO: can we keep the Connections to nodes to make this more efficient??
        let conn = self.quic_p2p.connect_to(recipient).await?;
        conn.send_only(msg).await.map_err(RoutingError::Network)
    }

    pub async fn send_direct_message(
        &mut self,
        recipient: &SocketAddr,
        variant: Variant,
    ) -> Result<()> {
        let message = Message::single_src(&self.full_id, DstLocation::Direct, variant, None, None)?;
        self.send_message_to_target(recipient, message.to_bytes())
            .await
    }

    // TODO: remove this function
    /*pub fn handle_unsent_message(
        &mut self,
        addr: SocketAddr,
        msg: Bytes,
        msg_token: Token,
    ) -> PeerStatus {
        self.transport
            .target_failed(msg, msg_token, addr, &self.timer)
    }*/

    pub fn send_event(&self, event: Event) {
        let _ = self.user_event_tx.send(event);
    }
}
