// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::{Result, RoutingError},
    id::FullId,
    location::DstLocation,
    messages::{Message, Variant},
};
use bytes::Bytes;
use hex_fmt::HexFmt;
use quic_p2p::{Config, Connection, Endpoint, IncomingConnections, QuicP2p};
use std::{boxed::Box, net::SocketAddr, sync::Arc};

// Communication component of the node to interact with other nodes.
#[derive(Clone)]
pub(crate) struct Comm {
    quic_p2p: Arc<Box<QuicP2p>>,
    endpoint: Arc<Box<Endpoint>>,
}

impl Comm {
    pub async fn new(transport_config: Config) -> Result<Self> {
        let quic_p2p = Arc::new(Box::new(QuicP2p::with_config(
            Some(transport_config),
            Default::default(),
            true,
        )?));

        // Don't bootstrap, just create an endpoint where to listen to
        // the incoming messages from other nodes.
        let endpoint = Arc::new(Box::new(quic_p2p.new_endpoint()?));

        Ok(Self { quic_p2p, endpoint })
    }

    pub async fn from_bootstrapping(transport_config: Config) -> Result<(Self, Connection)> {
        let mut quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Bootstrap to the network returning the connection to a node.
        let (endpoint, connection) = quic_p2p
            .bootstrap()
            .await
            .map_err(|err| RoutingError::ToBeDefined(format!("{}", err)))?;

        let quic_p2p = Arc::new(Box::new(quic_p2p));
        let endpoint = Arc::new(Box::new(endpoint));

        Ok((Self { quic_p2p, endpoint }, connection))
    }

    /// Starts listening for events returning a stream where to read them from.
    pub fn listen_events(&mut self) -> Result<IncomingConnections> {
        self.endpoint.listen().map_err(|err| {
            RoutingError::ToBeDefined(format!("Failed to start listening for messages: {}", err))
        })
    }

    pub fn our_connection_info(&self) -> Result<SocketAddr> {
        self.endpoint.our_endpoint().map_err(|err| {
            debug!("Failed to retrieve our connection info: {:?}", err);
            err.into()
        })
    }

    pub async fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) -> Result<()> {
        if conn_infos.len() < delivery_group_size {
            warn!(
                "Less than delivery_group_size valid targets! delivery_group_size = {}; targets = {:?}; msg = {:10}",
                delivery_group_size,
                conn_infos,
                HexFmt(&msg)
            );
        }

        trace!(
            "Sending message to {:?}",
            &conn_infos[..delivery_group_size.min(conn_infos.len())]
        );

        // initially only send to delivery_group_size targets
        for addr in conn_infos.iter().take(delivery_group_size) {
            // NetworkBytes is refcounted and cheap to clone.
            self.send_message_to_target(addr, msg.clone()).await?;
        }

        Ok(())
    }

    pub async fn send_message_to_target(
        &mut self,
        recipient: &SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        trace!("Sending message to target {:?}", recipient);
        // TODO: can we cache the Connections to nodes to make this more efficient??
        let conn = self.endpoint.connect_to(recipient).await?;
        conn.send_uni(msg).await.map_err(RoutingError::Network)
    }

    pub async fn send_direct_message(
        &mut self,
        src_id: &FullId,
        recipient: &SocketAddr,
        variant: Variant,
    ) -> Result<()> {
        let message = Message::single_src(src_id, DstLocation::Direct, variant, None, None)?;
        self.send_message_to_target(recipient, message.to_bytes())
            .await
    }

    // Private helper to send a message using the given quic-p2p Connection
    pub async fn send_direct_message_on_conn(
        &mut self,
        src_id: &FullId,
        conn: &mut Connection,
        variant: Variant,
    ) -> Result<()> {
        let message = Message::single_src(src_id, DstLocation::Direct, variant, None, None)?;
        conn.send_uni(message.to_bytes())
            .await
            .map_err(RoutingError::Network)
    }
}
