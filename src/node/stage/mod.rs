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

pub(crate) use self::{
    approved::{Approved, RelocateParams},
    bootstrapping::{Bootstrapping, JoinParams},
    joining::Joining,
};
use crate::{
    error::{Result, RoutingError},
    messages::Message,
};
use bytes::Bytes;
use quic_p2p::IncomingConnections;
use std::net::SocketAddr;
use xor_name::Prefix;

#[cfg(feature = "mock_base")]
pub use self::{bootstrapping::BOOTSTRAP_TIMEOUT, joining::JOIN_TIMEOUT};

// Type to represent the various stages a node goes through during its lifetime.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Stage {
    Bootstrapping(Bootstrapping),
    Joining(Joining),
    Approved(Approved),
    Terminated,
}

impl Stage {
    pub fn approved(&self) -> Option<&Approved> {
        match self {
            Self::Approved(stage) => Some(stage),
            _ => None,
        }
    }

    pub fn approved_mut(&mut self) -> Option<&mut Approved> {
        match self {
            Self::Approved(stage) => Some(stage),
            _ => None,
        }
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        match self {
            Self::Bootstrapping(stage) => stage.comm().our_connection_info(),
            Self::Joining(stage) => stage.comm().our_connection_info(),
            Self::Approved(stage) => stage.comm().our_connection_info(),
            Self::Terminated => Err(RoutingError::InvalidState),
        }
    }

    pub fn listen_events(&mut self) -> Result<IncomingConnections> {
        match self {
            Self::Bootstrapping(stage) => stage.comm().listen_events(),
            Self::Joining(stage) => stage.comm().listen_events(),
            Self::Approved(stage) => stage.comm().listen_events(),
            Self::Terminated => Err(RoutingError::InvalidState),
        }
    }

    pub async fn send_message_to_target(
        &mut self,
        recipient: &SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        match self {
            Self::Bootstrapping(stage) => stage.send_message_to_target(recipient, msg).await,
            Self::Joining(stage) => stage.send_message_to_target(recipient, msg).await,
            Self::Approved(stage) => stage.send_message_to_target(recipient, msg).await,
            Self::Terminated => Err(RoutingError::InvalidState),
        }
    }

    pub async fn process_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
    ) -> Result<()> {
        match self {
            Self::Bootstrapping(stage) => stage.process_message(sender, msg).await,
            Self::Joining(stage) => stage.process_message(sender, msg).await,
            Self::Approved(stage) => stage.process_message(sender, msg).await,
            Self::Terminated => Err(RoutingError::InvalidState),
        }
    }

    /// Returns whether this node is running or has been terminated.
    pub fn is_running(&self) -> bool {
        match self {
            Self::Bootstrapping(_) | Self::Joining(_) | Self::Approved(_) => true,
            Self::Terminated => false,
        }
    }

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix> {
        match self {
            Self::Bootstrapping(_) | Self::Joining(_) | Self::Terminated => None,
            Self::Approved(stage) => Some(stage.shared_state.our_prefix()),
        }
    }
}
