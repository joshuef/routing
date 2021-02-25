// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod prefix_map;
mod stats;

use self::{prefix_map::PrefixMap, stats::NetworkStats};
use crate::{
    consensus::{verify_proof, Proof, Proven},
    peer::Peer,
    section::{EldersInfo, SectionChain},
};

use serde::{Deserialize, Serialize};
use sn_messaging::DstLocation;
use std::{borrow::Borrow, collections::HashSet, iter};
use xor_name::{Prefix, XorName};

/// Container for storing information about other sections in the network.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Network {
    // Neighbour sections: maps section prefixes to their latest signed elders infos.
    neighbours: PrefixMap<NeighbourInfo>,
    // BLS public keys of known sections excluding ours.
    keys: PrefixMap<Proven<(Prefix, bls::PublicKey)>>,
    // Indices of our section keys that are trusted by other sections.
    knowledge: PrefixMap<Proven<(Prefix, bls::PublicKey)>>,
}

impl Network {
    pub fn new() -> Self {
        Self {
            neighbours: Default::default(),
            keys: Default::default(),
            knowledge: Default::default(),
        }
    }

    /// Returns the known section that is closest to the given name, regardless of whether `name`
    /// belongs in that section or not.
    pub fn closest(&self, name: &XorName) -> Option<&EldersInfo> {
        self.all()
            .min_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, name))
    }

    /// Returns iterator over all known sections.
    pub fn all(&self) -> impl Iterator<Item = &EldersInfo> + Clone {
        self.neighbours.iter().map(|info| &info.elders_info.value)
    }

    /// Get `EldersInfo` of a known section with the given prefix.
    pub fn get(&self, prefix: &Prefix) -> Option<&EldersInfo> {
        self.neighbours
            .get(prefix)
            .map(|info| &info.elders_info.value)
    }

    /// Returns prefixes of all known sections.
    pub fn prefixes(&self) -> impl Iterator<Item = &Prefix> + Clone {
        self.all().map(|elders_info| &elders_info.prefix)
    }

    /// Returns all elders from all known sections.
    pub fn elders(&self) -> impl Iterator<Item = &Peer> {
        self.all().flat_map(|info| info.elders.values())
    }

    /// Returns a `Peer` of an elder from a known section.
    pub fn get_elder(&self, name: &XorName) -> Option<&Peer> {
        self.neighbours
            .get_matching(name)?
            .elders_info
            .value
            .elders
            .get(name)
    }

    /// Merge two `Network`s into one.
    /// TODO: make this operation commutative, associative and idempotent (CRDT)
    /// TODO: return bool indicating whether anything changed.
    pub fn merge(&mut self, other: Self, section_chain: &SectionChain) {
        // FIXME: these operations are not commutative:

        for entry in other.neighbours {
            if entry.verify(section_chain) {
                let _ = self.neighbours.insert(entry);
            }
        }

        for entry in other.keys {
            if entry.verify(section_chain) {
                let _ = self.keys.insert(entry);
            }
        }

        for entry in other.knowledge {
            if entry.verify(section_chain) {
                let _ = self.knowledge.insert(entry);
            }
        }
    }

    /// Update the info about a neighbour section.
    ///
    /// If this is for our sibling section, then `elders_info` is signed by them and so the signing
    /// key is not in our `section_chain`. To prove the key is valid, it must be accompanied by an
    /// additional `key_proof` which signs it using a key that is present in `section_chain`.
    ///
    /// If this is for a non-sibling section, the currently we require the info to be signed by our
    /// section (so we need to accumulate the signature for it first) and so `key_proof` is not
    /// needed in that case.
    pub fn update_neighbour_info(
        &mut self,
        elders_info: Proven<EldersInfo>,
        key_proof: Option<Proof>,
        section_chain: &SectionChain,
    ) -> bool {
        let info = NeighbourInfo {
            elders_info: elders_info.clone(),
            key_proof,
        };

        if !info.verify(section_chain) {
            return false;
        }

        if let Some(old) = self.neighbours.insert(info) {
            if old.elders_info == elders_info {
                return false;
            }
        }

        true
    }

    /// Updates the entry in `keys` for `prefix` to the latest known key.
    pub fn update_their_key(&mut self, new_key: Proven<(Prefix, bls::PublicKey)>) -> bool {
        // TODO: verify against section chain

        trace!(
            "update key for {:?}: {:?}",
            new_key.value.0,
            new_key.value.1
        );

        if let Some(old) = self.keys.insert(new_key.clone()) {
            if old == new_key {
                return false;
            }
        }

        true
    }

    /// Remove sections that are no longer our neighbours.
    pub fn prune_neighbours(&mut self, our_prefix: &Prefix) {
        let to_remove: Vec<_> = self
            .neighbours
            .prefixes()
            .filter(|prefix| {
                can_prune_neighbour(
                    our_prefix,
                    prefix,
                    self.neighbours
                        .descendants(prefix)
                        .map(|info| &info.elders_info.value.prefix),
                )
            })
            .copied()
            .collect();

        for prefix in to_remove {
            let _ = self.neighbours.remove(&prefix);
        }
    }

    /// Returns the known section keys.
    pub fn keys(&self) -> impl Iterator<Item = (&Prefix, &bls::PublicKey)> {
        self.keys
            .iter()
            .map(|entry| (&entry.value.0, &entry.value.1))
    }

    pub fn has_key(&self, key: &bls::PublicKey) -> bool {
        self.keys.iter().any(|entry| entry.value.1 == *key)
    }

    /// Returns the latest known key for the prefix that matches `name`.
    pub fn key_by_name(&self, name: &XorName) -> Option<&bls::PublicKey> {
        self.keys.get_matching(name).map(|entry| &entry.value.1)
    }

    /// Returns the latest known key for a section with `prefix`.
    /// If this returns `None` that means the latest known key is the genesis key.
    pub fn key_by_prefix(&self, prefix: &Prefix) -> Option<&bls::PublicKey> {
        self.keys
            .get_equal_or_ancestor(prefix)
            .map(|entry| &entry.value.1)
    }

    /// Returns the elders_info and the latest known key for the prefix that matches `name`,
    /// excluding self section.
    pub fn section_by_name(&self, name: &XorName) -> (Option<bls::PublicKey>, Option<EldersInfo>) {
        (
            self.keys.get_matching(name).map(|entry| entry.value.1),
            self.neighbours
                .get_matching(name)
                .map(|entry| entry.elders_info.value.clone()),
        )
    }

    /// Returns the public key in our chain that will be trusted by the given section.
    /// If `None` is returned, the only key guaranteed to be trusted is the root key.
    pub fn knowledge_by_section(&self, prefix: &Prefix) -> Option<&bls::PublicKey> {
        self.knowledge
            .get_equal_or_ancestor(prefix)
            .map(|entry| &entry.value.1)
    }

    /// Returns the public key in our chain that will be trusted by the given location.
    pub fn knowledge_by_location(&self, dst: &DstLocation) -> Option<&bls::PublicKey> {
        self.knowledge
            .get_matching(&dst.name()?)
            .map(|entry| &entry.value.1)
    }

    /// Updates the entry in `knowledge` for `prefix` to `new_index`; if a split
    /// occurred in the meantime, the index for sections covering the rest of the address space
    /// are initialised to the old index that was stored for their common ancestor
    pub fn update_knowledge(&mut self, knowledge: Proven<(Prefix, bls::PublicKey)>) {
        trace!(
            "update knowledge of section ({:b}) about our section to {:?}",
            knowledge.value.0,
            knowledge.value.1,
        );

        let _ = self.knowledge.insert(knowledge);
    }

    /// Returns network statistics.
    pub fn network_stats(&self, our: &EldersInfo) -> NetworkStats {
        let (known_elders, total_elders, total_elders_exact) = self.network_elder_counts(our);

        NetworkStats {
            known_elders,
            total_elders,
            total_elders_exact,
        }
    }

    // Compute an estimate of the total number of elders in the network from the size of our
    // routing table.
    //
    // Return (known, total, exact), where `exact` indicates whether `total` is an exact number of
    // an estimate.
    fn network_elder_counts(&self, our: &EldersInfo) -> (u64, u64, bool) {
        let known_prefixes = iter::once(&our.prefix).chain(self.prefixes());
        let is_exact = Prefix::default().is_covered_by(known_prefixes.clone());

        // Estimated fraction of the network that we have in our RT.
        // Computed as the sum of 1 / 2^(prefix.bit_count) for all known section prefixes.
        let network_fraction: f64 = known_prefixes
            .map(|p| 1.0 / (p.bit_count() as f64).exp2())
            .sum();

        let known = our.elders.len() + self.elders().count();
        let total = known as f64 / network_fraction;

        (known as u64, total.ceil() as u64, is_exact)
    }
}

// Check whether we can remove `other` from our neighbours given `our` prefix and all `known`
// descendants of `other`.
//
// We can remove `other` if:
// - it is not our neighbour anymore, or
// - the intersection of the address space covered by `other` and our neighbourhood is fully
//   covered by prefixes we know.
//
// Example:
// - We are (00) and we know (1). Then we add (10). Now (10) covers the whole address space of (1)
//   that is also in our neighbourhood (because (11) is not our neighbour) which means we can
//   remove (1).
// - We are (000) and we know (1). Then we add (100). None of (101), (110) and (111) is our
//   neighbour which means that (100) again covers the whole address space of (1) that is in our
//   neighbourhood so we can remove (1)
// - We are (0) and we know (1). Then we add (10). We can't remove (1) yet because we don't know
//   (11) which is also our neighbour.
fn can_prune_neighbour<'a, I>(our: &Prefix, other: &Prefix, known: I) -> bool
where
    I: IntoIterator<Item = &'a Prefix>,
{
    let known: HashSet<_> = known
        .into_iter()
        .filter(|prefix| prefix.is_extension_of(other))
        .collect();

    fn check(our: &Prefix, other: &Prefix, known: &HashSet<&Prefix>) -> bool {
        if !other.is_neighbour(our) && !other.is_extension_of(our) {
            return true;
        }

        if known.contains(other) {
            return true;
        }

        if other.bit_count() >= our.bit_count() {
            return false;
        }

        let child0 = other.pushed(false);
        let child1 = other.pushed(true);

        check(our, &child0, known) && check(our, &child1, known)
    }

    check(our, other, &known)
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
struct NeighbourInfo {
    // If this is signed by our section, then `key_proof` is `None`. If this is signed by our
    // sibling section, then `key_proof` contains the proof of the signing key itself signed by our
    // section.
    elders_info: Proven<EldersInfo>,
    key_proof: Option<Proof>,
}

impl NeighbourInfo {
    fn verify(&self, section_chain: &SectionChain) -> bool {
        if let Some(key_proof) = &self.key_proof {
            section_chain.has_key(&key_proof.public_key)
                && verify_proof(key_proof, &self.elders_info.proof.public_key)
                && self.elders_info.self_verify()
        } else {
            self.elders_info.verify(section_chain)
        }
    }
}

impl Borrow<Prefix> for NeighbourInfo {
    fn borrow(&self) -> &Prefix {
        &self.elders_info.value.prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus, section};
    use rand::Rng;

    #[test]
    fn update_keys_single_prefix_multiple_updates() {
        let k0 = gen_key();
        let k1 = gen_key();
        let k2 = gen_key();

        update_keys_and_check(vec![("1", &k0), ("1", &k1), ("1", &k2)], vec![("1", &k2)]);
    }

    #[test]
    fn update_keys_existing_old_key() {
        let k0 = gen_key();
        let k1 = gen_key();

        update_keys_and_check(vec![("1", &k0), ("1", &k1), ("1", &k0)], vec![("1", &k0)]);
    }

    #[test]
    fn update_keys_complete_split() {
        let k0 = gen_key();
        let k1 = gen_key();
        let k2 = gen_key();

        update_keys_and_check(
            vec![("1", &k0), ("10", &k1), ("11", &k2)],
            vec![("10", &k1), ("11", &k2)],
        );
    }

    #[test]
    fn update_keys_partial_split() {
        let k0 = gen_key();
        let k1 = gen_key();

        update_keys_and_check(vec![("1", &k0), ("10", &k1)], vec![("1", &k0), ("10", &k1)]);
    }

    #[test]
    fn update_keys_indirect_complete_split() {
        let k0 = gen_key();
        let k1 = gen_key();
        let k2 = gen_key();
        let k3 = gen_key();
        let k4 = gen_key();

        update_keys_and_check(
            vec![
                ("1", &k0),
                ("100", &k1),
                ("101", &k2),
                ("110", &k3),
                ("111", &k4),
            ],
            vec![("100", &k1), ("101", &k2), ("110", &k3), ("111", &k4)],
        );
    }

    #[test]
    fn update_keys_indirect_partial_split() {
        let k0 = gen_key();
        let k1 = gen_key();
        let k2 = gen_key();

        update_keys_and_check(
            vec![("1", &k0), ("100", &k1), ("101", &k2)],
            vec![("1", &k0), ("100", &k1), ("101", &k2)],
        );
    }

    #[test]
    fn update_keys_split_out_of_order() {
        let k0 = gen_key();
        let k1 = gen_key();
        let k2 = gen_key();
        let k3 = gen_key();
        let k4 = gen_key();

        // Late keys ignored
        update_keys_and_check(
            vec![
                ("1", &k0),
                ("10", &k1),
                ("11", &k2),
                ("101", &k3),
                ("10", &k4),
            ],
            vec![("10", &k1), ("101", &k3), ("11", &k2)],
        );
    }

    #[test]
    fn update_their_knowledge_after_split_from_one_sibling() {
        let pk1 = gen_key();
        let pk2 = gen_key();

        update_their_knowledge_and_check_proving_index(
            vec![("1", pk1), ("10", pk2)],
            vec![("10", pk2), ("11", pk1)],
        )
    }

    #[test]
    fn update_their_knowledge_after_split_from_both_siblings() {
        let pk1 = gen_key();
        let pk2 = gen_key();

        update_their_knowledge_and_check_proving_index(
            vec![("1", pk1), ("10", pk2), ("11", pk2)],
            vec![("10", pk2), ("11", pk2)],
        )
    }

    #[test]
    fn closest() {
        let sk = bls::SecretKey::random();
        let chain = SectionChain::new(sk.public_key());

        let p01: Prefix = "01".parse().unwrap();
        let p10: Prefix = "10".parse().unwrap();
        let p11: Prefix = "11".parse().unwrap();

        // Create map containing sections (00), (01) and (10)
        let mut map = Network::new();
        let _ = map.update_neighbour_info(gen_proven_elders_info(&sk, p01), None, &chain);
        let _ = map.update_neighbour_info(gen_proven_elders_info(&sk, p10), None, &chain);

        let mut rng = rand::thread_rng();
        let n01 = p01.substituted_in(rng.gen());
        let n10 = p10.substituted_in(rng.gen());
        let n11 = p11.substituted_in(rng.gen());

        assert_eq!(map.closest(&n01).map(|i| &i.prefix), Some(&p01));
        assert_eq!(map.closest(&n10).map(|i| &i.prefix), Some(&p10));
        assert_eq!(map.closest(&n11).map(|i| &i.prefix), Some(&p10));
    }

    #[test]
    fn prune_neighbours() {
        let sk = bls::SecretKey::random();
        let chain = SectionChain::new(sk.public_key());

        let p00 = "00".parse().unwrap();
        let mut map = Network::new();

        let p1 = "1".parse().unwrap();
        let section1 = gen_proven_elders_info(&sk, p1);
        assert!(map.update_neighbour_info(section1, None, &chain));
        map.prune_neighbours(&p00);

        assert!(map.prefixes().any(|&prefix| prefix == p1));

        // (10) is a neighbour of (00), but (11) is not. So by inserting (10),
        // we no longer need (1)
        let p10 = "10".parse().unwrap();
        let section10 = gen_proven_elders_info(&sk, p10);
        assert!(map.update_neighbour_info(section10, None, &chain));
        map.prune_neighbours(&p00);

        assert!(map.prefixes().any(|&prefix| prefix == p10));
        assert!(map.prefixes().all(|&prefix| prefix != p1));
    }

    // Create a `Network` and apply a series of `update_keys` calls to it, then verify the stored
    // keys are as expected.
    //
    // updates:  updates to `Network::keys` as a sequence of (prefix, key) pairs that are
    //           applied in sequence by calling `update_keys`
    // expected: vec of pairs (prefix, key) of the expected keys for each prefix, in the expected
    //           order.
    fn update_keys_and_check(
        updates: Vec<(&str, &bls::PublicKey)>,
        expected: Vec<(&str, &bls::PublicKey)>,
    ) {
        let sk = bls::SecretKey::random();

        let mut map = Network::new();

        for (prefix, key) in updates {
            let prefix = prefix.parse().unwrap();
            let proof = consensus::test_utils::prove(&sk, &(&prefix, key)).unwrap();
            let proven = Proven::new((prefix, *key), proof);
            let _ = map.update_their_key(proven);
        }

        let actual: Vec<_> = map.keys().map(|(prefix, key)| (*prefix, key)).collect();
        let expected: Vec<(Prefix, _)> = expected
            .into_iter()
            .map(|(prefix, key)| (prefix.parse().unwrap(), key))
            .collect();
        assert_eq!(actual, expected);
    }

    // Perform a series of updates to `knowledge`, then verify that the proving indices for
    // the given dst locations are as expected.
    //
    // - `updates` - pairs of (prefix, key) to pass to `update_knowledge`
    // - `expected_trusted_keys` - pairs of (prefix, key) where the dst location name is
    //   generated such that it matches `prefix` and `key` is the expected trusted key.
    fn update_their_knowledge_and_check_proving_index(
        updates: Vec<(&str, bls::PublicKey)>,
        expected_trusted_keys: Vec<(&str, bls::PublicKey)>,
    ) {
        let sk = bls::SecretKey::random();

        let mut map = Network::new();

        for (prefix_str, key) in updates {
            let prefix = prefix_str.parse().unwrap();
            let payload = consensus::test_utils::proven(&sk, (prefix, key)).unwrap();
            map.update_knowledge(payload);
        }

        for (dst_name_prefix_str, expected_key) in expected_trusted_keys {
            let dst_name_prefix: Prefix = dst_name_prefix_str.parse().unwrap();
            let dst_name = dst_name_prefix.substituted_in(rand::random());
            let dst = DstLocation::Section(dst_name);

            assert_eq!(map.knowledge_by_location(&dst), Some(&expected_key));
        }
    }

    fn gen_proven_elders_info(sk: &bls::SecretKey, prefix: Prefix) -> Proven<EldersInfo> {
        let (elders_info, _) = section::test_utils::gen_elders_info(prefix, 5);
        consensus::test_utils::proven(sk, elders_info).unwrap()
    }

    fn gen_key() -> bls::PublicKey {
        bls::SecretKey::random().public_key()
    }
}
