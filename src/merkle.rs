use serde::{Deserialize, Serialize};
use starknet::{
    core::{
        codec::{Decode, Encode},
        types::Felt,
    },
    macros::selector,
};
use starknet_crypto::{poseidon_hash, poseidon_hash_many};

use crate::TokenAmount;

#[derive(Debug)]
pub struct MerkleTree {
    layers: Vec<Vec<Felt>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct RecoveryClaim {
    pub recipient: Felt,
    pub share: u128,
    pub withdrawable: Vec<TokenAmount>,
}

impl MerkleTree {
    pub fn from_claims<'a, I>(claims: I) -> Self
    where
        I: Iterator<Item = &'a RecoveryClaim>,
    {
        let mut layers = vec![];

        // Leaves layer
        let mut layer = claims.map(|claim| claim.merkle_leaf()).collect::<Vec<_>>();

        while layer.len() != 1 {
            let next_layer = reduce_merkle_layer(&layer);
            layers.push(layer);
            layer = next_layer;
        }

        layers.push(layer);

        Self { layers }
    }

    pub fn root(&self) -> Felt {
        let last_layer = self.layers.last().unwrap();
        assert!(last_layer.len() == 1);
        last_layer[0]
    }

    pub fn get_proof(&self, index: usize) -> Vec<Felt> {
        let mut proof = vec![];
        let mut index = index;

        for layer in &self.layers[..(self.layers.len() - 1)] {
            let neighbour_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            proof.push(layer.get(neighbour_index).copied().unwrap_or_default());
            index /= 2;
        }

        proof
    }
}

impl RecoveryClaim {
    pub fn verify_proof(&self, merkle_root: Felt, proof: &[Felt]) -> bool {
        let mut node = self.merkle_leaf();

        for proof_node in proof {
            node = poseidon_hash_sorted(node, *proof_node);
        }

        merkle_root == node
    }

    fn merkle_leaf(&self) -> Felt {
        let mut serialized = vec![];
        self.encode(&mut serialized).unwrap();

        poseidon_hash(
            selector!("zklend_recovery::Claim"),
            poseidon_hash_many(&serialized),
        )
    }
}

fn reduce_merkle_layer(layer: &[Felt]) -> Vec<Felt> {
    let mut next_layer = vec![];

    let mut iter = layer.iter();

    while let Some(left) = iter.next() {
        next_layer.push(poseidon_hash_sorted(
            *left,
            iter.next().copied().unwrap_or_default(),
        ))
    }

    next_layer
}

fn poseidon_hash_sorted(a: Felt, b: Felt) -> Felt {
    if a <= b {
        poseidon_hash(a, b)
    } else {
        poseidon_hash(b, a)
    }
}
