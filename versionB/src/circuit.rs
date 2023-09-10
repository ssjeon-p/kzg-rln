use std::marker::PhantomData;

use eigentrust_zk::{
    gadgets::{
        main::{MainChip, MainConfig},
        set::{SetChip, SetConfig},
    },
    merkle_tree::{native::{MerkleTree, Path}, MerklePathConfig, MerklePathChip},
    params::hasher::poseidon_bn254_5x5::Params,
    poseidon::{
        native::Poseidon, FullRoundChip, PartialRoundChip, PoseidonChipset, PoseidonConfig,
    },
    utils::{generate_params, prove_and_verify},
    Chip, CommonConfig,
    halo2::{halo2curves::bn256::Fr, circuit::{Layouter, Value}, poly::Error}, RegionCtx, Chipset,
};

use rand::thread_rng;
use halo2::{plonk::{Circuit, ConstraintSystem}, circuit::{SimpleFloorPlanner, Region, AssignedCell}, arithmetic::Field};

const ARITY: usize = 2;
const HEIGHT: usize = 3;
const LENGTH: usize = 4;

type NativeH = Poseidon<Fr, 5, Params>;
type H = PoseidonChipset<Fr, 5, Params>;

pub type type_tree = MerkleTree<Fr, ARITY, HEIGHT, Poseidon<Fr, 5, Params>>;
pub type type_path = Path<Fr, ARITY, HEIGHT, LENGTH, Poseidon<Fr, 5, Params>>;

use super::{
    UniPoly_381,
    Commitment,
    Bls12_381,
}



pub fn tree_with_user (
    key_hash: Fr,
) -> (type_tree, type_path) {
    let rng = &mut thread_rng();
	let value = Fr::random(rng.clone());
	let leaves = vec![
		Fr::random(rng.clone()),
		Fr::random(rng.clone()),
		Fr::random(rng.clone()),
		Fr::random(rng.clone()),
		value,
		Fr::random(rng.clone()),
		Fr::random(rng.clone()),
		Fr::random(rng.clone()),
	];
	let merkle = MerkleTree::<Fr, ARITY, HEIGHT, Poseidon<Fr, 5, Params>>::build_tree(leaves);
    let path = Path::<Fr, ARITY, HEIGHT, LENGTH, Poseidon<Fr, 5, Params>>::find_path(&merkle, 4);

    (merkle, path)
}