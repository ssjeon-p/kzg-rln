use ark_poly::polynomial;
use halo2_gadgets::sinsemilla::merkle::*;
use halo2_proofs::{dev::MockProver, pasta::Fp};

use super::{
    UniPoly_381,
    Commitment,
    Bls12_381,
}

#[derive(Default)]
pub struct tree {

}

pub fn create_zkp(
    polynomial: UniPoly_381,
    comm: Commitment<Bls12_381>,
) -> MockProver<Fp> {
    
}