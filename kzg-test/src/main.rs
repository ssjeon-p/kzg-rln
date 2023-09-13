use halo2::{
    poly::kzg::commitment::{ParamsKZG, ParamsVerifierKZG},
    poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
    poly::{EvaluationDomain, commitment::{ParamsProver, ParamsVerifier}},
    poly::Polynomial,
    poly::Coeff,
    halo2curves::bn256::{Bn256, Fr}, arithmetic::Field,

};

use std::{marker::PhantomData, ops::{IndexMut, Deref}};
use rand::thread_rng;

fn main() {
    let rng = &mut thread_rng();
    let keys = ParamsKZG::<Bn256>::new(2);
    let domain = EvaluationDomain::<Fr>::new(1, 2);
    let values = vec![
        Fr::random(rng.clone()),
        Fr::random(rng.clone()),
        Fr::random(rng.clone()),
        Fr::random(rng.clone()),
    ];
    let poly = domain.coeff_from_vec(values);
    let commit = keys.commit(&poly, halo2::poly::commitment::Blind::default());
    let prover = ProverSHPLONK::new(&keys);
}
