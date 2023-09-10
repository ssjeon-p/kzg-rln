#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]

use std::collections::HashMap;

use ark_bls12_381::*;
use ark_ec::{AffineCurve, PairingEngine};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_poly_commit::{kzg10::*, PCRandomness};
use ark_std::{test_rng, UniformRand};

use once_cell::sync::Lazy;

mod circuit;
mod linalg;

type UniPoly_381 = DensePolynomial<<Bls12_381 as PairingEngine>::Fr>;
type KZG = KZG10<Bls12_381, UniPoly_381>;

static KEYS: Lazy<(Powers<Bls12_381>, VerifierKey<Bls12_381>)> = Lazy::new(|| {
    let rng = &mut test_rng();
    let pp = KZG::setup(100, true, rng).unwrap();

    let powers_of_g = pp.powers_of_g.clone();
    let powers_of_gamma_g = vec![pp.powers_of_gamma_g[&0], pp.powers_of_gamma_g[&1]];

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };

    (powers, vk)
});


struct RLN {
    limit: u8,
    shares: HashMap<Commitment<Bls12_381>, Vec<(Fr, Fr)>>,
    tree: circuit::type_tree,
}

impl RLN {
    fn new_RLN_with_user(limit: u8) -> Self {
        Self {
            limit,
            shares: HashMap::new(),
            tree: circuit::type_tree::default(),
        }
    }

    fn register_epoch(
        &mut self,
        zkp: MockProver<Fp>,
        comm: Commitment<Bls12_381>,
    ) {
        zkp.assert_satisfied();
        self.shares.insert(comm, vec![]);
    }

    fn new_message(
        &mut self,
        comm: Commitment<Bls12_381>,
        message_hash: Fr,
        evaluation: Fr,
        proof: Proof<Bls12_381>,
    ) {
        assert!(KZG::check(&KEYS.1, &comm, message_hash, evaluation, &proof)
            .expect("Wrong message proof"));

        let mut messages = self.shares.get_mut(&comm).unwrap();
        messages.push((message_hash, evaluation));

        if messages.len() > self.limit as usize {
            let sk = Self::recover_key(&messages);
            self.shares.remove(&comm);
            self.delete_user(sk);
        }
    }
    
    fn recover_key(shares: &Vec<(Fr, Fr)>) -> Fr {
        let size = shares.len();
        let vec_x: Vec<Fr> = shares.iter().map(|a| {a.0}).collect();
        let vec_y: Vec<Fr> = shares.iter().map(|a| {a.1}).collect();

        let mut matrix: Vec<Vec<Fr>> = vec![vec![Fr::from(1); size]];
        matrix.push(vec_x.clone());

        for i in 2..size {
            let next_row = matrix[i-1].iter().zip(&vec_x).map(|(&a, &b)| {a * b}).collect();
            matrix.push(next_row);
        }

        let denominator = linalg::determinant(matrix.clone());
        _ = std::mem::replace(&mut matrix[0], vec_y);
        let numerator = linalg::determinant(matrix);

        numerator / denominator
    }
}

struct User {
    sk: Fr,
    path:  Vec<Fr>,
    polynomial: UniPoly_381,
    comm: Commitment<Bls12_381>,
}

impl User {
    fn new(
        sk: Fr,
        rln: &mut RLN,
    ) -> Self {
        let path = rln.add_user(sk);
        let polynomial = UniPoly_381::default();
        let comm = Commitment::<Bls12_381>::default();

        Self {
            sk,
            path,
            polynomial,
            comm
        }
    }

    fn register_epoch(
        &self,
        rln: &mut RLN
    ) {
        let rng = &mut test_rng();
        let mut polynomial = UniPoly_381::rand((rln.limit + 1) as usize, rng);
        *polynomial.first_mut().unwrap() = self.sk;
        assert!(polynomial.coeffs()[0] == self.sk);

        let (comm, rand) = KZG::commit(&KEYS.0, &self.polynomial, None, None).unwrap();
        let zkp = circuit::create_zkp(self.polynomial, self.comm);

        rln.register_epoch(zkp, comm);
    }

    fn send(
        &self,
        message_hash: Fr,
        rln: &mut RLN
    ) {
        let evaluation = self.polynomial.evaluate(&message_hash);
        let proof = KZG::open(
            &KEYS.0,
            &self.polynomial,
            message_hash,
            &Randomness::<Fr, UniPoly_381>::empty(),
        )
        .expect("Cannot make proof");

        rln.new_message(self.comm, message_hash, evaluation, proof);
    }
}


fn main() {
    println!("Hello, world!");
}
