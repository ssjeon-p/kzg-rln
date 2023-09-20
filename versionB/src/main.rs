#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]

use halo2::{
    halo2curves::bn256::{G1Affine, Fr, Bn256},
    dev::MockProver,
    poly::{kzg::commitment::ParamsKZG, commitment::ParamsProver},
    arithmetic::{Field, self},
};
use rand::thread_rng;

mod circuit;
mod linalg;
mod kzg;

struct RLN {
    limit: u8,
    shares: Vec<(G1Affine, Vec<(Fr, Fr)>)>,
    keys: ParamsKZG<Bn256>
}

impl RLN {
    fn new_RLN_with_user(limit: u8) -> Self {
        let rng = &mut thread_rng();
        // TODO: replace 2 with respect to limit
        let keys = ParamsKZG::<Bn256>::new(2);
        Self {
            limit,
            shares: Vec::new(),
            keys: keys,
        }
    }

    fn verify_epoch_opening(
        &mut self,
        zkp: MockProver<Fr>,
        comm: G1Affine
    ) {
        zkp.assert_satisfied();
        self.shares.push((comm, vec![]));
    }

    fn new_message(
        &mut self,
        comm: &G1Affine,
        message_hash: Fr,
        evaluation: Fr,
        proof: &G1Affine,
    ) {
        assert!(kzg::verify_proof(&self.keys, proof, comm, message_hash, evaluation));

        let mut index = 0;
        let mut messages = self.shares.iter().find(|&&(commit, _)| {
            index += 1;
            commit == *comm
        }).unwrap().1.clone();
        messages.push((message_hash, evaluation));

        if messages.len() > self.limit as usize {
            let _sk = Self::recover_key(&messages);
            let _ = self.shares.swap_remove(index-1);
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

        numerator * Fr::invert(&denominator).unwrap()
    }
}

struct User {
    sk: Fr,
    polynomial: Vec<Fr>,
    comm: G1Affine
}

impl User {
    fn new(
        sk: Fr,
        rln: &mut RLN,
    ) -> Self {
        let polynomial = vec![];
        let comm = G1Affine::default();

        Self {
            sk,
            polynomial,
            comm
        }
    }

    fn register_epoch(
        &self,
        rln: &mut RLN
    ) {
        let rng = &mut thread_rng();
        let mut poly = vec![self.sk];
        for _ in 0..rln.limit {
            poly.push(Fr::random(rng.clone()));
        }

        let comm = kzg::commit(&rln.keys, poly.clone());
        let g = rln.keys.get_g().to_vec();
        let zkp = circuit::create_zkp(self.polynomial.clone(), self.comm, g);

        rln.verify_epoch_opening(zkp, comm);
    }

    fn send(
        &self,
        message_hash: Fr,
        rln: &mut RLN
    ) {
        let evaluation = arithmetic::eval_polynomial(&self.polynomial, message_hash);
        let proof = kzg::witness_polynomial(&rln.keys, self.polynomial.clone(), message_hash);

        rln.new_message(&self.comm, message_hash, evaluation, &proof);
    }
}


fn main() {
    println!("Hello, world!");
}