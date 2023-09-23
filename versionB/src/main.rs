#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]
#![allow(dead_code)]

use std::{vec, time::SystemTime};

use halo2::{
    arithmetic::{eval_polynomial, Field},
    dev::MockProver,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine, G2Affine, Gt},
        pairing::Engine,
    },
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};

use rand::thread_rng;

mod circuit;
mod kzg;

struct RLN {
    limit: u8,
    shares: Vec<(G1Affine, Vec<(Fr, Fr)>, Gt)>, // commit, (message, evaluation), pairing_cache
    keys: ParamsKZG<Bn256>,
}

impl RLN {
    fn new(limit: u8) -> Self {
        let keys = ParamsKZG::<Bn256>::new(log2_floor(limit));
        Self {
            limit,
            shares: Vec::new(),
            keys,
        }
    }

    fn verify_epoch_opening(&mut self, zkp: MockProver<Fr>, comm: &G1Affine) {
        let cur_time = SystemTime::now();

        zkp.assert_satisfied();
        let pairing_cache = Bn256::pairing(comm, &G2Affine::generator());
        self.shares.push((*comm, vec![], pairing_cache));

        println!(
            "Rln's epoch verifying time (milliseconds): {}",
            cur_time.elapsed().unwrap().as_millis()
        );
    }

    fn new_message(
        &mut self,
        comm: &G1Affine,
        message_hash: Fr,
        evaluation: Fr,
        proof: &G1Affine,
    ) -> Option<Fr> {
        let cur_time = SystemTime::now();

        let index = self
            .shares
            .iter()
            .position(|(share_commit, _, _)| *share_commit == *comm)
            .unwrap();
        self.shares[index].1.push((message_hash, evaluation));

        assert!(kzg::verify_proof(
            &self.keys,
            proof,
            message_hash,
            evaluation,
            &self.shares[index].2,
        ));

        println!(
            "Rln's message verifying time (microsecs): {}",
            cur_time.elapsed().unwrap().as_micros()
        );

        if self.shares[index].1.len() > self.limit as usize {
            let sk = Self::recover_key(&self.shares[index].1);
            self.shares.swap_remove(index);
            return Some(sk);
        }
        None
    }

    fn recover_key(shares: &[(Fr, Fr)]) -> Fr {
        let size = shares.len();
        let vec_x: Vec<Fr> = shares.iter().map(|a| a.0).collect();
        let vec_y: Vec<Fr> = shares.iter().map(|a| a.1).collect();

        let mut matrix: Vec<Vec<Fr>> = vec![vec![Fr::from(1); size]];
        matrix.push(vec_x);

        for i in 2..size {
            let next_row = matrix[i - 1]
                .iter()
                .zip(&matrix[1])
                .map(|(&a, &b)| a * b)
                .collect();
            matrix.push(next_row);
        }

        let denominator = determinant(matrix.clone());
        matrix[0] = vec_y;
        let numerator = determinant(matrix);

        numerator * Fr::invert(&denominator).unwrap()
    }
}

fn determinant(mut matrix: Vec<Vec<Fr>>) -> Fr {
    let n = matrix.len();
    let mut det = Fr::from(1);

    for i in 0..n {
        let mut pivot_row = i;
        for (j, col) in matrix.iter().enumerate().skip(i) {
            if col[i] != Fr::from(0) {
                pivot_row = j;
                break;
            }
        }

        if pivot_row != i {
            matrix.swap(i, pivot_row);
            det = -det;
        }

        let pivot = matrix[i][i];

        if pivot == Fr::from(0) {
            return Fr::from(0);
        }

        det *= pivot;

        for j in (i + 1)..n {
            let factor = matrix[j][i] * Fr::invert(&pivot).unwrap();
            for k in (i + 1)..n {
                matrix[j][k] = matrix[j][k] - factor * matrix[i][k];
            }
        }
    }

    det
}

struct User {
    sk: Fr,
    polynomial: Vec<Fr>,
    comm: G1Affine,
}

impl User {
    fn new(sk: Fr) -> Self {
        let polynomial = vec![];
        let comm = G1Affine::default();

        Self {
            sk,
            polynomial,
            comm,
        }
    }

    fn register_epoch(&mut self, rln: &mut RLN) {
        let cur_time = SystemTime::now();

        let rng = &mut thread_rng();
        self.polynomial = vec![self.sk];
        for _ in 0..rln.limit {
            self.polynomial.push(Fr::random(rng.clone()));
        }

        self.comm = kzg::commit(&rln.keys, &self.polynomial);
        let g = rln.keys.get_g()[0..(rln.limit + 1) as usize].to_vec();
        let zkp = circuit::create_zkp(self.polynomial.clone(), &self.comm, g);

        println!(
            "User's epoch registering time (milliseconds): {}",
            cur_time.elapsed().unwrap().as_millis()
        );

        rln.verify_epoch_opening(zkp, &self.comm);
    }

    fn send(&self, message_hash: Fr, rln: &mut RLN) {
        let evaluation = eval_polynomial(&self.polynomial, message_hash);
        let proof = kzg::witness_polynomial(&rln.keys, self.polynomial.clone(), message_hash);

        if let Some(sk) = rln.new_message(&self.comm, message_hash, evaluation, &proof) {
            assert_eq!(sk, self.sk);
            println!("recover key success");
        }
    }
}

fn log2_floor(num: u8) -> u32 {
    let mut pow = 0;
    while (1 << pow) <= num {
        pow += 1;
    }
    pow
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rln_kzg() {
        let limit = 3;
        let mut rln = RLN::new(limit);

        let rng = thread_rng();
        let mut user = User::new(Fr::random(rng.clone()));

        // epoch 1
        user.register_epoch(&mut rln);
        for _ in 0..limit + 1 {
            user.send(Fr::random(rng.clone()), &mut rln);
        }
        assert!(rln.shares.is_empty());

        //epoch 2
        // user.register_epoch(&mut rln);
        // for _ in 0..limit + 1 {
        //     user.send(Fr::random(rng.clone()), &mut rln);
        // }
        // assert!(rln.shares.is_empty());
    }
}

fn main() {}
