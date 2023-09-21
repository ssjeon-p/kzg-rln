#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]
#![allow(dead_code)]

use halo2::{
    arithmetic::{eval_polynomial, Field},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use rand::thread_rng;

mod circuit;
mod kzg;
mod linalg;

struct RLN {
    limit: u8,
    shares: Vec<(G1Affine, Vec<(Fr, Fr)>)>,
    keys: ParamsKZG<Bn256>,
}

impl RLN {
    fn new(limit: u8) -> Self {
        let mut pow = 0;
        while (1 << pow) <= limit {
            pow += 1;
        }

        let keys = ParamsKZG::<Bn256>::new(pow);
        Self {
            limit,
            shares: Vec::new(),
            keys,
        }
    }

    fn verify_epoch_opening(&mut self, zkp: MockProver<Fr>, comm: G1Affine) {
        zkp.assert_satisfied();
        self.shares.push((comm, vec![]));
    }

    fn new_message(
        &mut self,
        comm: &G1Affine,
        message_hash: Fr,
        evaluation: Fr,
        proof: &G1Affine,
    ) -> Option<Fr> {
        assert!(kzg::verify_proof(
            &self.keys,
            proof,
            comm,
            message_hash,
            evaluation
        ));

        let mut index = 0;
        for _ in self.shares.iter() {
            if self.shares[0].0 == *comm {
                break;
            }
            index += 1;
        }
        self.shares[index].1.push((message_hash, evaluation));

        if self.shares[index].1.len() > self.limit as usize {
            let sk = Self::recover_key(&self.shares[index].1);
            let _ = self.shares.swap_remove(index);
            return Some(sk);
        }
        None
    }

    fn recover_key(shares: &Vec<(Fr, Fr)>) -> Fr {
        let size = shares.len();
        let vec_x: Vec<Fr> = shares.iter().map(|a| a.0).collect();
        let vec_y: Vec<Fr> = shares.iter().map(|a| a.1).collect();

        let mut matrix: Vec<Vec<Fr>> = vec![vec![Fr::from(1); size]];
        matrix.push(vec_x.clone());

        for i in 2..size {
            let next_row = matrix[i - 1]
                .iter()
                .zip(&vec_x)
                .map(|(&a, &b)| a * b)
                .collect();
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
    comm: G1Affine,
}

impl User {
    fn new(sk: Fr, rln: &mut RLN) -> Self {
        let polynomial = vec![];
        let comm = G1Affine::default();

        Self {
            sk,
            polynomial,
            comm,
        }
    }

    fn register_epoch(&mut self, rln: &mut RLN) {
        let rng = &mut thread_rng();
        self.polynomial.push(self.sk);
        for _ in 0..rln.limit {
            self.polynomial.push(Fr::random(rng.clone()));
        }

        self.comm = kzg::commit(&rln.keys, self.polynomial.clone());
        let g = rln.keys.get_g()[0..(rln.limit + 1) as usize].to_vec();
        // let zkp = circuit::create_zkp(self.polynomial.clone(), &self.comm, g);

        // rln.verify_epoch_opening(zkp, self.comm);
        rln.shares.push((self.comm, vec![]));
    }

    fn send(&self, message_hash: Fr, rln: &mut RLN) {
        let evaluation = eval_polynomial(&self.polynomial, message_hash);
        let proof = kzg::witness_polynomial(&rln.keys, self.polynomial.clone(), message_hash);

        if let Some(sk) = rln.new_message(&self.comm, message_hash, evaluation, &proof) {
            println!("recover key success");
            assert_eq!(sk, self.sk);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rln_kzg() {
        let limit = 3;
        let mut rln = RLN::new(limit);

        let rng = thread_rng();
        let mut user = User::new(Fr::random(rng.clone()), &mut rln);

        // epoch 1
        user.register_epoch(&mut rln);
        for _ in 0..limit + 1 {
            user.send(Fr::random(rng.clone()), &mut rln);
        }
        assert!(rln.shares.is_empty());
    }
}

fn main() {
    println!("Hello, world!");
}
