// #![allow(non_snake_case)]
// #![allow(non_camel_case_types)]
// #![allow(clippy::upper_case_acronyms)]
// #![allow(clippy::type_complexity)]

// use std::collections::HashMap;

// use halo2::{
//     halo2curves::bn256::{G1Affine, Fr, Bn256},
//     dev::MockProver,
//     poly::{kzg::commitment::ParamsKZG, commitment::ParamsProver, self}
// };
// use rand::thread_rng;


mod circuit;
mod linalg;
mod kzg;

// struct RLN {
//     limit: u8,
//     shares: HashMap<G1Affine, Vec<(Fr, Fr)>>,
//     setup: ParamsKZG<Bn256>
// }

// impl RLN {
//     fn new_RLN_with_user(limit: u8) -> Self {
//         let rng = &mut thread_rng();
//         // TODO: replace 2 with respect to limit
//         let keys = ParamsKZG::<Bn256>::new(2);
//         Self {
//             limit,
//             shares: HashMap::new(),
//             setup: keys,
//         }
//     }

//     fn register_epoch(
//         &mut self,
//         zkp: MockProver<Fr>,
//         comm: G1Affine
//     ) {
//         zkp.assert_satisfied();
//         self.shares.insert(comm, vec![]);
//     }

//     fn new_message(
//         &mut self,
//         comm: G1Affine,
//         message_hash: Fr,
//         evaluation: Fr,
//         proof: Proof<Bls12_381>,
//     ) {
//         assert!(KZG::check(&KEYS.1, &comm, message_hash, evaluation, &proof)
//             .expect("Wrong message proof"));

//         let mut messages = self.shares.get_mut(&comm).unwrap();
//         messages.push((message_hash, evaluation));

//         if messages.len() > self.limit as usize {
//             let sk = Self::recover_key(&messages);
//             self.shares.remove(&comm);
//             self.delete_user(sk);
//         }
//     }
    
//     fn recover_key(shares: &Vec<(Fr, Fr)>) -> Fr {
//         let size = shares.len();
//         let vec_x: Vec<Fr> = shares.iter().map(|a| {a.0}).collect();
//         let vec_y: Vec<Fr> = shares.iter().map(|a| {a.1}).collect();

//         let mut matrix: Vec<Vec<Fr>> = vec![vec![Fr::from(1); size]];
//         matrix.push(vec_x.clone());

//         for i in 2..size {
//             let next_row = matrix[i-1].iter().zip(&vec_x).map(|(&a, &b)| {a * b}).collect();
//             matrix.push(next_row);
//         }

//         let denominator = linalg::determinant(matrix.clone());
//         _ = std::mem::replace(&mut matrix[0], vec_y);
//         let numerator = linalg::determinant(matrix);

//         numerator / denominator
//     }
// }

// struct User {
//     sk: Fr,
//     polynomial: Vec<Fr>,
//     comm: G1Affine
// }

// impl User {
//     fn new(
//         sk: Fr,
//         rln: &mut RLN,
//     ) -> Self {
//         let polynomial = vec![];
//         let comm = G1Affine::default();

//         Self {
//             sk,
//             polynomial,
//             comm
//         }
//     }

//     fn register_epoch(
//         &self,
//         rln: &mut RLN
//     ) {
//         let rng = &mut test_rng();
//         let mut polynomial = UniPoly_381::rand((rln.limit + 1) as usize, rng);
//         *polynomial.first_mut().unwrap() = self.sk;
//         assert!(polynomial.coeffs()[0] == self.sk);

//         let (comm, rand) = KZG::commit(&KEYS.0, &self.polynomial, None, None).unwrap();
//         let zkp = circuit::create_zkp(self.polynomial, self.comm);

//         rln.register_epoch(zkp, comm);
//     }

//     fn send(
//         &self,
//         message_hash: Fr,
//         rln: &mut RLN
//     ) {
//         let evaluation = self.polynomial.evaluate(&message_hash);
//         let proof = KZG::open(
//             &KEYS.0,
//             &self.polynomial,
//             message_hash,
//             &Randomness::<Fr, UniPoly_381>::empty(),
//         )
//         .expect("Cannot make proof");

//         rln.new_message(self.comm, message_hash, evaluation, proof);
//     }
// }


fn main() {
    println!("Hello, world!");
}