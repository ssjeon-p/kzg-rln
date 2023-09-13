#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]

// use std::collections::HashMap;

// use halo2::{
//     poly::kzg::*,

// };

// use once_cell::sync::Lazy;

mod circuit;
mod linalg;

// type UniPoly_381 = DensePolynomial<<Bls12_381 as PairingEngine>::Fr>;
// type KZG = KZG10<Bls12_381, UniPoly_381>;

// struct RLN {
//     limit: u8,
//     shares: HashMap<Commitment<Bls12_381>, Vec<(Fr, Fr)>>,
//     tree: circuit::type_tree,
// }

// impl RLN {
//     fn new_RLN_with_user(limit: u8) -> Self {
//         Self {
//             limit,
//             shares: HashMap::new(),
//             tree: circuit::type_tree::default(),
//         }
//     }

//     fn register_epoch(
//         &mut self,
//         zkp: MockProver<Fp>,
//         comm: Commitment<Bls12_381>,
//     ) {
//         zkp.assert_satisfied();
//         self.shares.insert(comm, vec![]);
//     }

//     fn new_message(
//         &mut self,
//         comm: Commitment<Bls12_381>,
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
//     path:  Vec<Fr>,
//     polynomial: UniPoly_381,
//     comm: Commitment<Bls12_381>,
// }

// impl User {
//     fn new(
//         sk: Fr,
//         rln: &mut RLN,
//     ) -> Self {
//         let path = rln.add_user(sk);
//         let polynomial = UniPoly_381::default();
//         let comm = Commitment::<Bls12_381>::default();

//         Self {
//             sk,
//             path,
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


use eigentrust_zk::{
    ecc::generic,
    gadgets::{
        main::{MainChip, MainConfig},
        set::{SetChip, SetConfig},
    },
    merkle_tree::{
        native::{MerkleTree, Path},
        MerklePathChip, MerklePathConfig,
    },
    params::hasher::poseidon_bn254_5x5::Params,
    poseidon::{
        native::Poseidon, FullRoundChip, PartialRoundChip, PoseidonChipset, PoseidonConfig,
    },
    utils::{generate_params, prove_and_verify},
    Chip, CommonConfig,
};

use halo2::{
    arithmetic::{eval_polynomial, Field},
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256,
    halo2curves::bn256::{Bn256, Fr},
    halo2curves::{
        bn256::Fq,
        ff::PrimeField,
        group::{prime::PrimeCurveAffine, Curve},
        pairing::Engine,
        CurveAffine,
    },
    plonk::{Circuit, ConstraintSystem, Error},
    poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
    poly::Coeff,
    poly::Polynomial,
    poly::{commitment::Verifier, kzg::strategy::AccumulatorStrategy},
    poly::{
        commitment::{Blind, CommitmentScheme, Prover},
        kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
    },
    poly::{
        commitment::{ParamsProver, ParamsVerifier},
        EvaluationDomain,
    },
    poly::{ProverQuery, VerificationStrategy, VerifierQuery},
    transcript::{EncodedChallenge, TranscriptReadBuffer},
};

use ecc::{
    general_ecc::GeneralEccChip,
    integer::{rns::Integer, AssignedInteger, IntegerInstructions, Range, NUMBER_OF_LOOKUP_LIMBS},
    maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx},
    AssignedPoint, EccConfig,
};

use rand::{rngs::OsRng, thread_rng};
use std::{
    marker::PhantomData,
    ops::{Deref, IndexMut},
};

const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;

#[derive(Clone, Debug)]
struct Myconfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl Myconfig {
    fn new<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    >(
        meta: &mut ConstraintSystem<N>,
    ) -> Self {
        let (rns_base, rns_scalar) = GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();

        let main_gate_config = MainGate::<N>::configure(meta);
        let mut overflow_bit_lens: Vec<usize> = vec![];
        overflow_bit_lens.extend(rns_base.overflow_lengths());
        overflow_bit_lens.extend(rns_scalar.overflow_lengths());
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

        let range_config = RangeChip::<N>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        Myconfig {
            main_gate_config,
            range_config,
        }
    }

    fn config_range<N: PrimeField>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
        let range_chip = RangeChip::<N>::new(self.range_config.clone());
        range_chip.load_table(layouter)?;

        Ok(())
    }
}

#[derive(Default, Clone, Debug)]
struct Mycircuit<const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> {
    degree: usize,
    coeffs: Vec<Fr>,
    setup: Vec<bn256::G1Affine>,
}

impl<const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> Circuit<Fr>
    for Mycircuit<NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    type Config = Myconfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let (base, scalar) =
            GeneralEccChip::<bn256::G1Affine, Fr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let main_gate_config = MainGate::<Fr>::configure(meta);
        let mut overflow_bit_lens: Vec<usize> = vec![];
        overflow_bit_lens.extend(base.overflow_lengths());
        overflow_bit_lens.extend(scalar.overflow_lengths());
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

        let range_config = RangeChip::<Fr>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        Myconfig {
            main_gate_config,
            range_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let ecc_chip_config =
            EccConfig::new(config.range_config.clone(), config.main_gate_config.clone());
        let ecc_chip = GeneralEccChip::<bn256::G1Affine, Fr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
            ecc_chip_config,
        );
        let scalar_chip = ecc_chip.scalar_field_chip();

        let out = layouter.assign_region(
            || "region mul",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let pairs: Vec<(
                    AssignedPoint<
                        <bn256::G1Affine as CurveAffine>::Base,
                        Fr,
                        NUMBER_OF_LIMBS,
                        BIT_LEN_LIMB,
                    >,
                    AssignedInteger<
                        <bn256::G1Affine as CurveAffine>::ScalarExt,
                        Fr,
                        NUMBER_OF_LIMBS,
                        BIT_LEN_LIMB,
                    >,
                )> = (0..self.degree + 1)
                    .map(|i| {
                        let coeff = Integer::from_fe(self.coeffs[i], ecc_chip.rns_scalar());
                        let setup =
                            ecc_chip.assign_point(ctx, Value::known(self.setup[i].into()))?;
                        let coeff = scalar_chip.assign_integer(
                            ctx,
                            Value::known(coeff).into(),
                            Range::Remainder,
                        )?;
                        Ok((setup, coeff))
                    })
                    .collect::<Result<_, Error>>()?;

                let out = ecc_chip.mul_batch_1d_horizontal(ctx, pairs, self.degree + 1)?;
                ecc_chip.normalize(ctx, &out)
            },
        )?;
        ecc_chip.expose_public(layouter.namespace(|| "commit"), out, 0);

        config.config_range(&mut layouter)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use ecc::{Point, integer::rns::Rns};
    use halo2::dev::MockProver;

    use super::*;

    #[test]
    fn test_commit() {
        let rng = &mut thread_rng();
        let keys = ParamsKZG::<Bn256>::new(2);
        let domain = EvaluationDomain::<Fr>::new(1, 2);
        let coeffs = vec![
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
        ];
        let poly = domain.coeff_from_vec(coeffs.clone());
        let commit = keys.commit(&poly, halo2::poly::commitment::Blind::default()).to_affine();
        let g = keys.get_g().to_vec();

        let test_circuit = Mycircuit::<NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            degree: 3,
            coeffs: coeffs,
            setup: g,
        };

        let (rns_base, _, _) = setup::<bn256::G1Affine, Fr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(0);
        let rns_base = Rc::new(rns_base);

        let random = bn256::G1Affine::random(rng);
        let input = Point::new(Rc::clone(&rns_base), random);
        let input = input.public();

        let prover = MockProver::run(10, &test_circuit, vec![input]).unwrap();
        //prover.assert_satisfied();
    }

    #[allow(clippy::type_complexity)]
    fn setup<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    >(
        k_override: u32,
    ) -> (
        Rns<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Rns<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        u32,
    ) {
        let (rns_base, rns_scalar) = GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        if k_override != 0 {
            k = k_override;
        }
        (rns_base, rns_scalar, k)
    }
}
