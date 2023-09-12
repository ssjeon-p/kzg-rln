use eigentrust_zk::{
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
    halo2curves::bn256::{Bn256, Fr},
    halo2curves::{ff::PrimeField, group::Curve, pairing::Engine, CurveAffine},
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
    maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RegionCtx}, EccConfig,
};

use rand::{rngs::OsRng, thread_rng};
use std::{
    marker::PhantomData,
    ops::{Deref, IndexMut},
};

const ARITY: usize = 2;
const HEIGHT: usize = 3;
const LENGTH: usize = 4;

type NativeH = Poseidon<Fr, 5, Params>;
type H = PoseidonChipset<Fr, 5, Params>;

pub type type_tree = MerkleTree<Fr, ARITY, HEIGHT, Poseidon<Fr, 5, Params>>;
pub type type_path = Path<Fr, ARITY, HEIGHT, LENGTH, Poseidon<Fr, 5, Params>>;

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
    setup: Vec<Value<Bn256>>,
    gen: Value<Bn256>,
}

impl<const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> Circuit
    for Mycircuit<NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    type Config = Myconfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let (base, scalar) = GeneralEccChip::<Bn256, Fr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new();
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

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let ecc_chip_config = EccConfig::new(config.range_config.clone(), config.main_gate_config.clone());
        let ecc_chip = GeneralEccChip::<Bn256, Fr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

        let sum = layouter.assign_region(
            || "region 0",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let a = self.a;
                let b = self.b;
                let a = ecc_chip.assign_point(ctx, a)?;
                let b = ecc_chip.assign_point(ctx, b)?;
                let c = ecc_chip.add(ctx, &a, &b)?;
                ecc_chip.normalize(ctx, &c)
            },
        )?;
        ecc_chip.expose_public(layouter.namespace(|| "sum"), sum, 0)?;

        let sum = layouter.assign_region(
            || "region 1",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let a = self.a;
                let a = ecc_chip.assign_point(ctx, a)?;
                let c = ecc_chip.double(ctx, &a)?;
                ecc_chip.normalize(ctx, &c)
            },
        )?;
        ecc_chip.expose_public(layouter.namespace(|| "sum"), sum, 8)?;

        config.config_range(&mut layouter)?;

        Ok(())
    }
}

pub fn tree_with_user(key_hash: Fr) -> (type_tree, type_path) {
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
