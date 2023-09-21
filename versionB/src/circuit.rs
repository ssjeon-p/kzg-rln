use std::rc::Rc;

use halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Fq, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error},
};

use ecc::{
    integer::rns::Rns,
    integer::NUMBER_OF_LOOKUP_LIMBS,
    maingate::{
        AssignedValue, MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig,
        RangeInstructions, RegionCtx,
    },
    AssignedPoint, BaseFieldEccChip, EccConfig, Point,
};

use rand::rngs::OsRng;

const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;
type BASE = Fq;
type SCALAR = Fr;

#[derive(Clone, Debug)]
struct Myconfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

#[derive(Default, Clone, Debug)]
struct Mycircuit<const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> {
    coeffs: Vec<Fr>,
    setup: Vec<G1Affine>,
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
        let rns = Rns::<BASE, SCALAR, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();
        let main_gate_config = MainGate::<SCALAR>::configure(meta);
        let overflow_bit_lens = rns.overflow_lengths();
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

        let range_config = RangeChip::<SCALAR>::configure(
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
        mut layouter: impl Layouter<SCALAR>,
    ) -> Result<(), Error> {
        let ecc_chip_config =
            EccConfig::new(config.range_config.clone(), config.main_gate_config.clone());
        let mut ecc_chip =
            BaseFieldEccChip::<G1Affine, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
        let maingate = MainGate::<SCALAR>::new(config.main_gate_config.clone());

        layouter.assign_region(
            || "assign aux values",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                ecc_chip.assign_aux_generator(ctx, Value::known(G1Affine::random(OsRng)))?;
                ecc_chip.assign_aux(ctx, 2, self.coeffs.len())?;
                Ok(())
            },
        )?;

        let out = layouter.assign_region(
            || "region mul",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let pairs: Vec<(
                    AssignedPoint<BASE, SCALAR, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                    AssignedValue<SCALAR>,
                )> = (0..self.coeffs.len())
                    .map(|i| {
                        let coeff = maingate.assign_value(ctx, Value::known(self.coeffs[i]))?;
                        let setup =
                            ecc_chip.assign_point(ctx, Value::known(self.setup[i]))?;
                        Ok((setup, coeff))
                    })
                    .collect::<Result<_, Error>>()?;
                let out = ecc_chip.mul_batch_1d_horizontal(ctx, pairs, 2)?;
                ecc_chip.normalize(ctx, &out)
            },
        )?;
        ecc_chip.expose_public(layouter.namespace(|| "commit"), out, 0)?;

        let range_chip = RangeChip::<Fr>::new(config.range_config.clone());
        range_chip.load_table(&mut layouter)?;

        Ok(())
    }
}

fn rns_setup(k_override: u32) -> (Rns<BASE, SCALAR, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, u32) {
    let rns = Rns::construct();
    let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
    let mut k: u32 = (bit_len_lookup + 1) as u32;
    if k_override != 0 {
        k = k_override;
    }
    (rns, k)
}

pub fn create_zkp(coeffs: Vec<Fr>, comm: &G1Affine, setup: Vec<G1Affine>) -> MockProver<Fr> {
    const NUMBER_OF_LIMBS: usize = 4;
    const BIT_LEN_LIMB: usize = 68;

    let circuit = Mycircuit::<NUMBER_OF_LIMBS, BIT_LEN_LIMB> { coeffs, setup };

    let (rns, _) = rns_setup(20);
    let rns = Rc::new(rns);

    let input = Point::new(Rc::clone(&rns), *comm);
    let input = input.public();

    MockProver::run(18, &circuit, vec![input]).unwrap()
}

#[cfg(test)]
mod tests {
    use std::{rc::Rc, vec};

    use halo2::{
        arithmetic::Field,
        dev::MockProver,
        halo2curves::bn256::Bn256,
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    };
    use rand::thread_rng;

    use crate::kzg::commit;

    use super::*;

    #[test]
    fn test_commit() {
        let rng = &mut thread_rng();
        let keys = ParamsKZG::<Bn256>::new(2);
        let coeffs = vec![
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
        ];
        let comm = commit(&keys, coeffs.clone());
        let g = keys.get_g()[0..4].to_vec();
        let test_circuit = Mycircuit::<NUMBER_OF_LIMBS, BIT_LEN_LIMB> { coeffs, setup: g };

        let (rns, _) = rns_setup(20);
        let rns = Rc::new(rns);

        let input = Point::new(Rc::clone(&rns), comm);
        let input = input.public();
        let prover = MockProver::run(18, &test_circuit, vec![input]).unwrap();

        prover.assert_satisfied();
    }
}
