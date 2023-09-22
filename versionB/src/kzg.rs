use halo2::{
    arithmetic::{best_multiexp, kate_division, Field},
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine, G2Affine, Gt},
        group::Curve,
        pairing::Engine,
    },
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};

pub fn multiexp(keys: &ParamsKZG<Bn256>, poly: &[Fr]) -> G1Affine {
    let g = keys.get_g()[0..poly.len()].to_vec();
    best_multiexp(poly, &g).to_affine()
}

pub fn commit(keys: &ParamsKZG<Bn256>, poly: &[Fr]) -> G1Affine {
    multiexp(keys, poly)
}

pub fn witness_polynomial(keys: &ParamsKZG<Bn256>, poly: Vec<Fr>, b: Fr) -> G1Affine {
    let mut q = kate_division(poly.iter(), b);
    q.push(Fr::ZERO);
    multiexp(keys, &q)
}

pub fn verify_proof(
    keys: &ParamsKZG<Bn256>,
    proof: &G1Affine,
    b: Fr,
    evaluation: Fr,
    paring_cache: &Gt,
) -> bool {
    let g = G1Affine::generator();
    let h = G2Affine::generator();
    let h_to_alpha_minus_b = (keys.s_g2() - h * b).to_affine();
    let rhs = Bn256::pairing(proof, &h_to_alpha_minus_b) + Bn256::pairing(&g, &h) * evaluation;

    *paring_cache == rhs
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2::arithmetic::eval_polynomial;
    use rand::thread_rng;

    #[test]
    fn test_kzg() {
        let rng = &mut thread_rng();
        let keys = ParamsKZG::<Bn256>::new(2);

        let coeffs = vec![
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
            Fr::random(rng.clone()),
        ];

        let comm = commit(&keys, &coeffs);

        let b = Fr::random(rng.clone());
        let proof = witness_polynomial(&keys, coeffs.clone(), b);

        let evaluation = eval_polynomial(&coeffs, b);
        let pairing_cache = Bn256::pairing(&comm, &G2Affine::generator());

        assert!(verify_proof(&keys, &proof, b, evaluation, &pairing_cache));
    }
}
