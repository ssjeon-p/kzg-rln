use halo2::{
    arithmetic::{best_multiexp, Field},
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine, G2Affine},
        group::Curve,
        pairing::Engine,
    },
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};

pub fn multiexp(keys: &ParamsKZG<Bn256>, poly: Vec<Fr>) -> G1Affine {
    let g = keys.get_g()[0..poly.len()].to_vec();
    best_multiexp(&poly, &g).to_affine()
}

pub fn commit(keys: &ParamsKZG<Bn256>, poly: Vec<Fr>) -> G1Affine {
    multiexp(keys, poly)
}

// compute phi(x) = (f(x)-f(b))/(x-b), return g^{phi(alpha)}
pub fn witness_polynomial(keys: &ParamsKZG<Bn256>, poly: Vec<Fr>, b: Fr) -> G1Affine {
    let a = poly.into_iter();

    let mut q = vec![Fr::ZERO; a.len() - 1];

    let mut tmp = Fr::ZERO;
    for (q, r) in q.iter_mut().rev().zip(a.rev()) {
        let mut lead_coeff = r;
        lead_coeff -= tmp;
        *q = lead_coeff;
        tmp = lead_coeff;
        tmp *= -b;
    }
    q.push(Fr::ZERO);
    multiexp(keys, q)
}

pub fn verify_proof(
    keys: &ParamsKZG<Bn256>,
    proof: &G1Affine,
    commit: &G1Affine,
    b: Fr,
    evaluation: Fr,
) -> bool {
    let g = G1Affine::generator();
    let h = G2Affine::generator();
    let lhs = Bn256::pairing(commit, &h);
    let h_to_alpha_minus_b = (keys.s_g2() - h * b).to_affine();
    let rhs = Bn256::pairing(proof, &h_to_alpha_minus_b) + Bn256::pairing(&g, &h) * evaluation;

    lhs == rhs
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

        let comm = commit(&keys, coeffs.clone());

        let b = Fr::random(rng.clone());
        let proof = witness_polynomial(&keys, coeffs.clone(), b);

        let evaluation = eval_polynomial(&coeffs, b);

        assert!(verify_proof(&keys, &proof, &comm, b, evaluation));
    }
}
