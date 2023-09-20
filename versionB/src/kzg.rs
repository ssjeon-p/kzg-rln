use halo2::{
    poly::{kzg::commitment::ParamsKZG,
    commitment::{ParamsProver, Blind}, EvaluationDomain},
    halo2curves::{bn256::{Fr, Bn256, G1Affine, G2Affine}, pairing::Engine, group::Curve},
    arithmetic::Field,
};

pub fn commit(
    keys: &ParamsKZG<Bn256>,
    poly: Vec<Fr>,
) -> G1Affine {
    let domain = EvaluationDomain::<Fr>::new(1, 2);
    let poly = domain.coeff_from_vec(poly);
    keys.commit(&poly, Blind::default()).into()
}

// compute phi(x) = (f(x)-f(b))/(x-b), return g^{phi(alpha)}
pub fn witness_polynomial(
    keys: &ParamsKZG<Bn256>,
    poly: Vec<Fr>,
    b: Fr,
) -> G1Affine {
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
    commit(&keys, q)
}

pub fn verify_proof(
    keys: &ParamsKZG<Bn256>,
    proof: G1Affine,
    commit: G1Affine,
    b: Fr,
    eval: Fr,
) -> bool {
    let g = G1Affine::generator();
    let h = G2Affine::generator();
    let lhs = Bn256::pairing(&commit, &h);
    let h_to_alpha_minus_b = (keys.s_g2() - h * b).to_affine();
    let rhs = Bn256::pairing(&proof, &h_to_alpha_minus_b) + Bn256::pairing(&g, &h) * eval;

    lhs == rhs
}

#[cfg(test)]
mod test {
    use halo2::arithmetic::eval_polynomial;
    use rand::thread_rng;
    use super::*;

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

        let commit = commit(&keys, coeffs.clone());
        
        let b = Fr::random(rng.clone());
        let proof = witness_polynomial(&keys, coeffs.clone(), b);

        let eval = eval_polynomial(&coeffs, b);
        
        assert!(verify_proof(&keys, proof, commit, b, eval));
    }
}
