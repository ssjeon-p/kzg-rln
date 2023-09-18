use halo2::{
    poly::{kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
    commitment::{ParamsProver, Blind}, EvaluationDomain},
    halo2curves::{bn256::{Fr, Bn256, G1Affine, G2Affine}, pairing::{self, Engine}, group::cofactor::CofactorCurveAffine},
    arithmetic::Field,
};

struct KZG {
    keys: ParamsKZG<Bn256>,
    domain: EvaluationDomain<Fr>,
    
}

pub fn commit(
    keys: &ParamsKZG<Bn256>,
    poly: Vec<Fr>,
) -> G1Affine {
    let domain = EvaluationDomain::<Fr>::new(1, 2);
    let poly = domain.coeff_from_vec(poly);
    keys.commit(&poly, Blind::default()).into()
}

// compute phi(x) = (f(x)-f(b))/(x-b), return g^{phi(alpha)}
pub fn create_proof(
    keys: &ParamsKZG<Bn256>,
    poly: Vec<Fr>,
    b: Fr,
) -> G1Affine {
    b = -b;
    let a = poly.into_iter();

    let mut q = vec![Fr::ZERO; a.len() - 1];

    let mut tmp = Fr::ZERO;
    for (q, r) in q.iter_mut().rev().zip(a.rev()) {
        let mut lead_coeff = *r;
        lead_coeff.sub_assign(&tmp);
        *q = lead_coeff;
        tmp = lead_coeff;
        tmp -= b;
    }

    commit(&keys, q)
}

pub fn verify_proof(
    keys: &ParamsKZG<Bn256>,
    proof: G1Affine,
    commit: G1Affine,
    b: Fr,
) -> bool {

}

pub fn pairing_check (
    &keys: ParamsKZG<Bn256>,
    pairing,
) {
    Bn256::pairing(&G1Affine::identity(), &G2Affine::identity());
}