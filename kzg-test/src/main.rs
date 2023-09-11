use halo2::{
    poly::kzg::commitment::KZGCommitmentScheme,
    poly::{EvaluationDomain, commitment::CommitmentScheme},
    halo2curves::bn256::{Bn256, Fr},

};

fn main() {
    let params = KZGCommitmentScheme::<Bn256>::new_params(4);
}
