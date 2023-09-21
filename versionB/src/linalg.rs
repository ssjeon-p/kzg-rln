use halo2::arithmetic::Field;
use halo2::halo2curves::bn256::Fr;

pub fn determinant(mut matrix: Vec<Vec<Fr>>) -> Fr {
    let n = matrix.len();
    let mut det = Fr::from(1);

    for i in 0..n {
        let mut pivot_row = i;
        for (j, col) in matrix.iter().enumerate().skip(i) {
            if col[i] != Fr::from(0) {
                pivot_row = j;
                break;
            }
        }

        if pivot_row != i {
            matrix.swap(i, pivot_row);
            det = -det;
        }

        let pivot = matrix[i][i];

        if pivot == Fr::from(0) {
            return Fr::from(0);
        }

        det *= pivot;

        for j in (i + 1)..n {
            let factor = matrix[j][i] * Fr::invert(&pivot).unwrap();
            for k in (i + 1)..n {
                matrix[j][k] = matrix[j][k] - factor * matrix[i][k];
            }
        }
    }

    det
}
