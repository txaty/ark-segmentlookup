use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain};

use crate::error::Error;
use crate::kzg::Kzg;
use crate::public_parameters::PublicParameters;
use crate::table::Table;

pub struct Witness<P: Pairing> {
    pub(crate) num_witness_segments: usize,
    pub(crate) segment_size: usize,
    pub poly_f: DensePolynomial<P::ScalarField>,
    pub poly_eval_list_f: Vec<P::ScalarField>,
    pub(crate) segment_indices: Vec<usize>,
}

impl<P: Pairing> Witness<P> {
    pub fn new(
        pp: &PublicParameters<P>,
        table: &Table<P>,
        queried_segment_indices: &[usize],
    ) -> Result<Self, Error> {
        if queried_segment_indices.len() != pp.num_witness_segments {
            return Err(Error::InvalidNumberOfQueries(queried_segment_indices.len()));
        }

        let mut table_element_indices =
            Vec::with_capacity(pp.num_witness_segments * pp.segment_size);
        for &segment_index in queried_segment_indices {
            for j in 0..pp.segment_size {
                let index = segment_index * pp.segment_size + j;
                if index >= table.values.len() {
                    return Err(Error::InvalidSegmentElementIndex(index));
                }

                table_element_indices.push(segment_index * pp.segment_size + j);
            }
        }

        let poly_eval_list_f: Vec<P::ScalarField> = table_element_indices
            .iter()
            .map(|&i| table.values[i])
            .collect();
        let poly_coeff_list_f = pp.domain_v.ifft(&poly_eval_list_f);
        let poly_f = DensePolynomial::from_coefficients_vec(poly_coeff_list_f);

        Ok(Self {
            num_witness_segments: pp.num_witness_segments,
            segment_size: pp.segment_size,
            poly_f,
            poly_eval_list_f,
            segment_indices: queried_segment_indices.to_vec(),
        })
    }

    pub fn new_with_padding(
        pp: &PublicParameters<P>,
        table: &Table<P>,
        queried_segment_indices: &[usize],
    ) -> Result<Self, Error> {
        let mut queried_segment_indices = queried_segment_indices.to_vec();
        queried_segment_indices.resize(pp.num_witness_segments, 0);

        Self::new(pp, table, &queried_segment_indices)
    }

    pub fn generate_statement(&self, g1_srs: &[P::G1Affine]) -> P::G1Affine {
        Kzg::<P::G1>::commit(g1_srs, &self.poly_f).into_affine()
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_std::rand::RngCore;
    use ark_std::test_rng;

    use crate::table::rand_segments;

    use super::*;

    #[test]
    fn test_witness_new() {
        let mut rng = test_rng();
        let pp =
            PublicParameters::setup(&mut rng, 8, 4, 4).expect("Failed to setup public parameters");
        let segments = rand_segments::generate(&pp);

        let t = Table::<Bn254>::new(&pp, segments).expect("Failed to create table");

        let queried_segment_indices: Vec<usize> = (0..pp.num_witness_segments)
            .map(|_| rng.next_u32() as usize % pp.num_table_segments)
            .collect();

        Witness::new(&pp, &t, &queried_segment_indices).expect("Failed to create witness");
    }
}
