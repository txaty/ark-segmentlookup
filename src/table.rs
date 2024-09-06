use crate::error::Error;
use crate::kzg::Kzg;
use crate::public_parameters::PublicParameters;
use crate::toeplitz::UpperToeplitz;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_std::Zero;
use rayon::prelude::*;
use std::ops::Mul;

pub struct Table<P: Pairing> {
    num_segments: usize,
    segment_size: usize,
    pub(crate) values: Vec<P::ScalarField>,
}

pub struct TablePreprocessedParameters<P: Pairing> {
    pub(crate) g2_affine_t: P::G2Affine,
    pub(crate) g1_affine_list_q1: Vec<P::G1Affine>,
}

impl<P: Pairing> Table<P> {
    pub fn new(
        pp: &PublicParameters<P>,
        segment_values: Vec<Vec<P::ScalarField>>,
    ) -> Result<Self, Error> {
        let num_segments = pp.num_table_segments;
        let segment_size = pp.segment_size;

        if segment_values.len() != num_segments {
            return Err(Error::InvalidNumberOfSegments(segment_values.len()));
        }

        let mut values = Vec::with_capacity(num_segments * segment_size);
        for segment in segment_values {
            if segment.len() != segment_size {
                return Err(Error::InvalidSegmentSize(segment.len()));
            }
            values.extend_from_slice(&segment);
        }

        Ok(Self {
            num_segments,
            segment_size,
            values,
        })
    }

    pub fn preprocess(
        &self,
        pp: &PublicParameters<P>,
    ) -> Result<TablePreprocessedParameters<P>, Error> {
        if self.num_segments != pp.num_table_segments {
            return Err(Error::InvalidNumberOfSegments(self.num_segments));
        }

        if self.segment_size != pp.segment_size {
            return Err(Error::InvalidSegmentSize(self.segment_size));
        }

        let domain = pp.domain_w;
        let g1_affine_srs = &pp.g1_affine_srs;
        let g2_affine_srs = &pp.g2_affine_srs;

        let table_poly = DensePolynomial::from_coefficients_slice(&domain.ifft(&self.values));
        let g2_affine_t: P::G2Affine = Kzg::<P::G2>::commit(g2_affine_srs, &table_poly).into();
        let g1_affine_list_q1 = compute_quotients::<P>(&table_poly, &domain, g1_affine_srs)?;

        Ok(TablePreprocessedParameters {
            g2_affine_t,
            g1_affine_list_q1,
        })
    }
}

fn compute_quotients<P: Pairing>(
    poly_t: &DensePolynomial<P::ScalarField>,
    domain: &Radix2EvaluationDomain<P::ScalarField>,
    g1_affine_srs: &[P::G1Affine],
) -> Result<Vec<P::G1Affine>, Error> {
    /*
        - N (table size) is always pow2
        - Toeplitz multiplication will happen in 2 * N, so appending zero commitments on hs is not needed
    */
    let domain_size = domain.size();
    if poly_t.degree() >= domain_size {
        return Err(Error::InvalidPolynomialDegree(poly_t.degree()));
    }

    // Resize the polynomial coefficients to the domain size
    let mut poly_t_coeffs = poly_t.coeffs().to_vec();
    poly_t_coeffs.resize(domain_size, P::ScalarField::zero());

    let toeplitz = UpperToeplitz::from_coeff_slice(&poly_t_coeffs);

    let g1_affine_srs = g1_affine_srs.iter().take(domain_size).collect::<Vec<_>>();
    let mut g1_srs: Vec<P::G1> = g1_affine_srs.par_iter().map(|t| t.into_group()).collect();
    g1_srs.reverse();

    let g1_list_h: Vec<P::G1> = toeplitz.mul_by_vec(&g1_srs);
    if g1_list_h.len() != 2 * domain_size {
        return Err(Error::InvalidCommitmentLength(format!(
            "Expected h_commitments length to be {}, but was {}",
            2 * domain.size(),
            g1_list_h.len()
        )));
    }

    let ks: Vec<_> = domain.fft(&g1_list_h[..domain.size()]);

    let fr_inv_n = domain
        .size_as_field_element()
        .inverse()
        .ok_or(Error::FailedToInverseFieldElement)?;
    let normalized_roots: Vec<P::ScalarField> =
        domain.elements().map(|g_i| g_i * fr_inv_n).collect();

    let qs: Vec<P::G1> = ks
        .par_iter()
        .zip(normalized_roots)
        .map(|(ki, normalizer_i)| ki.mul(normalizer_i))
        .collect();

    Ok(P::G1::normalize_batch(&qs))
}

#[cfg(test)]
pub mod rand_segments {
    use ark_ec::pairing::Pairing;
    use ark_std::UniformRand;

    use crate::public_parameters::PublicParameters;

    pub fn generate<P: Pairing>(pp: &PublicParameters<P>) -> Vec<Vec<P::ScalarField>> {
        let mut rng = ark_std::test_rng();
        let mut segments = Vec::with_capacity(pp.num_table_segments);
        for _ in 0..pp.num_table_segments {
            let mut segment = Vec::with_capacity(pp.segment_size);
            for _ in 0..pp.segment_size {
                segment.push(P::ScalarField::rand(&mut rng));
            }
            segments.push(segment);
        }

        segments
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_std::test_rng;

    use super::*;

    #[test]
    fn test_table_new() {
        let mut rng = test_rng();
        let pp =
            PublicParameters::setup(&mut rng, 8, 4, 4).expect("Failed to setup public parameters");
        let segments = rand_segments::generate::<Bn254>(&pp);

        Table::<Bn254>::new(&pp, segments).expect("Failed to create table");
    }

    #[test]
    fn test_table_preprocess() {
        let mut rng = test_rng();
        let pp =
            PublicParameters::setup(&mut rng, 8, 4, 4).expect("Failed to setup public parameters");
        let segments = rand_segments::generate(&pp);

        let t = Table::<Bn254>::new(&pp, segments).expect("Failed to create table");

        t.preprocess(&pp).expect("Failed to preprocess table");
    }
}
