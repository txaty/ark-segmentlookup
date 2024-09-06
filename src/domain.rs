use crate::error::Error;
use crate::kzg::Kzg;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use ark_std::{One, Zero};
use std::ops::Div;

pub(crate) fn vanishing_poly_commitment_affine<C: CurveGroup>(
    affine_srs: &[C::Affine],
    domain: &Radix2EvaluationDomain<C::ScalarField>,
) -> C::Affine {
    let vanishing_poly: DensePolynomial<C::ScalarField> = domain.vanishing_polynomial().into();

    Kzg::<C>::commit(&affine_srs, &vanishing_poly).into_affine()
}

pub(crate) fn create_sub_domain<P: Pairing>(
    original_domain: &Radix2EvaluationDomain<P::ScalarField>,
    order: usize,
    segment_size: usize,
) -> Result<Radix2EvaluationDomain<P::ScalarField>, Error> {
    if segment_size == 0 {
        return Err(Error::InvalidSegmentSize(segment_size));
    }
    if segment_size == 1 {
        return Ok(original_domain.clone());
    }
    if !order.is_power_of_two() {
        return Err(Error::InvalidEvaluationDomainSize(order));
    }
    let original_order = original_domain.size();
    if segment_size > original_order {
        return Err(Error::InvalidSegmentSize(segment_size));
    }
    if segment_size == original_order {
        let domain_1 = Radix2EvaluationDomain::<P::ScalarField>::new(1)
            .ok_or(Error::FailedToCreateEvaluationDomain)?;
        return Ok(domain_1);
    }

    let size: u64 = order as u64;
    let log_size_of_group = order.trailing_zeros();
    if log_size_of_group > <P::ScalarField as FftField>::TWO_ADICITY {
        return Err(Error::InvalidEvaluationDomainSize(order));
    }

    let roots_of_unity_larger_domain = roots_of_unity::<P>(&original_domain);
    let group_gen = roots_of_unity_larger_domain[segment_size];
    let size_as_field_element = P::ScalarField::from(size);
    let size_inv = size_as_field_element
        .inverse()
        .ok_or(Error::FailedToInverseFieldElement)?;

    let group_gen_inv = group_gen
        .inverse()
        .ok_or(Error::FailedToInverseFieldElement)?;

    Ok(Radix2EvaluationDomain {
        size,
        log_size_of_group,
        size_as_field_element,
        size_inv,
        group_gen,
        group_gen_inv,
        offset: P::ScalarField::one(),
        offset_inv: P::ScalarField::one(),
        offset_pow_size: P::ScalarField::one(),
    })
}

pub(crate) fn create_domain_with_generator<F: FftField>(
    group_gen: F,
    size: u64,
) -> Result<Radix2EvaluationDomain<F>, Error> {
    if !size.is_power_of_two() {
        return Err(Error::InvalidEvaluationDomainSize(size as usize));
    }
    let log_size_of_group = size.trailing_zeros();

    // libfqfft uses > https://github.com/scipr-lab/libfqfft/blob/e0183b2cef7d4c5deb21a6eaf3fe3b586d738fe0/libfqfft/evaluation_domain/domains/basic_radix2_domain.tcc#L33
    if log_size_of_group > F::TWO_ADICITY {
        return Err(Error::InvalidEvaluationDomainSize(size as usize));
    }

    // Check that it is indeed the 2^(log_size_of_group) root of unity.
    debug_assert_eq!(group_gen.pow([size]), F::one());
    let size_as_field_element = F::from(size);
    let size_inv = size_as_field_element
        .inverse()
        .ok_or(Error::FailedToInverseFieldElement)?;
    let group_gen_inv = group_gen
        .inverse()
        .ok_or(Error::FailedToInverseFieldElement)?;

    Ok(Radix2EvaluationDomain {
        size,
        log_size_of_group,
        size_as_field_element,
        size_inv,
        group_gen,
        group_gen_inv,
        offset: F::one(),
        offset_inv: F::one(),
        offset_pow_size: F::one(),
    })
}

pub(crate) fn roots_of_unity<P: Pairing>(
    domain: &Radix2EvaluationDomain<P::ScalarField>,
) -> Vec<P::ScalarField> {
    domain.elements().collect()
}

pub(crate) fn identity_poly<P: Pairing>(
    domain: &Radix2EvaluationDomain<P::ScalarField>,
) -> DensePolynomial<P::ScalarField> {
    let id_list = vec![P::ScalarField::one(); domain.size()];

    Evaluations::from_vec_and_domain(id_list, *domain).interpolate()
}

pub(crate) fn divide_by_vanishing_poly_checked<P: Pairing>(
    domain: &Radix2EvaluationDomain<P::ScalarField>,
    poly: &DensePolynomial<P::ScalarField>,
) -> Result<DensePolynomial<P::ScalarField>, Error> {
    let (quotient, remainder) = poly
        .divide_by_vanishing_poly(*domain)
        .ok_or(Error::FailedToDivideByVanishingPolynomial)?;

    if !remainder.is_zero() {
        return Err(Error::RemainderAfterDivisionIsNonZero);
    }

    Ok(quotient)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;

    use super::*;

    #[test]
    fn test_create_domain_from_large_domain() {
        let num_queries = 8;
        let segment_size = 4;

        let order_v = num_queries * segment_size;
        let domain_v =
            Radix2EvaluationDomain::<<Bn254 as Pairing>::ScalarField>::new(order_v).unwrap();
        let order_k = num_queries;
        let domain_k = create_sub_domain::<Bn254>(&domain_v, order_k, segment_size).unwrap();
        let group_gen_k = domain_k.group_gen;
        assert_eq!(
            group_gen_k.pow([domain_k.size]),
            <Bn254 as Pairing>::ScalarField::one()
        );
    }
}
