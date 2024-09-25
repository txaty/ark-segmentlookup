use crate::error::Error;
use crate::multi_unity::multi_unity_verify;
use crate::prover::Proof;
use crate::public_parameters::PublicParameters;
use crate::table::TablePreprocessedParameters;
use crate::transcript::{Label, Transcript};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::rand::Rng;
use ark_std::{One, Zero};
use rayon::prelude::*;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg};

const BATCH_SIZE: usize = 8;

pub fn verify<P: Pairing, R: Rng + ?Sized>(
    pp: &PublicParameters<P>,
    tpp: &TablePreprocessedParameters<P>,
    statement: P::G1Affine,
    proof: &Proof<P>,
    rng: &mut R,
) -> Result<(), Error> {
    let mut transcript = Transcript::<P::ScalarField>::new();
    transcript.append_public_parameters(&pp, &tpp)?;

    transcript.append_elements(&[
        (Label::G1M, proof.g1_affine_m),
        (Label::G1MDivW, proof.g1_affine_m_div_w),
        (Label::G1Qm, proof.g1_affine_qm),
        (Label::G1L, proof.g1_affine_l),
        (Label::G1LDivV, proof.g1_affine_l_div_v),
        (Label::G1Ql, proof.g1_affine_ql),
        (Label::G1D, proof.g1_affine_d),
        (Label::G1Qd, proof.g1_affine_qd),
        (Label::CaulkG1D, proof.g1_affine_d),
        (Label::CaulkG1UBar, proof.multi_unity_proof.g1_u_bar),
        (Label::CaulkG1H2, proof.multi_unity_proof.g1_h_2),
    ])?;

    let caulk_alpha = transcript.get_and_append_challenge(Label::ChallengeCaulkAlpha)?;

    transcript.append_element(Label::CaulkG1H1, &proof.multi_unity_proof.g1_h_1)?;

    let caulk_beta = transcript.get_and_append_challenge(Label::ChallengeCaulkBeta)?;

    let beta = transcript.get_and_append_challenge(Label::ChallengeBeta)?;
    let delta = transcript.get_and_append_challenge(Label::ChallengeDelta)?;

    transcript.append_elements(&[
        (Label::G1A, proof.g1_affine_a),
        (Label::G1Qa, proof.g1_affine_qa),
        (Label::G1Qb, proof.g1_affine_qb),
        (Label::G1A0, proof.g1_affine_a0),
        (Label::G1B0, proof.g1_affine_b0),
        (Label::G1Px, proof.g1_affine_px),
    ])?;

    let gamma = transcript.get_and_append_challenge(Label::ChallengeGamma)?;

    transcript.append_elements(&[
        (Label::FrB0AtGamma, proof.fr_b0_at_gamma),
        (Label::FrFAtGamma, proof.fr_f_at_gamma),
        (Label::FrLAtGamma, proof.fr_l_at_gamma),
        (Label::FrAAtZero, proof.fr_a_at_zero),
        (Label::FrLAtGammaDivV, proof.fr_l_at_gamma_div_v),
        (Label::FrQlAtGamma, proof.fr_ql_at_gamma),
        (Label::FrDAtGamma, proof.fr_d_at_gamma),
        (Label::FrQdAtGamma, proof.fr_qd_at_gamma),
    ])?;

    let eta = transcript.get_and_append_challenge(Label::ChallengeEta)?;

    let g2_affine_one = pp.g2_affine_srs[0];
    let g2_affine_tau = pp.g2_affine_srs[1];

    let checks: Vec<Result<(), Error>> = vec![
        // Round 2: The first pairing check.
        // This is intended to check the correctness of multiplicity polynomials.
        first_pairing_check(
            &proof,
            &pp.g2_affine_srs,
            pp.g2_affine_zw,
            pp.num_table_segments,
        ),
        // Round 3-8: Multi-unity check.
        multi_unity_verify(
            pp,
            caulk_alpha,
            caulk_beta,
            &proof.g1_affine_d,
            &proof.multi_unity_proof,
            rng,
        )
        .map_err(|_| Error::FailedToCheckMultiUnity),
        // Round 11: The second pairing check.
        // This is intended to check the correctness of polynomial A.
        second_pairing_check::<P>(
            &proof,
            beta,
            delta,
            proof.g1_affine_m,
            tpp.g2_affine_adjusted_t,
            pp.g2_affine_zw,
            &pp.g2_affine_srs,
        ),
        // Round 11: Degree pairing check.
        degree_check(
            &proof,
            pp.num_table_segments,
            pp.num_witness_segments,
            pp.segment_size,
            &pp.g2_affine_srs,
        ),
        // Round 15-4: The third pairing check.
        third_pairing_check(
            &proof,
            statement,
            beta,
            delta,
            gamma,
            eta,
            pp.num_table_segments,
            pp.num_witness_segments,
            pp.segment_size,
            &pp.domain_v,
            g2_affine_tau,
            g2_affine_one,
        ),
        // Round 15-4: The fourth pairing check.
        fourth_pairing_check(&proof, g2_affine_tau, g2_affine_one),
        // Round 15-4: The first point check.
        first_point_check(
            &proof,
            gamma,
            pp.num_witness_segments,
            &pp.domain_v,
            &pp.domain_w,
        ),
        // Round 15-4: The second point check.
        second_point_check(&proof, gamma, &pp.domain_k),
    ];

    checks.into_iter().try_for_each(|check| check)?;

    Ok(())
}

fn first_pairing_check<P: Pairing>(
    proof: &Proof<P>,
    g2_affine_srs: &[P::G2Affine],
    g2_affine_zw: P::G2Affine,
    num_table_segments: usize,
) -> Result<(), Error> {
    let g1_affine_m = proof.g1_affine_m;
    let g1_neg_m_div_w = -proof.g1_affine_m_div_w.into_group();
    let g2_affine_tau_pow_ns = g2_affine_srs[num_table_segments];
    let g2_neg_one = -g2_affine_srs[0].into_group();
    let g1_affine_qm = proof.g1_affine_qm;

    let left_pairing = P::pairing(
        g1_affine_m + g1_neg_m_div_w,
        g2_affine_tau_pow_ns + g2_neg_one,
    );
    let right_pairing = P::pairing(g1_affine_qm, g2_affine_zw);

    if left_pairing != right_pairing {
        return Err(Error::Pairing1Failed);
    }

    Ok(())
}

fn second_pairing_check<P: Pairing>(
    proof: &Proof<P>,
    beta: P::ScalarField,
    delta: P::ScalarField,
    g1_affine_m: P::G1Affine,
    g2_affine_t: P::G2Affine,
    g2_affine_zw: P::G2Affine,
    g2_affine_srs: &[P::G2Affine],
) -> Result<(), Error> {
    let g1_affine_a = proof.g1_affine_a;
    let g2_affine_tau = g2_affine_srs[1];
    let left_pairing = P::pairing(g1_affine_a, g2_affine_t + g2_affine_tau.mul(delta));

    let g1_affine_qa = proof.g1_affine_qa;
    let g1_affine_neg_beta_mul_a = g1_affine_a.mul(-beta).into_affine();
    let g2_one = g2_affine_srs[0];
    let right_pairing = P::multi_pairing(
        &[
            g1_affine_qa,
            g1_affine_m.add(g1_affine_neg_beta_mul_a).into_affine(),
        ],
        &[g2_affine_zw, g2_one],
    );

    if left_pairing != right_pairing {
        return Err(Error::Pairing2Failed);
    }

    Ok(())
}

fn degree_check<P: Pairing>(
    proof: &Proof<P>,
    num_table_segments: usize,
    num_witness_segments: usize,
    segment_size: usize,
    g2_affine_srs: &[P::G2Affine],
) -> Result<(), Error> {
    let g1_affine_px = proof.g1_affine_px;
    let g2_affine_one = g2_affine_srs[0];
    if num_table_segments > num_witness_segments {
        let deg_tau = (num_table_segments - num_witness_segments) * segment_size - 1;
        let g1_affine_b0 = proof.g1_affine_b0;
        let left_pairing = P::pairing(g1_affine_b0, g2_affine_srs[deg_tau]);
        let right_pairing = P::pairing(g1_affine_px, g2_affine_one);

        if left_pairing != right_pairing {
            return Err(Error::DegreeCheckFailed);
        }
    } else if num_table_segments < num_witness_segments {
        let deg_tau = (num_witness_segments - num_table_segments) * segment_size - 1;
        let g1_affine_a0 = proof.g1_affine_a0;
        let left_pairing = P::pairing(g1_affine_a0, g2_affine_srs[deg_tau]);
        let right_pairing = P::pairing(g1_affine_px, g2_affine_one);

        if left_pairing != right_pairing {
            return Err(Error::DegreeCheckFailed);
        }
    }

    Ok(())
}

fn third_pairing_check<P: Pairing>(
    proof: &Proof<P>,
    statement: P::G1Affine,
    beta: P::ScalarField,
    delta: P::ScalarField,
    gamma: P::ScalarField,
    eta: P::ScalarField,
    num_table_segments: usize,
    num_witness_segments: usize,
    segment_size: usize,
    domain_v: &Radix2EvaluationDomain<P::ScalarField>,
    g2_affine_tau: P::G2Affine,
    g2_affine_one: P::G2Affine,
) -> Result<(), Error> {
    // Round 15-1: Compute b_0 = ns * a_0 / (ks)
    let table_elem_size = num_table_segments * segment_size;
    let fr_table_elem_size = P::ScalarField::from(table_elem_size as u64);
    let witness_elem_size = num_witness_segments * segment_size;
    let fr_inv_witness_elem_size = P::ScalarField::from(witness_elem_size as u64)
        .inverse()
        .ok_or(Error::FailedToInverseFieldElement)?;
    let fr_b_at_zero = proof.fr_a_at_zero * fr_table_elem_size * fr_inv_witness_elem_size;

    // Round 15-2: Compute q_{B, gamma}
    // Compute the inverse of zv_{gamma}
    let fr_zv_at_gamma = domain_v.evaluate_vanishing_polynomial(gamma);
    let fr_inv_zv_at_gamma = fr_zv_at_gamma
        .inverse()
        .ok_or(Error::FailedToInverseFieldElement)?;
    // Compute b_{gamma} = b_{0, gamma} * gamma + b_0
    let fr_b_at_gamma = proof.fr_b0_at_gamma * gamma + fr_b_at_zero;
    let mut fr_qb_at_gamma = proof.fr_f_at_gamma + beta + (delta * proof.fr_l_at_gamma);
    fr_qb_at_gamma = fr_qb_at_gamma * fr_b_at_gamma - P::ScalarField::one();
    fr_qb_at_gamma = fr_qb_at_gamma * fr_inv_zv_at_gamma;

    // Compute p_{gamma} = l_{gamma, v} + eta * l_{gamma} + eta^2 * q_{gamma, L} +
    // eta^3 * d_{gamma} + eta^4 * q_{gamma, D} + eta^5 * b_{0, gamma} + eta^6 *
    // f_{gamma} + eta^7 * q_{B, gamma}
    let eta_pow_list = (0..BATCH_SIZE)
        .map(|i| eta.pow([i as u64]))
        .collect::<Vec<P::ScalarField>>();
    let fr_p_at_gamma_terms: Vec<P::ScalarField> = [
        &proof.fr_l_at_gamma_div_v,
        &proof.fr_l_at_gamma,
        &proof.fr_ql_at_gamma,
        &proof.fr_d_at_gamma,
        &proof.fr_qd_at_gamma,
        &proof.fr_b0_at_gamma,
        &proof.fr_f_at_gamma,
        &fr_qb_at_gamma,
    ]
    .par_iter()
    .zip(eta_pow_list.par_iter())
    .map(|(fr, eta_pow_x)| {
        let term = fr.mul(eta_pow_x);

        term
    })
    .collect();
    let mut fr_p_at_gamma = P::ScalarField::zero();
    for term in fr_p_at_gamma_terms {
        fr_p_at_gamma = fr_p_at_gamma.add(&term);
    }

    let g1_affine_p_terms: Vec<P::G1> = [
        &proof.g1_affine_l_div_v,
        &proof.g1_affine_l,
        &proof.g1_affine_ql,
        &proof.g1_affine_d,
        &proof.g1_affine_qd,
        &proof.g1_affine_b0,
        &statement,
        &proof.g1_affine_qb,
    ]
    .par_iter()
    .zip(eta_pow_list.par_iter())
    .map(|(g1, eta_pow_x)| {
        let term = g1.mul(eta_pow_x);

        term
    })
    .collect();
    let mut g1_p = P::G1::zero();
    for term in g1_affine_p_terms {
        g1_p = g1_p.add(&term);
    }
    let g1_affine_p = g1_p.into_affine();

    let left_pairing = P::pairing(proof.g1_affine_hp, g2_affine_tau);
    let g1_gamma_mul_hp = proof.g1_affine_hp.mul(gamma).into_affine();
    let g1_neg_p_at_gamma = fr_to_curve_element::<P::G1>(-fr_p_at_gamma).into_affine();
    let right_pairing = P::pairing(
        g1_affine_p + g1_neg_p_at_gamma + g1_gamma_mul_hp,
        g2_affine_one,
    );

    if left_pairing != right_pairing {
        return Err(Error::Pairing3Failed);
    }

    Ok(())
}

fn fourth_pairing_check<P: Pairing>(
    proof: &Proof<P>,
    g2_affine_tau: P::G2Affine,
    g2_affine_one: P::G2Affine,
) -> Result<(), Error> {
    let g1_affine_neg_a0 = fr_to_curve_element::<P::G1>(-proof.fr_a_at_zero).into_affine();
    let left_pairing = P::pairing(proof.g1_affine_a + g1_affine_neg_a0, g2_affine_one);
    let right_pairing = P::pairing(proof.g1_affine_a0, g2_affine_tau);

    if left_pairing != right_pairing {
        return Err(Error::Pairing4Failed);
    }

    Ok(())
}

fn first_point_check<P: Pairing>(
    proof: &Proof<P>,
    gamma: P::ScalarField,
    num_witness_segments: usize,
    domain_v: &Radix2EvaluationDomain<P::ScalarField>,
    domain_w: &Radix2EvaluationDomain<P::ScalarField>,
) -> Result<(), Error> {
    let fr_gamma_pow_k_sub_one = gamma.pow([num_witness_segments as u64]) - P::ScalarField::one();
    let fr_neg_gamma_pow_k_sub_one = -fr_gamma_pow_k_sub_one;
    let fr_neg_zv_at_gamma = -domain_v.evaluate_vanishing_polynomial(gamma);

    let mut g1_l_at_gamma_div_v = fr_to_curve_element::<P::G1>(proof.fr_l_at_gamma_div_v);
    let mut g1_l_at_gamma = fr_to_curve_element::<P::G1>(proof.fr_l_at_gamma);
    let mut g1_ql_at_gamma = fr_to_curve_element::<P::G1>(proof.fr_ql_at_gamma);

    g1_l_at_gamma_div_v.mul_assign(fr_neg_gamma_pow_k_sub_one * domain_w.group_gen);
    g1_l_at_gamma.mul_assign(fr_gamma_pow_k_sub_one);
    g1_ql_at_gamma.mul_assign(fr_neg_zv_at_gamma);
    let mut g1_check1 = g1_l_at_gamma_div_v.clone();
    g1_check1.add_assign(g1_l_at_gamma);
    g1_check1.add_assign(g1_ql_at_gamma);

    if g1_check1 != P::G1::zero() {
        return Err(Error::PointCheck1Failed);
    }

    Ok(())
}

fn second_point_check<P: Pairing>(
    proof: &Proof<P>,
    gamma: P::ScalarField,
    domain_k: &Radix2EvaluationDomain<P::ScalarField>,
) -> Result<(), Error> {
    let mut g1_l_at_gamma = fr_to_curve_element::<P::G1>(proof.fr_l_at_gamma);
    let fr_zk_at_gamma = domain_k.evaluate_vanishing_polynomial(gamma);
    let g1_d_at_gamma = fr_to_curve_element::<P::G1>(proof.fr_d_at_gamma);

    g1_l_at_gamma.add_assign(g1_d_at_gamma.neg());
    let mut g1_check2 = g1_l_at_gamma.clone();
    let mut g1_qd_at_gamma = fr_to_curve_element::<P::G1>(proof.fr_qd_at_gamma);
    g1_qd_at_gamma.mul_assign(-fr_zk_at_gamma);
    g1_check2.add_assign(g1_qd_at_gamma);

    if g1_check2 != P::G1::zero() {
        return Err(Error::PointCheck2Failed);
    }

    Ok(())
}

fn fr_to_curve_element<C: CurveGroup>(fr: C::ScalarField) -> C {
    let mut g1_gen = C::generator();
    g1_gen.mul_assign(fr);

    g1_gen
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_std::rand::RngCore;
    use ark_std::{test_rng, UniformRand};

    use crate::prover::prove;
    use crate::table::{rand_segments, Table};
    use crate::witness::Witness;

    use super::*;

    type Fr = <Bn254 as Pairing>::ScalarField;
    type G1Affine = <Bn254 as Pairing>::G1Affine;

    #[test]
    fn test_successful_verify() {
        let mut rng = test_rng();

        let inputs = [(4, 8, 4), (8, 4, 4), (16, 8, 4)];

        for (num_table_segments, num_witness_segments, segment_size) in inputs.into_iter() {
            let pp = PublicParameters::builder()
                .num_table_segments(num_table_segments)
                .num_witness_segments(num_witness_segments)
                .segment_size(segment_size)
                .build(&mut rng)
                .expect("Failed to setup public parameters");
            let segments = rand_segments::generate(&pp);

            let t = Table::<Bn254>::new(&pp, segments).expect("Failed to create table");
            let tpp = t.preprocess(&pp).unwrap();

            let queried_segment_indices: Vec<usize> = (0..pp.num_witness_segments)
                .map(|_| rng.next_u32() as usize % pp.num_table_segments)
                .collect();

            let witness =
                Witness::new(&pp, &tpp.adjusted_table_values, &queried_segment_indices).unwrap();

            let statement = witness.generate_statement(&pp.g1_affine_srs);

            let rng = &mut test_rng();

            let proof = prove::<Bn254, _>(&pp, &tpp, &witness, rng).expect("Failed to prove");

            assert!(verify::<Bn254, _>(&pp, &tpp, statement, &proof, rng).is_ok());
        }
    }

    #[test]
    fn test_failed_verify() {
        let mut rng = test_rng();

        let inputs = [(4, 8, 4), (8, 4, 4), (16, 8, 4)];

        for (num_table_segments, num_witness_segments, segment_size) in inputs.into_iter() {
            let pp = PublicParameters::builder()
                .num_table_segments(num_table_segments)
                .num_witness_segments(num_witness_segments)
                .segment_size(segment_size)
                .build(&mut rng)
                .expect("Failed to setup public parameters");
            let segments = rand_segments::generate(&pp);

            let t = Table::<Bn254>::new(&pp, segments.clone()).expect("Failed to create table");
            let tpp = t.preprocess(&pp).unwrap();

            let queried_segment_indices: Vec<usize> = (0..pp.num_witness_segments)
                .map(|_| rng.next_u32() as usize % pp.num_table_segments)
                .collect();

            let witness =
                Witness::new(&pp, &tpp.adjusted_table_values, &queried_segment_indices).unwrap();

            let statement = witness.generate_statement(&pp.g1_affine_srs);

            let rng = &mut test_rng();

            // Wrong table
            let new_segments = segments
                .into_iter()
                .map(|segment| {
                    segment
                        .iter()
                        .map(|&s| s + Fr::rand(rng))
                        .collect::<Vec<Fr>>()
                })
                .collect();
            let new_t = Table::new(&pp, new_segments).expect("Failed to create table");
            let new_tpp = new_t.preprocess(&pp).unwrap();

            let proof = prove(&pp, &new_tpp, &witness, rng).expect("Failed to prove");

            assert!(!verify(&pp, &tpp, statement, &proof, rng).is_ok());

            // Wrong witness from wrong table
            let new_queried_segment_indices: Vec<usize> = (0..pp.num_witness_segments)
                .map(|_| rng.next_u32() as usize % pp.num_table_segments)
                .collect();
            let new_witness = Witness::new(
                &pp,
                &new_tpp.adjusted_table_values,
                &new_queried_segment_indices,
            )
            .unwrap();

            let proof = prove(&pp, &tpp, &new_witness, rng).expect("Failed to prove");

            assert!(!verify(&pp, &tpp, statement, &proof, rng).is_ok());

            // Wrong witness from wrong indices
            let new_queried_segment_indices: Vec<usize> = (0..pp.num_witness_segments)
                .map(|_| rng.next_u32() as usize % pp.num_table_segments)
                .collect();
            let new_witness = Witness {
                num_segments: pp.num_witness_segments,
                segment_size: pp.segment_size,
                segment_indices: new_queried_segment_indices,
                poly: witness.poly.clone(),
                evaluations: witness.evaluations.clone(),
            };

            let proof = prove(&pp, &tpp, &new_witness, rng).expect("Failed to prove");

            assert!(!verify(&pp, &tpp, statement, &proof, rng).is_ok());

            // Wrong statement
            let new_statement = G1Affine::generator().mul(Fr::rand(rng)).into_affine();
            let proof = prove(&pp, &tpp, &witness, rng).expect("Failed to prove");

            assert!(!verify(&pp, &tpp, new_statement, &proof, rng).is_ok());
        }
    }
}
