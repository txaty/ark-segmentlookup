use std::collections::BTreeMap;
use std::ops::{Add, Div, Mul, Sub};

use crate::domain::roots_of_unity;
use crate::error::Error;
use crate::kzg::Kzg;
use crate::multi_unity::{multi_unity_prove, MultiUnityProof};
use crate::public_parameters::PublicParameters;
use crate::table::{Table, TablePreprocessedParameters};
use crate::transcript::Transcript;
use crate::witness::Witness;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain, UVPolynomial};
use ark_std::rand::prelude::StdRng;
use ark_std::{One, Zero};

pub struct Proof<E: PairingEngine> {
    // Round 1 message
    pub(crate) g1_m: E::G1Affine,       // [M(tau)]_1
    pub(crate) g1_m_div_w: E::G1Affine, // [M(tau / w)]_1
    pub(crate) g1_q_m: E::G1Affine,     // [Q_M(tau)]_1
    g1_l: E::G1Affine,                  // [L(tau)]_1
    g1_l_mul_v: E::G1Affine,            // [L(tau * v)]_1
    g1_q_l: E::G1Affine,                // [Q_L(tau)]_1
    pub(crate) g1_d: E::G1Affine,       // [D(tau)]_1
    g1_q_d: E::G1Affine,                // [Q_D(tau)]_1
    pub(crate) g1_a: E::G1Affine,       // [A(tau)]_1
    pub(crate) g1_q_a: E::G1Affine,     // [Q_A(tau)]_1
    g1_b: E::G1Affine,                  // [B(tau)]_1
    g1_q_b: E::G1Affine,                // [Q_B(tau)]_1

    pub(crate) multi_unity_proof: MultiUnityProof<E>, // Proof of the Caulk Sub-protocol
}

pub fn prove<E: PairingEngine>(
    pp: &PublicParameters<E>,
    table: &Table<E>,
    tpp: &TablePreprocessedParameters<E>,
    witness: &Witness<E>,
    // statement: E::G1Affine,
    rng: &mut StdRng,
) -> Result<Proof<E>, Error> {
    let mut transcript = Transcript::<E::Fr>::new();

    // Round 1-1: Compute the multiplicity polynomial M of degree (ns - 1),
    // and send [M(tau)]_1 and [M(tau / w)]_1 to the verifier.
    // Round 1-2: Compute and send [Q_M(tau)]_1 using the SRS and Lemma 4.
    let segment_multiplicities =
        segment_multiplicities(&witness.queried_segment_indices, pp.num_segments)?;
    let MultiplicityPolynomialsAndQuotient {
        g1_m,
        g1_m_div_w,
        g1_q_m,
    } = multiplicity_polynomials_and_quotient_g1::<E>(
        &segment_multiplicities,
        &pp.g1_l_w_list,
        &pp.g1_l_w_div_w_list,
        &pp.g1_q3_list,
        &pp.g1_q4_list,
        pp.segment_size,
    );

    // Round 1-3: Compute the indexing polynomial L(X) of degree (ks - 1),
    // which maps the segment element indices from the witness to the table.
    // Round 1-5: Compute another indexing polynomial D(X) of degree (k - 1).
    // For each i \in [0, k - 1], D(v^{is}) = L(v^{is}) = w^{js}
    // Round 1-4: Compute the quotient polynomial Q_L(X) s.t.
    // (X^k - 1)*(L(Xv) - w*L(X)) = Z_V(X)*Q_L(X),
    // and send [Q_L(tau)]_1 to the verifier.
    // Inverse FFT costs O(ks log(ks)) operations
    // Round 1-6: Compute Q_D s.t. L(X) - D(X) = Z_K(X)*Q_D(X),
    // and send [Q_D(tau)]_1 to the verifier.
    let IndexPolynomialsAndQuotients {
        g1_l,
        g1_l_mul_v,
        g1_d,
        poly_d,
        g1_q_l,
        g1_q_d,
    } = index_polynomials_and_quotients_g1::<E>(
        &pp.domain_w,
        &pp.domain_k,
        &pp.domain_v,
        &pp.g1_l_v_list,
        &pp.g1_l_v_mul_v_list,
        &pp.g1_srs,
        &witness.queried_segment_indices,
        pp.witness_size,
        pp.segment_size,
        pp.num_queries,
    );

    // Round 2 is performed by the verifier

    // Round 3 - Round 8:
    // Using the instantiation of Lemma 5,
    // the prover and verifier engage in a protocol that polynomial L is well-formed.
    let multi_unity_proof = match multi_unity_prove(pp, &mut transcript, &poly_d, &g1_d, rng) {
        Ok(proof) => proof,
        Err(e) => return Err(e),
    };

    // Round 9: The verifier sends random scalar fields beta, delta to the prover.
    // Use Fiat-Shamir heuristic to make the protocol non-interactive.
    let beta = transcript.get_and_append_challenge(b"beta");
    let delta = transcript.get_and_append_challenge(b"delta");

    // Round 10-1: The prover computes A(X) of degree ns-1 in sparse form,
    // and sends [A(tau)]_1 to the verifier.
    // Round 10-2: The prover computes [Q_A(tau)]_1 using the SRS and Lemma 4.
    let mut sparse_poly_eval_list_a = BTreeMap::<usize, E::Fr>::default();
    let mut g1_a = E::G1Projective::zero();
    let mut g1_q_a = E::G1Projective::zero();
    let roots_of_unity_w = roots_of_unity::<E>(&pp.domain_w);

    for (&segment_index, &multiplicity) in segment_multiplicities.iter() {
        let segment_element_indices =
            segment_index * pp.segment_size..(segment_index + 1) * pp.segment_size;
        for elem_index in segment_element_indices {
            let fr_a_i = (beta + table.values[elem_index] + delta * roots_of_unity_w[elem_index])
                .inverse()
                .ok_or(Error::FailedToInverseFieldElement)?
                *  E::Fr::from(multiplicity as u64);

            sparse_poly_eval_list_a.insert(elem_index, fr_a_i);
            g1_a = g1_a + pp.g1_l_w_list[elem_index].mul(fr_a_i);
            g1_q_a = g1_q_a + tpp.g1_q1_list[elem_index].mul(fr_a_i);
            g1_q_a = g1_q_a + pp.g1_q2_list[elem_index].mul(delta.mul(fr_a_i));
        }
    }

    // Round 10-3: The prover computes B(X) of degree ks-1,
    // and sends [B(tau)]_1 to the verifier.
    // Round 10-4: The prover computes [Q_B(tau)]_1 using the SRS and Lemma 4.
    let roots_of_unity_v = roots_of_unity::<E>(&pp.domain_v);
    let poly_eval_list_b: Result<Vec<E::Fr>, Error> = (0..pp.witness_size)
        .map(|i| {
            (beta + witness.poly_eval_list_f[i] + delta * roots_of_unity_v[i])
                .inverse()
                .ok_or(Error::FailedToInverseFieldElement)
        })
        .collect();
    let poly_eval_list_b = poly_eval_list_b?;

    // Round 10-5: The prover computes B_0(X) = (B(X) - B(0)) / X, A_0(X) = (A(X) - A(0)) / X,
    // and sends [A_0(tau)]_1 and [B_0(tau)]_1 to the verifier.
    let poly_coeff_list_b = pp.domain_v.ifft(&poly_eval_list_b);
    let poly_b = DensePolynomial::from_coefficients_vec(poly_coeff_list_b);
    let g1_b = Kzg::<E>::commit_g1(&pp.g1_srs, &poly_b).into_affine();
    let poly_b_0 = DensePolynomial::from_coefficients_slice(&poly_b.coeffs[1..]);
    let g1_b_0 = Kzg::<E>::commit_g1(&pp.g1_srs, &poly_b_0).into_affine();

    Ok(Proof {
        g1_m,
        g1_m_div_w,
        g1_q_m,
        g1_l,
        g1_l_mul_v,
        g1_q_l,
        g1_d,
        g1_q_d,
        g1_a: g1_a.into_affine(),
        g1_q_a: g1_q_a.into_affine(),
        g1_b,
        g1_q_b: E::G1Affine::default(),
        multi_unity_proof,
    })
}

fn segment_multiplicities(
    queried_segment_indices: &[usize],
    num_segments: usize,
) -> Result<BTreeMap<usize, usize>, Error> {
    let mut multiplicities = BTreeMap::<usize, usize>::default();
    for &i in queried_segment_indices.iter() {
        if i > num_segments {
            return Err(Error::InvalidSegmentIndex(i));
        }

        let segment_index_multiplicity = multiplicities.entry(i).or_insert(0);
        *segment_index_multiplicity += 1;
    }

    Ok(multiplicities)
}

// Multiplicity polynomials and the quotient,
// containing [M(tau)]_1, [M(tau / w)]_1, and [Q_M(tau)]_1.
struct MultiplicityPolynomialsAndQuotient<E: PairingEngine> {
    g1_m: E::G1Affine,
    g1_m_div_w: E::G1Affine,
    g1_q_m: E::G1Affine,
}

// Compute [M(tau)]_1, [M(tau / w)]_1, and [Q_M(tau)]_1
fn multiplicity_polynomials_and_quotient_g1<E: PairingEngine>(
    segment_multiplicities: &BTreeMap<usize, usize>,
    g1_l_w_list: &[E::G1Affine],
    g1_l_w_div_w_list: &[E::G1Affine],
    g1_q3_list: &[E::G1Affine],
    g1_q4_list: &[E::G1Affine],
    segment_size: usize,
) -> MultiplicityPolynomialsAndQuotient<E> {
    let mut g1_proj_m = E::G1Projective::zero(); // [M(tau)]_1
    let mut g1_proj_m_div_w = E::G1Projective::zero(); // [M(tau / w)]_1
    let mut g1_proj_q_m = E::G1Projective::zero(); // [Q_M(tau)]_1
    for (&i, &m) in segment_multiplicities.iter() {
        let segment_element_indices = i * segment_size..(i + 1) * segment_size;
        let fr_mul = E::Fr::from(m as u64);
        for elem_index in segment_element_indices {
            // Linear combination of [L^W_i(tau)]_1
            g1_proj_m = g1_l_w_list[elem_index].mul(fr_mul).add(g1_proj_m);
            // Linear combination of [L^W_i(tau / w)]_1
            g1_proj_m_div_w = g1_l_w_div_w_list[elem_index]
                .mul(fr_mul)
                .add(g1_proj_m_div_w);
            // Linear combination of q_{i, 3}
            g1_proj_q_m = g1_q3_list[elem_index].mul(fr_mul).add(g1_proj_q_m);
            // Linear combination of q_{i, 4}
            g1_proj_q_m = g1_q4_list[elem_index]
                .mul(-fr_mul) // negate the coefficient
                .add(g1_proj_q_m);
        }
    }

    MultiplicityPolynomialsAndQuotient {
        g1_m: g1_proj_m.into_affine(),
        g1_m_div_w: g1_proj_m_div_w.into_affine(),
        g1_q_m: g1_proj_q_m.into_affine(),
    }
}

// Index polynomials and the quotients,
// containing [L(tau)]_1, [L(tau * v)]_1, [D(tau)]_1, [Q_L(tau)]_1, and [Q_D(tau)]_1.
struct IndexPolynomialsAndQuotients<E: PairingEngine> {
    g1_l: E::G1Affine,
    g1_l_mul_v: E::G1Affine,
    g1_d: E::G1Affine,
    poly_d: DensePolynomial<E::Fr>,
    g1_q_l: E::G1Affine,
    g1_q_d: E::G1Affine,
}

// Compute the commitments of [L(tau)]_1, [L(tau*v)]_1, [D(tau)]_1, [Q_L(tau)]_1, and [Q_D(tau)]_1
fn index_polynomials_and_quotients_g1<E: PairingEngine>(
    domain_w: &Radix2EvaluationDomain<E::Fr>,
    domain_k: &Radix2EvaluationDomain<E::Fr>,
    domain_v: &Radix2EvaluationDomain<E::Fr>,
    g1_l_v_list: &[E::G1Affine],
    g1_l_v_mul_v_list: &[E::G1Affine],
    g1_srs: &[E::G1Affine],
    queried_segment_indices: &[usize],
    witness_size: usize,
    segment_size: usize,
    num_queries: usize,
) -> IndexPolynomialsAndQuotients<E> {
    let mut poly_eval_list_l: Vec<E::Fr> = Vec::with_capacity(witness_size);
    let mut g1_proj_l = E::G1Projective::zero(); // [L(tau)]_1
    let mut g1_proj_l_mul_v = E::G1Projective::zero(); // [L(tau * v)]_1
    let roots_of_unity_w: Vec<E::Fr> = roots_of_unity::<E>(&domain_w);
    let mut witness_element_index: usize = 0;
    let mut poly_eval_list_d: Vec<E::Fr> = Vec::with_capacity(num_queries);
    for &seg_index in queried_segment_indices.iter() {
        let segment_element_indices = seg_index * segment_size..(seg_index + 1) * segment_size;
        for j in segment_element_indices {
            let root_of_unity_w = roots_of_unity_w[j];
            poly_eval_list_l.push(root_of_unity_w);
            // Linear combination of [L^V_i(tau)]_1
            g1_proj_l = g1_l_v_list[witness_element_index]
                .mul(root_of_unity_w)
                .add(g1_proj_l);
            // Linear combination of [L^V_i(tau * v)]_1
            g1_proj_l_mul_v = g1_l_v_mul_v_list[witness_element_index]
                .mul(root_of_unity_w)
                .add(g1_proj_l_mul_v);
            witness_element_index += 1;
        }

        let root_of_unity_w = roots_of_unity_w[seg_index * segment_size];
        poly_eval_list_d.push(root_of_unity_w);
    }

    let poly_coeff_list_d = domain_k.ifft(&poly_eval_list_d);
    let poly_d = DensePolynomial::from_coefficients_vec(poly_coeff_list_d);
    let g1_d = Kzg::<E>::commit_g1(g1_srs, &poly_d).into_affine();

    // Compute the quotient polynomial Q_L(X) s.t. (X^k - 1)*(L(Xv) - w*L(X)) = Z_V(X)*Q_L(X),
    // Inverse FFT costs O(ks log(ks)) operations
    let poly_coeff_list_l = domain_v.ifft(&poly_eval_list_l);
    // The coefficients of L(Xv). We can scale each L(X) polynomial coefficients by v^i
    let roots_of_unity_v: Vec<E::Fr> = roots_of_unity::<E>(&domain_v);
    let poly_coeff_list_l_mul_v: Vec<E::Fr> = poly_coeff_list_l
        .iter()
        .enumerate()
        .map(|(i, &c)| c * roots_of_unity_v[i])
        .collect();
    let poly_l_mul_v = DensePolynomial::from_coefficients_vec(poly_coeff_list_l_mul_v);
    // The coefficients of w*L(X).
    let generator_w = roots_of_unity_w[1];
    let poly_coeff_list_w_mul_l: Vec<E::Fr> =
        poly_coeff_list_l.iter().map(|&c| c * generator_w).collect();
    let poly_w_mul_l = DensePolynomial::from_coefficients_vec(poly_coeff_list_w_mul_l);
    // The coefficients of f(X) = X^k - 1
    let mut poly_coeff_list_x_pow_k_sub_one = vec![E::Fr::zero(); witness_size];
    poly_coeff_list_x_pow_k_sub_one[num_queries] = E::Fr::one();
    poly_coeff_list_x_pow_k_sub_one[0] = -E::Fr::one();
    let poly_x_pow_k_sub_one =
        DensePolynomial::from_coefficients_vec(poly_coeff_list_x_pow_k_sub_one);
    let vanishing_poly_v: DensePolynomial<E::Fr> = domain_v.vanishing_polynomial().into();
    let mut poly_q_l = poly_l_mul_v.sub(&poly_w_mul_l);
    poly_q_l = poly_q_l.div(&vanishing_poly_v);
    poly_q_l = poly_q_l.mul(&poly_x_pow_k_sub_one);
    let g1_q_l = Kzg::<E>::commit_g1(&g1_srs, &poly_q_l).into_affine();

    // Compute Q_D s.t. L(X) - D(X) = Z_K(X)*Q_D(X).
    let poly_l = DensePolynomial::from_coefficients_vec(poly_coeff_list_l);
    let mut poly_q_d = poly_l.sub(&poly_d);
    let vanishing_poly_k: DensePolynomial<E::Fr> = domain_k.vanishing_polynomial().into();
    poly_q_d = poly_q_d.div(&vanishing_poly_k);
    let g1_q_d = Kzg::<E>::commit_g1(&g1_srs, &poly_q_d).into_affine();

    IndexPolynomialsAndQuotients {
        g1_l: g1_proj_l.into_affine(),
        g1_l_mul_v: g1_proj_l_mul_v.into_affine(),
        g1_d,
        poly_d,
        g1_q_l,
        g1_q_d,
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use super::*;
    use crate::table::rand_segments;
    use ark_bn254::Bn254;
    use ark_std::rand::RngCore;
    use ark_std::{test_rng, UniformRand};

    type Fr = <Bn254 as PairingEngine>::Fr;
    type G1Affine = <Bn254 as PairingEngine>::G1Affine;
    type G2Affine = <Bn254 as PairingEngine>::G2Affine;

    #[test]
    fn test_mul_and_neg() {
        let mut rng = test_rng();
        let s1 = Fr::rand(&mut rng);
        let s2 = Fr::rand(&mut rng);
        let p1 = G1Affine::prime_subgroup_generator().mul(s1).into_affine();
        assert_eq!(p1.mul(s2).neg(), p1.mul(-s2));
    }

    #[test]
    fn test_domain_generator() {
        let size = 8;
        let domain = Radix2EvaluationDomain::<<Bn254 as PairingEngine>::Fr>::new(size).unwrap();
        let domain_elements: Vec<_> = domain.elements().collect();
        assert_eq!(domain_elements[1], domain.group_gen);
    }

    #[test]
    fn test_segment_multiplicities() {
        let queried_segment_indices = vec![0, 1, 2, 3, 0, 1, 2, 3];
        let num_segments = 4;
        let multiplicities =
            segment_multiplicities(&queried_segment_indices, num_segments).unwrap();
        assert_eq!(multiplicities.len(), 4);
        assert_eq!(multiplicities[&0], 2);
        assert_eq!(multiplicities[&1], 2);
        assert_eq!(multiplicities[&2], 2);
        assert_eq!(multiplicities[&3], 2);
    }

    #[test]
    fn test_com1_multiplicity_polynomials_and_quotient() {
        let mut rng = test_rng();
        let num_segments = 16;
        let num_queries = 8;
        let segment_size = 4;
        let pp =
            PublicParameters::<Bn254>::setup(&mut rng, num_segments, num_queries, segment_size)
                .unwrap();
        let queried_segment_indices = vec![0, 1, 2, 3, 0, 1, 2, 3];
        let multiplicities =
            segment_multiplicities(&queried_segment_indices, num_segments).unwrap();

        // Construct polynomial M(X) using Inverse FFT.
        let mut poly_eval_m_list = vec![Fr::zero(); pp.table_size];
        for (&i, &m) in multiplicities.iter() {
            let segment_element_indices = i * segment_size..(i + 1) * segment_size;
            let fr_multiplicity = Fr::from(m as u64);
            for j in segment_element_indices {
                poly_eval_m_list[j] = fr_multiplicity;
            }
        }
        let poly_coeff_list_m = pp.domain_w.ifft(&poly_eval_m_list);
        let poly_m = DensePolynomial::from_coefficients_vec(poly_coeff_list_m.clone());
        let g1_m_expected = Kzg::<Bn254>::commit_g1(&pp.g1_srs, &poly_m).into_affine();
        let inv_generator_w = pp.domain_w.group_gen_inv;
        let poly_coeff_list_m_div_w: Vec<Fr> = poly_coeff_list_m
            .iter()
            .enumerate()
            .map(|(i, &c)| c * inv_generator_w.pow(&[i as u64]))
            .collect();
        let poly_m_div_w = DensePolynomial::from_coefficients_vec(poly_coeff_list_m_div_w);
        let g1_m_div_w_expected = Kzg::<Bn254>::commit_g1(&pp.g1_srs, &poly_m_div_w).into_affine();

        let mut poly_coeff_list_x_pow_n_sub_one = vec![Fr::zero(); pp.table_size];
        poly_coeff_list_x_pow_n_sub_one[pp.num_segments] = Fr::one();
        poly_coeff_list_x_pow_n_sub_one[0] = -Fr::one();
        let poly_x_pow_n_sub_one =
            DensePolynomial::from_coefficients_vec(poly_coeff_list_x_pow_n_sub_one);
        let mut poly_q_m = poly_m.clone();
        poly_q_m = poly_q_m.sub(&poly_m_div_w);
        poly_q_m = poly_q_m.naive_mul(&poly_x_pow_n_sub_one);
        poly_q_m = poly_q_m.div(&pp.domain_w.vanishing_polynomial().into());
        let g1_q_m_expected = Kzg::<Bn254>::commit_g1(&pp.g1_srs, &poly_q_m).into_affine();

        let MultiplicityPolynomialsAndQuotient {
            g1_m: g1_m_got,
            g1_m_div_w: g1_m_div_w_got,
            g1_q_m: g1_q_m_got,
        } = multiplicity_polynomials_and_quotient_g1::<Bn254>(
            &multiplicities,
            &pp.g1_l_w_list,
            &pp.g1_l_w_div_w_list,
            &pp.g1_q3_list,
            &pp.g1_q4_list,
            segment_size,
        );

        assert_eq!(g1_m_expected, g1_m_got);
        assert_eq!(g1_m_div_w_expected, g1_m_div_w_got);
        assert_eq!(g1_q_m_expected, g1_q_m_got);
    }

    // TODO: add test cases with different parameters,
    // e.g., (8, 4, 4), (4, 8, 4).

    #[test]
    fn test_prove() {
        let mut rng = test_rng();
        let pp =
            PublicParameters::setup(&mut rng, 16, 8, 4).expect("Failed to setup public parameters");
        let segments = rand_segments::generate(&pp);
        let segment_slices: Vec<&[<Bn254 as PairingEngine>::Fr]> =
            segments.iter().map(|segment| segment.as_slice()).collect();
        let t = Table::<Bn254>::new(&pp, &segment_slices).expect("Failed to create table");

        let queried_segment_indices: Vec<usize> = (0..pp.num_queries)
            .map(|_| rng.next_u32() as usize % pp.num_segments)
            .collect();

        let witness = Witness::new(&pp, &t, &queried_segment_indices).unwrap();

        let tpp = t.preprocess(&pp).unwrap();

        let rng = &mut test_rng();

        prove::<Bn254>(&pp, &t, &tpp, &witness, rng).unwrap();
    }
}
