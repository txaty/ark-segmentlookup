mod domain;
mod error;
pub mod kzg;
mod lagrange_basis;
pub mod multi_unity;
pub mod prover;
pub mod public_parameters;
pub mod table;
mod toeplitz;
mod transcript;
pub mod verifier;
pub mod witness;

#[cfg(test)]
mod tests {
    use crate::prover::prove;
    use crate::public_parameters::PublicParameters;
    use crate::table::{rand_segments, Table, TablePreprocessedParameters};
    use crate::verifier::verify;
    use crate::witness::Witness;
    use ark_ec::pairing::Pairing;
    use ark_std::rand::RngCore;
    use ark_std::test_rng;

    fn prepare_common_inputs<P: Pairing>(
        num_table_segments: usize,
        num_witness_segments: usize,
        segment_size: usize,
    ) -> (
        PublicParameters<P>,
        Table<P>,
        Witness<P>,
        P::G1Affine,
        TablePreprocessedParameters<P>,
    ) {
        let mut rng = test_rng();
        let pp = PublicParameters::setup(
            &mut rng,
            num_table_segments,
            num_witness_segments,
            segment_size,
        )
        .unwrap();
        let segments = rand_segments::generate(&pp);

        let t = Table::<P>::new(&pp, segments).expect("Failed to create table");

        let queried_segment_indices: Vec<usize> = (0..pp.num_witness_segments)
            .map(|_| rng.next_u32() as usize % pp.num_table_segments)
            .collect();

        let witness = Witness::new(&pp, &t, &queried_segment_indices).unwrap();

        let statement = witness.generate_statement(&pp.g1_affine_srs);

        let tpp = t.preprocess(&pp).unwrap();

        (pp, t, witness, statement, tpp)
    }

    #[test]
    fn test_success_prove_and_verify() {
        let inputs = [
            // (2, 2, 1), // this doesn't work due to next_pow2() in fk library.
            (2, 2, 2),
            (2, 2, 4),
            (4, 1, 1),
            (4, 4, 1),
            (4, 4, 4),
            (4, 16, 4),
            (8, 1, 8),
            (8, 8, 1),
            (8, 8, 4),
            (8, 16, 4),
            (16, 1, 4),
            (16, 8, 4),
        ];
        for (num_table_segments, num_witness_segments, segment_size) in inputs.iter() {
            println!(
                "num_table_segments: {}, num_witness_segments: {}, segment_size: {}",
                num_table_segments, num_witness_segments, segment_size
            );
            let (pp, t, witness, statement, tpp) = prepare_common_inputs::<ark_bn254::Bn254>(
                *num_table_segments,
                *num_witness_segments,
                *segment_size,
            );

            let rng = &mut test_rng();

            let proof = prove(&pp, &t, &tpp, &witness, rng).unwrap();

            let result = verify(&pp, &tpp, statement, &proof, rng);
            assert!(result.is_ok(), "Failed to verify proof: {:?} num_table_segments: {}, num_witness_segments: {}, segment_size: {}", result, num_table_segments, num_witness_segments, segment_size);
        }
    }
}
