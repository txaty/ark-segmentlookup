use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_segmentlookup::prover::prove;
use ark_segmentlookup::public_parameters::PublicParameters;
use ark_segmentlookup::table::Table;
use ark_segmentlookup::verifier::verify;
use ark_segmentlookup::witness::Witness;
use ark_std::rand::RngCore;
use ark_std::{test_rng, UniformRand};
use rand::seq::SliceRandom;

const UNIQUE_SEGMENTS: usize = 4;

fn rand_inputs<P: Pairing>(
    num_table_segments: usize,
    num_witness_segments: usize,
    segment_size: usize,
) -> (Vec<Vec<P::ScalarField>>, Vec<usize>) {
    let mut rng = test_rng();

    let segments = {
        let mut segments = Vec::with_capacity(num_table_segments);
        for _ in 0..num_table_segments {
            let mut segment = Vec::with_capacity(segment_size);
            for _ in 0..segment_size {
                segment.push(P::ScalarField::rand(&mut rng));
            }
            segments.push(segment);
        }

        segments
    };

    // Select exactly 4 unique segment indices
    assert!(
        num_table_segments >= UNIQUE_SEGMENTS,
        "num_table_segments must be at least 4 to select 4 unique segment indices"
    );
    let mut unique_indices = Vec::with_capacity(UNIQUE_SEGMENTS);
    while unique_indices.len() < UNIQUE_SEGMENTS {
        let idx = rng.next_u32() as usize % num_table_segments;
        if !unique_indices.contains(&idx) {
            unique_indices.push(idx);
        }
    }

    // Duplicate these 4 indices to reach the witness size of 1024
    let duplicates_per_index = num_witness_segments / unique_indices.len();
    let mut duplicated_indices = Vec::with_capacity(duplicates_per_index * unique_indices.len());

    for &idx in &unique_indices {
        duplicated_indices.extend(std::iter::repeat(idx).take(duplicates_per_index));
    }

    // If there's a remainder, add additional indices
    let remainder = num_witness_segments % unique_indices.len();
    if remainder > 0 {
        duplicated_indices.extend(unique_indices.iter().take(remainder));
    }

    // Shuffle the duplicated indices to randomize their order in the witness
    duplicated_indices.shuffle(&mut rng);

    (segments, duplicated_indices)
}

const ITERATIONS: usize = 5;

fn end_to_end(num_table_segments: usize, num_witness_segments: usize, segment_size: usize) {
    println!(
        "num table seg: {}, num witness seg: {}, seg size: {}",
        num_table_segments, num_witness_segments, segment_size
    );
    let (segments, queried_segment_indices) =
        rand_inputs::<Bn254>(num_table_segments, num_witness_segments, segment_size);
    let mut rng = &mut test_rng();
    let curr_time = std::time::Instant::now();
    let pp = PublicParameters::builder()
        .num_table_segments(num_table_segments)
        .num_witness_segments(num_witness_segments)
        .segment_size(segment_size)
        .build(&mut rng)
        .expect("Failed to setup public parameters");
    let table = Table::<Bn254>::new(&pp, segments).expect("Failed to create table");
    let tpp = table.preprocess(&pp).expect("Failed to preprocess table");
    println!("setup time: {:?} ms", curr_time.elapsed().as_millis());

    let witness = Witness::new(&pp, &tpp.adjusted_table_values, &queried_segment_indices).unwrap();
    let statement = witness.generate_statement(&pp.g1_affine_srs);

    for iter in 0..ITERATIONS {
        println!("iter: {}", iter);
        let curr_time = std::time::Instant::now();
        let proof = prove(&pp, &tpp, &witness, statement, rng).expect("Failed to prove");
        println!("prove time: {:?} ms", curr_time.elapsed().as_millis());

        let curr_time = std::time::Instant::now();
        let res = verify(&pp, &tpp, statement, &proof, rng);
        println!("verify time: {:?} ms", curr_time.elapsed().as_millis());
        assert!(res.is_ok());
    }
}
fn main() {
    const NUM_SEGMENT_POWERS: [usize; 23] = [
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    const SEGMENT_SIZE: usize = 64;

    const WITNESS_SIZE: usize = 1024;

    for num_segment_power in NUM_SEGMENT_POWERS {
        println!("num_segment_power: {}", num_segment_power);
        let num_segments = 2_i32.pow(num_segment_power as u32);
        end_to_end(num_segments as usize, WITNESS_SIZE, SEGMENT_SIZE);
    }
}
