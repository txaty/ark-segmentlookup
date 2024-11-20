use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_segmentlookup::prover::prove;
use ark_segmentlookup::public_parameters::PublicParameters;
use ark_segmentlookup::table::Table;
use ark_segmentlookup::verifier::verify;
use ark_segmentlookup::witness::Witness;
use ark_std::{test_rng, UniformRand};

fn rand_inputs<P: Pairing>(
    num_table_segments: usize,
    num_witness_segments: usize,
    segment_size: usize,
    num_different_segment_chosen: usize,
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

    let queried_segment_indices: Vec<usize> = (0..num_witness_segments)
        .map(|i| i % num_different_segment_chosen)
        .collect();

    (segments, queried_segment_indices)
}

fn end_to_end(
    num_table_segments: usize,
    num_witness_segments: usize,
    segment_size: usize,
    num_different_segment_chosen: usize,
) {
    println!(
        "num table segments: {}, num witness segments: {}, segment size: {}",
        num_table_segments, num_witness_segments, segment_size
    );
    let (segments, queried_segment_indices) = rand_inputs::<Bn254>(
        num_table_segments,
        num_witness_segments,
        segment_size,
        num_different_segment_chosen,
    );
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

    let curr_time = std::time::Instant::now();
    let proof = prove(&pp, &tpp, &witness, statement, rng).expect("Failed to prove");
    println!("prove time: {:?} ms", curr_time.elapsed().as_millis());

    let curr_time = std::time::Instant::now();
    let res = verify(&pp, &tpp, statement, &proof, rng);
    println!("verify time: {:?} ms", curr_time.elapsed().as_millis());
    assert!(res.is_ok());
}
fn main() {
    const NUM_SEGMENT_POWERS: [usize; 13] = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 24];
    const SEGMENT_SIZE: usize = 64;

    const WITNESS_SIZE: usize = 1024;

    const NUM_DIFFERENT_SEGMENT_CHOSEN: usize = 4;

    for num_segment_power in NUM_SEGMENT_POWERS {
        println!("num_segment_power: {}", num_segment_power);
        let num_segments = 2_i32.pow(num_segment_power as u32);
        end_to_end(
            num_segments as usize,
            WITNESS_SIZE,
            SEGMENT_SIZE,
            NUM_DIFFERENT_SEGMENT_CHOSEN,
        );
    }
}
