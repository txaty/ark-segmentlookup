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
    segment_size: usize,
) -> Vec<Vec<P::ScalarField>> {
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

    segments
}

const ITERATIONS: usize = 5;

fn end_to_end(num_table_segments: usize, num_witness_segments: usize, segment_size: usize) {
    println!(
        "num table seg: {}, num witness seg: {}, seg size: {}",
        num_table_segments, num_witness_segments, segment_size
    );
    let segments = rand_inputs::<Bn254>(num_table_segments, segment_size);
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

    // Select different segments to compose the witness
    // Number of different segments to select: 2^i, i = 0, 1, ..., 10
    for i in 0..=10 {
        let num_different_segments = 1 << i;
        println!("No. Different Segments: {}", num_different_segments);
        let mut queried_segment_indices = Vec::with_capacity(num_witness_segments);
        (0..num_different_segments).for_each(|i| {
            let num_indices = num_witness_segments / num_different_segments;
            for _ in 0..num_indices {
                queried_segment_indices.push(i);
            }
        });

        for iter in 0..ITERATIONS {
            println!("ITER: {}", iter);
            let witness =
                Witness::new(&pp, &tpp.adjusted_table_values, &queried_segment_indices).unwrap();
            let statement = witness.generate_statement(&pp.g1_affine_srs);

            let curr_time = std::time::Instant::now();
            let proof = prove(&pp, &tpp, &witness, statement, rng).expect("Failed to prove");
            println!("prove time: {:?} ms", curr_time.elapsed().as_millis());

            let curr_time = std::time::Instant::now();
            let res = verify(&pp, &tpp, statement, &proof, rng);
            println!("verify time: {:?} ms", curr_time.elapsed().as_millis());
            assert!(res.is_ok());
        }
    }
}
fn main() {
    const NUM_TABLE_SEGMENTS: usize = 1024;
    const NUM_WITNESS_SEGMENTS: usize = 1024;
    const SEGMENT_SIZE: usize = 64;

    end_to_end(NUM_TABLE_SEGMENTS, NUM_WITNESS_SEGMENTS, SEGMENT_SIZE);
}
