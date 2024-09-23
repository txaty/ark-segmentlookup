use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_segmentlookup::prover::prove;
use ark_segmentlookup::public_parameters::PublicParameters;
use ark_segmentlookup::table::Table;
use ark_segmentlookup::verifier::verify;
use ark_segmentlookup::witness::Witness;
use ark_std::rand::RngCore;
use ark_std::{test_rng, UniformRand};

mod parameters;

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

fn end_to_end(n: usize, k: usize, s: usize) {
    println!("n: {}, k: {}, s: {}", n, k, s);
    let segments = rand_inputs::<Bn254>(n, s);
    let mut rng = &mut test_rng();
    let curr_time = std::time::Instant::now();
    let pp = PublicParameters::builder()
        .num_table_segments(n)
        .num_witness_segments(k)
        .segment_size(s)
        .build(&mut rng)
        .expect("Failed to setup public parameters");
    let table = Table::<Bn254>::new(&pp, segments).expect("Failed to create table");
    let tpp = table.preprocess(&pp).expect("Failed to preprocess table");
    println!("setup time: {:?} ms", curr_time.elapsed().as_millis());

    for i in 0..=10 {
        let num_different_segments = 1 << i;
        println!("No. Different Segments: {}", num_different_segments);
        let mut queried_segment_indices = Vec::with_capacity(k);
        (0..num_different_segments).for_each(|i| {
            let num_indices = k / num_different_segments;
            for _ in 0..num_indices {
                queried_segment_indices.push(i);
            }
        });

        let witness = Witness::new(&pp, &table, &queried_segment_indices).unwrap();

        let curr_time = std::time::Instant::now();
        let proof = prove(&pp, &table, &tpp, &witness, rng).expect("Failed to prove");
        println!("prove time: {:?} ms", curr_time.elapsed().as_millis());

        let statement = witness.generate_statement(&pp.g1_affine_srs);

        let curr_time = std::time::Instant::now();
        let res = verify(&pp, &tpp, statement, &proof, rng);
        println!("verify time: {:?} ms", curr_time.elapsed().as_millis());
        assert!(res.is_ok());
    }
}
fn main() {
    // for n in N_VEC {
    //     let k = K_MID;
    //     let s = S_MID;
    //     end_to_end(n, k, s);
    // }
    //
    // for s in S_VEC {
    //     let n = N_MID;
    //     let k = K_MID;
    //     end_to_end(n, k, s);
    // }

    // for k in K_VEC {
    //     let n = 1024;
    //     let s = 64;
    //     end_to_end(n, k, s);
    // }
    end_to_end(1024, 1024, 64);
}
