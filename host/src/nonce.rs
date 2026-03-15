use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use hashcash_lib::{check_hash, HashAlgorithm};
use log::info;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Keccak256, Keccak512};

// pub fn search_nonce(message: &[u8], difficulty: u32, starting_point: Option<u128>) -> u128 {
//     let mut nonce_count: u128 = starting_point.unwrap_or(0);

//     let mut mid = Sha256::new();
//     mid.update(message);

//     loop {
//         if nonce_count % 1_000_000 == 0 {
//             info!("Trying nonce {}", nonce_count);
//         }

//         let mut hasher = mid.clone();
//         hasher.update(&nonce_count.to_be_bytes());
//         let hash = hasher.finalize();

//         match check_hash(&hash, difficulty) {
//             Ok(hash) => {
//                 info!(
//                     "The hash {} was successfully computed using nonce {}!",
//                     hex::encode(hash),
//                     nonce_count
//                 );
//                 break;
//             }
//             Err(_) => {
//                 nonce_count += 1;
//             }
//         }
//     }
//     nonce_count
// }

pub fn search_nonce(
    message: &[u8],
    difficulty: u32,
    starting_point: Option<u128>,
    algorithm: HashAlgorithm,
) -> u128 {
    match algorithm {
        HashAlgorithm::Sha256 => {
            search_nonce_with_hasher::<Sha256>(message, difficulty, starting_point)
        }
        HashAlgorithm::Sha512 => {
            search_nonce_with_hasher::<Sha512>(message, difficulty, starting_point)
        }
        HashAlgorithm::Keccak256 => {
            search_nonce_with_hasher::<Keccak256>(message, difficulty, starting_point)
        }
        HashAlgorithm::Keccak512 => {
            search_nonce_with_hasher::<Keccak512>(message, difficulty, starting_point)
        }
    }
}

fn search_nonce_with_hasher<H: Digest + Clone + Send + 'static>(
    message: &[u8],
    difficulty: u32,
    starting_point: Option<u128>,
) -> u128 {
    let start: u128 = starting_point.unwrap_or(0);

    let mut mid = H::new();
    mid.update(message);

    let threads = num_cpus::get();
    let found = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();

    for id in 0..threads {
        let tx_clone = tx.clone();
        let mid_clone = mid.clone();
        let found_clone = found.clone();
        thread::spawn(move || {
            let mut nonce = start + id as u128;
            let step = threads as u128;
            while !found_clone.load(Ordering::Relaxed) {
                if nonce % 100_000_000 == 0 {
                    info!("Trying nonce {}", nonce);
                }
                let mut hasher = mid_clone.clone();
                hasher.update(nonce.to_be_bytes());
                let hash = hasher.finalize();
                if check_hash(&hash, difficulty) {
                    if !found_clone.swap(true, Ordering::Relaxed) {
                        info!(
                            "The hash {} was successfully computed using nonce {}!",
                            hex::encode(hash),
                            nonce,
                        );
                        let _ = tx_clone.send(nonce);
                    }
                    break;
                }
                nonce = nonce.wrapping_add(step);
            }
        });
    }

    rx.recv().unwrap()
}
