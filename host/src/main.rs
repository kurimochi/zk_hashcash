mod nonce;

use clap::{Parser, ValueEnum};
use env_logger::Env;
use hashcash_lib::{HashAlgorithm, calc_hash, public_values::HashCashPublicValues};
use log::info;
use sp1_sdk::{HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin, include_elf};
use std::error::Error;

use crate::nonce::search_nonce;

#[derive(Debug, Clone, ValueEnum)]
enum InputType {
    Hex,
    String,
    File,
}

#[derive(Debug, Clone, ValueEnum)]
enum ProofType {
    Raw,
    Compressed,
    Groth16,
    Plonk,
}

#[derive(Debug, Clone, ValueEnum)]
enum HashAlgorithmCli {
    Sha256,
    Sha512,
    Keccak256,
    Keccak512,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg()]
    message: String,

    #[arg(default_value_t = 8u32)]
    difficulty: u32,

    #[arg(long, default_value = "string")]
    input_type: InputType,

    #[arg(long, conflicts_with = "search", value_name = "NONCE")]
    only_prove: Option<u128>,

    #[arg(
        long,
        conflicts_with = "only_prove",
        value_name = "STARTING POINT",
        default_value_t = 0u128
    )]
    search: u128,

    #[arg(short, long, num_args = 2, value_names = ["PROOF and VKEY and MESSAGE", "NONCE and HASH"])]
    output_path: Option<Vec<String>>,

    #[arg(long, default_value = "raw")]
    proof: ProofType,

    #[arg(long, default_value = "sha256")]
    hash: HashAlgorithmCli,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(Env::new().default_filter_or("info"));

    let args = Cli::parse();

    let message = match args.input_type {
        InputType::File => std::fs::read(args.message)?,
        InputType::Hex => hex::decode(args.message)?,
        InputType::String => args.message.into_bytes(),
    };

    let hash_algorithm = match args.hash {
        HashAlgorithmCli::Sha256 => HashAlgorithm::Sha256,
        HashAlgorithmCli::Sha512 => HashAlgorithm::Sha512,
        HashAlgorithmCli::Keccak256 => HashAlgorithm::Keccak256,
        HashAlgorithmCli::Keccak512 => HashAlgorithm::Keccak512,
    };

    if message.len() < 2048 {
        info!("Message: 0x{}", hex::encode(&message));
    }
    info!("Ready");

    // nonce
    let nonce = if args.only_prove.is_some() {
        args.only_prove.unwrap()
    } else {
        search_nonce(&message, args.difficulty, Some(args.search), hash_algorithm)
    };
    info!("Nonce: {}", nonce);

    // zkVM phase
    info!("Proving on zkVM...");

    const ELF: sp1_sdk::Elf = include_elf!("hashcash-guest");

    let mut stdin = SP1Stdin::new();
    stdin.write(&message);
    stdin.write(&nonce);
    stdin.write(&args.difficulty);
    stdin.write(&hash_algorithm);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await?;

    let mut prover = client.prove(&pk, stdin);
    prover = match args.proof {
        ProofType::Compressed => prover.compressed(),
        ProofType::Groth16 => prover.groth16(),
        ProofType::Plonk => prover.plonk(),
        _ => prover,
    };
    info!("Proof type: {:?}", args.proof);
    let mut proof = prover.await?;

    let vk = pk.verifying_key();
    info!("Verifying...");
    client.verify(&proof, vk, None)?;

    let public = proof.public_values.read::<HashCashPublicValues>();
    assert!(public.is_valid, "The nonce is invalid");
    assert_eq!(public.hash_algorithm, hash_algorithm, "Hash algorithm mismatch");

    info!("Verified successfully!");

    // export
    if args.output_path.is_some() {
        let paths = args.output_path.unwrap();
        let public_path = &paths[0];
        let private_path = &paths[1];

        let public_json = serde_json::json!({
            "public": public,
            "vkey": vk.bytes32(),
            "proof": proof.proof
        });

        let private_json = serde_json::json!({
            "nonce": nonce,
            "hash": hex::encode(calc_hash(&message, nonce, hash_algorithm)),
        });

        std::fs::write(public_path, public_json.to_string())?;
        info!(
            "Proof, vkey, and public values have been saved to {}",
            public_path
        );
        std::fs::write(private_path, private_json.to_string())?;
        info!("Nonce and hash have been saved to {}", private_path);
    }

    Ok(())
}
