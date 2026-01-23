# Zero-Knowledge HashCash
This implementation is HashCash, but by proving the verification process of HashCash using SP1 zkVM, integrity can be maintained without disclosing the nonce.

## Requirements
* [Rust](https://rust-lang.org/tools/install/)
* [SP1 zkVM](https://docs.succinct.xyz/docs/sp1/getting-started/install)
* [Docker](https://docs.docker.com/get-started/get-docker/) (When using `Groth16` mode or `PLONK` mode)

## Usage
```
Usage: hashcash-host [OPTIONS] <MESSAGE> [DIFFICULTY]

Arguments:
  <MESSAGE>
  [DIFFICULTY]  [default: 8]

Options:
      --input-type <INPUT_TYPE>
          [default: string] [possible values: hex, string, file]
      --only-prove <NONCE>

      --search <STARTING POINT>
          [default: 0]
  -o, --output-path <PROOF and VKEY and MESSAGE> <NONCE and HASH>

      --proof <PROOF>
          [default: raw] [possible values: raw, compressed, groth16, plonk]
  -h, --help
          Print help
  -V, --version
          Print version
```
