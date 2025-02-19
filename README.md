# generate-peer-registry-args

This project generates peer registry arguments for a given set of inputs.

## Getting Started

### Prerequisites

- Rust (latest stable version)

### Installation

Clone the repository:

```sh
git clone https://github.com/AnmolBansalDEV/generate-peer-registry-args.git
cd generate-peer-registry-args
```

### Usage

To run the program, use the following command:

```sh
cargo run
```

### Example

Here is an example of how to use the program:

```sh
cargo run -- --multiaddr <MULTIADDR> --rpcaddr <RPCADDR>
```
### Environment Variables

Create a `.env` file in the root directory of the project. You can use the `.env.example` file as a template:

```sh
cp .env.example .env
```

Edit the `.env` file to configure the necessary environment variables. Ensure that `SECP256K1_SEED` and `RSA_SEED` are set to 32 bytes random strings.