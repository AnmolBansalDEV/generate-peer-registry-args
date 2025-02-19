use dotenv::dotenv;
use libp2p::{identity::secp256k1 as libp2p_secp256k1, identity::Keypair, Multiaddr};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::RsaPrivateKey;
use std::env;
use url::Url;
use clap::Parser;
use rsa::pkcs1::EncodeRsaPublicKey;

fn validate_url(url: &str) -> bool {
    match Url::parse(url) {
        Ok(parsed_url) => parsed_url.scheme() == "http" || parsed_url.scheme() == "https",
        Err(_) => false,
    }
}

pub fn fetch_secp256k1_keypair() -> Keypair {
    let seed = env::var("RSA_SEED").expect("RSA_SEED must be set");
    let seed_bytes = hex::decode(seed.clone()).unwrap();
    let seed_bytes: [u8; 32] = seed_bytes.try_into().expect("SECP256K1_SEED must be 32 bytes");
    let mut rng = ChaCha8Rng::from_seed(seed_bytes);
    let secret_key = secp256k1::SecretKey::new(&mut rng);
    let libp2p_secret_key = libp2p_secp256k1::SecretKey::try_from_bytes(secret_key.secret_bytes())
        .expect("Failed to create libp2p secret key");
    let secp256k1_keypair = libp2p_secp256k1::Keypair::from(libp2p_secret_key);
    Keypair::from(secp256k1_keypair)
}

pub fn fetch_rsa_key() -> RsaPrivateKey {
    let seed = env::var("RSA_SEED").expect("RSA_SEED must be set");
    let seed_bytes = hex::decode(seed).unwrap();
    let seed_bytes: [u8; 32] = seed_bytes.try_into().expect("RSA_SEED must be 32 bytes");
    let rng = ChaCha8Rng::from_seed(seed_bytes);
    RsaPrivateKey::new(&mut rng.clone(), 2048).unwrap()
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long)]
    multiaddr: String,

    #[arg(long)]
    rpcaddr: String,
}

fn main() {
    dotenv().ok();
    let args = Args::parse();
    let rpcaddr = args.rpcaddr;
    let _parsed_rpcaddr = validate_url(rpcaddr.as_str());

    let multiaddr: Multiaddr = args.multiaddr.parse().expect("Multiaddr is invalid");

    let libp2p_keypair = fetch_secp256k1_keypair();
    let libp2p_pubkey = hex::encode(libp2p_keypair.public().encode_protobuf());

    let peer_id = libp2p_keypair.public().to_peer_id().to_string();

    let rsa_private_key = fetch_rsa_key();
    let rsa_pubkey = rsa_private_key
        .to_public_key()
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::CR)
        .unwrap();

    println!("Multiaddr: {}\n", multiaddr);
    println!("RPC Address: {}\n", rpcaddr);
    println!("Peer ID: {}\n", peer_id);
    println!("Libp2p Public Key: {}\n", libp2p_pubkey);
    println!("RSA Public Key: {:?}\n", rsa_pubkey);
}
