use std::fs;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use tempris_collector::toolchain::keys::TOOLCHAIN_RELEASE_KEY_ID;
use tempris_collector::toolchain::manifest::{ToolchainEnvelope, ToolchainManifest};

#[derive(Parser)]
#[command(name = "operator_toolchain_signer")]
#[command(about = "Operator-only standalone toolchain signing and key management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new 32-byte Ed25519 release keypair
    GenerateKey {
        /// Output path for the private key file (must reside in protected operator storage outside Git)
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a canonical toolchain manifest JSON into a signed envelope
    Sign {
        /// Path to the 32-byte Ed25519 private key
        #[arg(long)]
        key: PathBuf,
        /// Path to the raw manifest JSON file
        #[arg(long)]
        manifest: PathBuf,
        /// Output path for the signed envelope JSON file
        #[arg(long)]
        out: PathBuf,
        /// Optional key identifier (defaults to compiled release key ID)
        #[arg(long, default_value = TOOLCHAIN_RELEASE_KEY_ID)]
        key_id: String,
    },
    /// Verify a signed envelope JSON
    Verify {
        /// Path to the signed envelope JSON file
        #[arg(long)]
        envelope: PathBuf,
        /// Optional public key hex string (defaults to compiled release public key)
        #[arg(long)]
        pubkey_hex: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey { out } => {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }

            let signing_key = SigningKey::generate(&mut OsRng);
            let secret_bytes = signing_key.to_bytes();
            let verifying_key = signing_key.verifying_key();
            let public_bytes = verifying_key.to_bytes();

            fs::write(&out, secret_bytes)?;

            let pub_path = out.with_extension("pub");
            fs::write(&pub_path, public_bytes)?;

            println!("Successfully generated Ed25519 keypair:");
            println!("  Private key: {}", out.display());
            println!("  Public key file: {}", pub_path.display());
            println!("  Public key hex: {}", hex::encode(public_bytes));
        }
        Commands::Sign {
            key,
            manifest,
            out,
            key_id,
        } => {
            let key_bytes = fs::read(&key)?;
            if key_bytes.len() != 32 {
                return Err(format!("Private key must be 32 bytes, got {}", key_bytes.len()).into());
            }

            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);
            let signing_key = SigningKey::from_bytes(&key_arr);

            let manifest_raw = fs::read_to_string(&manifest)?;

            // Pre-validation: ensure the manifest is valid before signing
            let parsed_manifest = ToolchainManifest::parse_and_validate(manifest_raw.as_bytes())?;
            println!(
                "Manifest parsed and validated successfully (seq={}, components={:?})",
                parsed_manifest.sequence_number,
                parsed_manifest.components.keys().collect::<Vec<_>>()
            );

            // Sign exact raw canonical bytes
            let signature = signing_key.sign(manifest_raw.as_bytes());
            let sig_hex = hex::encode(signature.to_bytes());

            let envelope = ToolchainEnvelope {
                format_version: 1,
                key_id,
                signature: sig_hex,
                manifest_raw,
            };

            let envelope_json = serde_json::to_string_pretty(&envelope)?;
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&out, envelope_json)?;

            println!("Signed envelope written to: {}", out.display());
        }
        Commands::Verify {
            envelope,
            pubkey_hex,
        } => {
            let env_bytes = fs::read(&envelope)?;
            let env: ToolchainEnvelope = serde_json::from_slice(&env_bytes)?;

            let verifying_key = if let Some(hex_str) = pubkey_hex {
                let bytes = hex::decode(hex_str)?;
                if bytes.len() != 32 {
                    return Err("Public key must be 32 bytes".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                VerifyingKey::from_bytes(&arr)?
            } else {
                tempris_collector::toolchain::keys::get_verification_key()?
            };

            let sig_bytes = hex::decode(&env.signature)?;
            if sig_bytes.len() != 64 {
                return Err("Signature must be 64 bytes".into());
            }
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);
            let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

            verifying_key.verify_strict(env.manifest_raw.as_bytes(), &signature)?;
            let manifest = ToolchainManifest::parse_and_validate(env.manifest_raw.as_bytes())?;

            println!("Signature VERIFIED. Manifest valid:");
            println!("  Schema Version: {}", manifest.schema_version);
            println!("  Channel: {}", manifest.channel);
            println!("  Sequence: {}", manifest.sequence_number);
            println!("  Min Collector Version: {}", manifest.min_collector_version);
            for (comp_name, comp) in manifest.components {
                println!("  Component '{}': v{} ({})", comp_name, comp.version, comp.entrypoint);
            }
        }
    }

    Ok(())
}
