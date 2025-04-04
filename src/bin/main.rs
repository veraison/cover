use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::prelude::*,
    path::{Path, PathBuf},
};

use base64::{
    self, Engine as _,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use clap::{ArgAction, Parser};
use clap_verbosity_flag::{InfoLevel, Verbosity};
use log::{debug, error, info};

use cover::{
    cca::CcaScheme,
    corim::{CorimStore, MemCorimStore},
    custom_error,
    keystore::{KeyStore, MemKeyStore},
    result::{Error, Result},
    scheme::Scheme,
    verifier::Verifier,
};

/// CoRIM verifier. Verifies evidence based on endorsements and trust anchors provided by CoRIMs.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// The path into which the command output will be written. If not specified, it will be
    /// generated based on the name of the evidence file.
    #[arg(short, long)]
    output: Option<String>,

    /// The key used to verify signatures on supplied CoRIMs. This should be specified in the format
    /// <kid>:<path>, i.e. the key ID prefix to the path with a colon. If the key ID is omitted, the
    /// name (not full path) of the file will be used as the key ID. The key ID is matched to the
    /// kid in the CoRIM in order to identify the key that should be used to verify it.
    #[arg(name = "key", short, long, action = ArgAction::Append)]
    keys: Vec<String>,

    /// Path to CoRIM containing data relevant to verification of provided evidence.
    #[arg(short, long = "corim", action = ArgAction::Append)]
    corims: Vec<String>,

    /// Path to a directory containing CoRIMs. An attempt will be made to load any file with
    /// extensions .cbor or .corim in this directory.
    #[arg(short = 'C', long = "corim-dir", action = ArgAction::Append)]
    corim_dirs: Vec<String>,

    /// Indicates the expected format of the evidence and determines how it is evaluated.
    #[arg(short, long, default_value = "cca")]
    scheme: String,

    /// Nonce is embedded in the EAR to prove freshness. The nonce must be base64 or base64-URL
    /// encoded.
    #[arg(short, long)]
    nonce: Option<String>,

    /// Pretty print the EAR.
    #[arg(short, long, default_value_t = false, global = true)]
    pretty: bool,

    /// Force overwrite output if exists.
    #[arg(short, long, default_value_t = false, global = true)]
    force: bool,

    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,

    /// Path to evidence that will be evaluated.
    evidence: String,
}

fn read_key<P: AsRef<Path>>(path: P) -> Result<(String, Vec<u8>)> {
    let parts = path
        .as_ref()
        .to_str()
        .ok_or(Error::custom("invalid key path"))?
        .split(":")
        .collect::<Vec<&str>>();

    let (kid, actual_path) = match parts.len() {
        1 => Ok((
            path.as_ref()
                .file_name()
                .ok_or(Error::custom("invalid key path"))?
                .to_string_lossy()
                .to_string(),
            parts[0].to_string(),
        )),
        2 => Ok((parts[0].to_string(), parts[1].to_string())),
        _ => Err(Error::custom("invalid key path")),
    }?;

    let bytes = fs::read(&actual_path).map_err(Error::custom)?;

    Ok((kid, bytes))
}

fn verify(args: &Cli) -> Result<()> {
    let mut schemes = HashMap::new();
    let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
    schemes.insert("cca".to_string(), cca_scheme);

    debug!(
        "supported schemes: {}",
        schemes
            .keys()
            .map(|k| k.as_ref())
            .collect::<Vec<&str>>()
            .join(", ")
    );

    let evidence = fs::read(&args.evidence).map_err(Error::custom)?;

    let mut key_store = MemKeyStore::new();

    for key_path in &args.keys {
        debug!("reading key from {:?}", key_path);
        let (kid, key) = read_key(key_path)?;
        key_store.add(kid.as_bytes(), key.as_ref())?;
    }

    let mut corim_store = MemCorimStore::new(key_store);

    for corim in &args.corims {
        debug!("loading CoRIM {:?}", corim);
        let corim_bytes = fs::read(corim).map_err(Error::custom)?;
        corim_store.add_bytes(corim_bytes.as_slice())?;
    }

    for dir in &args.corim_dirs {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            match entry.path().extension().and_then(OsStr::to_str) {
                Some("cbor") | Some("corim") => {
                    debug!("loading CoRIM {:?}", entry.path());
                    let corim_bytes = fs::read(entry.path()).map_err(Error::custom)?;
                    corim_store.add_bytes(corim_bytes.as_slice())?;
                }
                Some(_) | None => (),
            }
        }
    }

    let nonce = match &args.nonce {
        Some(encoded) => {
            let encoded = encoded.trim_end_matches("=");
            let decoded = if encoded.contains("/") || encoded.contains("+") {
                STANDARD_NO_PAD.decode(encoded)?
            } else {
                URL_SAFE_NO_PAD.decode(encoded)?
            };

            let decoded_len = decoded.len();
            if !(8..=64).contains(&decoded_len) {
                return Err(custom_error!(
                    "nonce length must be between 8 and 64 bytes (found {})",
                    decoded_len
                ));
            }

            Some(decoded)
        }
        None => None,
    };
    debug!("nonce: {:x?}", nonce);

    let verifier = Verifier::new(corim_store, schemes);
    let result = verifier.verify(&args.scheme, evidence.as_slice(), nonce.as_deref())?;

    debug!("ACS: {}", serde_json::to_string(&result.acs)?);

    let ear_json = match args.pretty {
        true => serde_json::to_string_pretty(&result.ear)?,
        false => serde_json::to_string(&result.ear)?,
    };

    let out_path = match &args.output {
        Some(path) => path.clone(),
        None => {
            let mut path = PathBuf::from(&args.evidence)
                .file_stem()
                .map(|x| x.to_string_lossy())
                .ok_or(Error::custom("could not create output path"))?
                .to_string();
            path.push_str(".ear.json");
            path
        }
    };

    info!("writing result to {}", &out_path);

    let mut out = match args.force {
        true => File::create(&out_path),
        false => File::create_new(&out_path),
    }
    .map_err(|e| {
        custom_error!(
            "could not open {:?} for writing: {}",
            &out_path,
            e.to_string()
        )
    })?;

    out.write_all(ear_json.as_bytes())?;

    Ok(())
}

fn terminate(res: Result<()>) {
    let exit_code = match &res {
        Ok(()) => {
            info!("done.");
            0
        }
        Err(e) => {
            error!("{e}");
            1
        }
    };

    std::process::exit(exit_code);
}

fn main() {
    let args = Cli::parse();

    env_logger::builder()
        .filter_level(args.verbosity.log_level_filter())
        .init();

    terminate(verify(&args));
}
