use std::{io::Write, path::{Path, PathBuf}, fs::{File, create_dir, read_dir}, collections::HashMap};

use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use monero::{network::Network, util::{key::PublicKey, address::{AddressType, Address}}, cryptonote::hash::keccak_256};

use modular_frost::{curves::dalek::Ed25519, MultisigParams, MultisigKeys, key_gen, tests::recover};

use structopt::StructOpt;

// Ripped from modular_frost::tests which wasn't usable as it hardcoded t/n
pub fn key_gen(t: u16, n: u16) -> HashMap<u16, MultisigKeys<Ed25519>> {
  let mut params = HashMap::new();
  let mut machines = HashMap::new();

  let mut commitments = HashMap::new();
  for i in 1 ..= n {
    params.insert(
      i,
      MultisigParams::new(t, n, i).unwrap()
    );
    machines.insert(
      i,
      key_gen::StateMachine::<Ed25519>::new(
        params[&i],
        "FROST Test key_gen".to_string()
      )
    );
    commitments.insert(
      i,
      machines.get_mut(&i).unwrap().generate_coefficients(&mut OsRng).unwrap()
    );
  }

  let mut secret_shares = HashMap::new();
  for (l, machine) in machines.iter_mut() {
    secret_shares.insert(
      *l,
      machine.generate_secret_shares(&mut OsRng, commitments.clone()).unwrap()
    );
  }

  let mut group_key = None;
  let mut keys = HashMap::new();
  for (i, machine) in machines.iter_mut() {
    let mut our_secret_shares = HashMap::new();
    for (l, shares) in &secret_shares {
      if i == l {
        continue;
      }
      our_secret_shares.insert(*l, shares[&i].clone());
    }
    let these_keys = machine.complete(&mut OsRng, our_secret_shares).unwrap();

    // Verify the group keys are agreed upon
    if group_key.is_none() {
      group_key = Some(these_keys.group_key());
    }
    assert_eq!(group_key.unwrap(), these_keys.group_key());

    keys.insert(*i, these_keys);
  }

  keys
}

#[derive(Clone, Serialize, Deserialize)]
struct KeyFile {
  // Optional so this can be run with leader(s), so they are the sole people who can watch the
  // wallet, while the rest are solely trusted to perform recovery as needed
  // Additionally having leaders have an offset, so their participation is required, may be beneficial
  address: Option<String>,
  view: Option<String>,
  serialized: String
}

#[derive(Clone, Debug, StructOpt)]
pub struct Cli {
  /// The needed amount of shares to recover the created private key.
  #[structopt(short)]
  t: Option<u16>,
  /// The amount of shares to create.
  #[structopt(short)]
  n: Option<u16>,
  /// Path to use for the keys directory.
  path: PathBuf,
  /// Load the keys from the specified directory, instead of creating new keys.
  #[structopt(long)]
  load: bool
}

fn view(spend: Scalar) -> Scalar {
  Scalar::from_bytes_mod_order(keccak_256(&spend.to_bytes()))
}

fn address(spend: Scalar, view: Scalar) -> String {
  Address {
    network: Network::Testnet,
    addr_type: AddressType::Standard,
    public_spend: PublicKey { point: (&ED25519_BASEPOINT_TABLE * &spend).compress() },
    public_view: PublicKey { point: (&ED25519_BASEPOINT_TABLE * &view).compress() }
  }.to_string()
}

fn load(path: &Path) -> (Scalar, Scalar, String) {
  assert!(path.exists(), "Key folder doesn't exist");

  let mut keys = HashMap::new();
  for file in read_dir(path).unwrap() {
    let file: KeyFile = serde_json::from_reader(File::open(file.unwrap().path()).unwrap()).unwrap();
    let share = MultisigKeys::<Ed25519>::deserialize(&hex::decode(file.serialized).unwrap()).unwrap();
    keys.insert(share.params().i(), share);
  }

  let spend = recover::<Ed25519>(&keys).0;
  let view = view(spend);
  (spend, view, address(spend, view))
}

fn new(path: &Path, t: u16, n: u16) -> (Scalar, Scalar, String) {
  assert!(!path.exists(), "Key folder already exists");

  let keys = key_gen(t, n);
  let spend = recover::<Ed25519>(&keys.iter().map(|(i, keys)| (*i, keys.clone())).collect()).0;
  let view = view(spend);
  let address = address(spend, view);

  let base = KeyFile {
    address: Some(address.clone()),
    view: Some(hex::encode(&view.to_bytes())),
    serialized: "".to_string()
  };

  create_dir(path).unwrap();
  for (i, share) in &keys {
    let mut this = base.clone();
    this.serialized = hex::encode(share.serialize());
    File::create(
      path.join(format!("share.{i}-{n}.json"))
    ).unwrap().write_all(serde_json::to_string(&this).unwrap().as_bytes()).unwrap();
  }

  // Load them back to verify
  let (loaded_spend, loaded_view, loaded_address) = load(path);
  assert_eq!(loaded_spend, spend, "Saved invalid keys");
  assert_eq!(loaded_view, view, "Saved invalid keys");
  assert_eq!(loaded_address, address, "Saved invalid keys");

  (spend, view, address)
}

fn main() {
  let cli = Cli::from_args();

  let (spend, view, address) = if !cli.load {
    let keys;
    if let (Some(t), Some(n)) = (cli.t, cli.n) {
      keys = new(cli.path.as_path(), t, n);
    } else {
      panic!("t and n must be specified when creating keys.")
    }
    println!("The key shares have been written to the specified folder. Test them before funding them.");
    println!("This means loading the private keys, entering them into monero-wallet-cli, and verifying the address.");
    println!("Failure to do so may result in a permanent loss of funds.");
    keys
  } else {
    load(cli.path.as_path())
  };

  println!("Private spend key: {}", hex::encode(spend.to_bytes()));
  println!("Private view key: {}", hex::encode(view.to_bytes()));
  println!("Address: {address}");
}
