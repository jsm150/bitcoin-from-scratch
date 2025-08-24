use bitcoin_practice::encrypt::{Fp, PublicAddress, PublicKey, Secp256k1, Signature};
use ruint::aliases::U256;


fn main() {
    let public_key = PublicKey::build(Secp256k1::default() * 0x12345deadbeef).unwrap();
    let addr = PublicAddress::builder(public_key)
        .from_compress()
        .into_main_net();

    println!("{:?}", addr);
}
