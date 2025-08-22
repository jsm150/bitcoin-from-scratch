use bitcoin_practice::encrypt::{Secp256k1, PublicKey};


fn main() {
    let key = PublicKey::build(Secp256k1::default() * 0xdeadbeef12345).unwrap();
    println!("{:02X?}", key.to_uncompress_sec());
}
