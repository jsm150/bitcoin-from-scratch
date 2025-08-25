use bitcoin_practice::encrypt::{PublicAddress, PublicKey, SecretKey};


fn main() {
    let secret_key = SecretKey::random();
    let public_key = PublicKey::build(secret_key).unwrap();
    let public_address = PublicAddress::build_with_public_key(public_key)
        .from_compress()
        .into_main_net();
    let wif = secret_key.to_wif(&public_address);

    println!("{wif}");
}
