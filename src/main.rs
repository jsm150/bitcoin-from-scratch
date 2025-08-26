use bitcoin_practice::encrypt::{PublicAddress, PublicKey, PublicKeySerialize, SecretAddress, SecretKey};


fn main() {
    let secret_key = SecretKey::random();
    let public_key = PublicKey::build(secret_key).unwrap();
    let public_sec = PublicKeySerialize::from_compress(public_key);
    
    let public_address = PublicAddress::build(&public_sec).into_test_net();
    let secret_wif = SecretAddress::build(&secret_key, &public_address, &public_sec);

    println!("secret_wif: {}", secret_wif.as_ref());
    println!("public_address: {}", public_address.as_ref());

    assert_eq!(secret_key, SecretKey::from(&secret_wif));
    assert_eq!(public_sec, PublicKeySerialize::try_from(&secret_wif).unwrap());
    assert_eq!(public_address, PublicAddress::try_from(&secret_wif).unwrap());
    
}
