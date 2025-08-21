use bitcoin_practice::encrypt::{Secp256k1};
use rand::{Rng};
use ruint::aliases::U256;


fn main() {
    let a = Secp256k1::default();
    assert_eq!(a * (Secp256k1::N + U256::from(1)), a);
    
    let a: U256 = rand::thread_rng().r#gen();
    dbg!(a);
}
