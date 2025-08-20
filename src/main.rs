use std::str::FromStr;

use bitcoin_practice::encrypt::{Secp256k1};
use ruint::aliases::U256;


fn main() {
    let a = Secp256k1::build();

    dbg!(a * (Secp256k1::N + U256::from(1)));
    dbg!(Secp256k1::GX, Secp256k1::GY);
}
