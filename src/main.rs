use std::str::FromStr;

use bitcoin_practice::secp256k1::elliptic_curve::{Curve, Fp};
use ruint::aliases::U256;

fn main() {
    let gx: U256 = U256::from_str("0x79BE667_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798").unwrap();
    let gy: U256 = U256::from_str("0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8").unwrap();
    let n = U256::from_str("0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141").unwrap();
    let p: U256 = U256::MAX - U256::from(u32::MAX) - U256::from(997);

    // U256::from_
    
    let a = U256::from_str("0x2_0").unwrap();
    dbg!(a);
}
