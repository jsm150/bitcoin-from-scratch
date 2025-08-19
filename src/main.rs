use bitcoin_practice::{elliptic_curve::{Curve, Fp}};


fn main() {
    let p1 = Curve::<223, 0, 7>::new(Fp::new(143), Fp::new(98));
    let p2 = Curve::<223, 0, 7>::new(Fp::new(76), Fp::new(66));
    
    println!("{:?}", p1 + p2);
}
