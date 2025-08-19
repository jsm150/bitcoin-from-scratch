use bitcoin_practice::{elliptic_curve::{Curve, FieldElement}};

pub type F<const P: usize> = FieldElement<P>;


fn main() {
    let p1 = Curve::<223, 0, 7>::new(F::new(143), F::new(98));
    let p2 = Curve::<223, 0, 7>::new(F::new(76), F::new(66));
    
    println!("{:?}", p1 + p2);
}
