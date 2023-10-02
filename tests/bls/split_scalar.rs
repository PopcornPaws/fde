use crate::*;

#[test]
fn scalar_splitting() {
    let scalar = Scalar::zero();
    let split_scalar = SpScalar::from(scalar);
    println!("{:?}", split_scalar);
    let reconstructed_scalar = split_scalar.reconstruct();
    assert_eq!(scalar, reconstructed_scalar);

    let rng = &mut test_rng();
    let max_scalar = Scalar::from(u32::MAX);
    for _ in 0..10 {
        let scalar = Scalar::rand(rng);
        let split_scalar = SpScalar::from(scalar);
        for split in split_scalar.splits() {
            assert!(split <= &max_scalar);
        }
        let reconstructed_scalar = split_scalar.reconstruct();
        assert_eq!(scalar, reconstructed_scalar);
    }
}
