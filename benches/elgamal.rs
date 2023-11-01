const N: usize = 4096;

fn bench_elgamal(c: &mut Criterion) {
    let mut group = c.benchmark_group("split-elgamal");

    group.bench_function("encrypt-scalars", |b| {
        b.iter(|| {
            todo!();
        }
    });

    group.bench_function("verify-split-encryption", |b| {
        b.iter(|| {
            todo!();
        }
    });

    group.finish()
}

criterion_group!(benches, bench_elgamal);
criterion_main!(benches);
