extern crate time;
extern crate onionsalt;

use time::PreciseTime;
use onionsalt::crypto;

fn main() {
    bench_random_nonce();
    for i in &[33usize, 64, 100, 1000, 10000] {
        bench_secretbox(*i);
        bench_cryptobox(*i);
    }
}

fn bench_function<F>(name: &str, len: usize, f: F) where F: Fn(&mut[u8], &mut[u8]) {
    let mut num_iters: usize = 10;
    let mut secs = 0.0;
    let mut total_secs = 0.0;
    let mut ciphertext = vec![0; len];
    let mut plaintext = vec![0; len];
    let time_goal = 1.0;

    while total_secs < time_goal {
        let start = PreciseTime::now();
        for _ in 0..num_iters {
            f(&mut ciphertext, &mut plaintext);
        }
        let stop = PreciseTime::now();
        let total = start.to(stop);
        total_secs = match total.num_nanoseconds() {
            Some(ns) => ns as f64 * 1e-9,
            None => match total.num_microseconds() {
                Some(us) => us as f64 * 1e-6,
                None => total.num_milliseconds() as f64 * 1e-3,
            },
        };
        secs = total_secs / num_iters as f64;
        num_iters = (1.1 * time_goal / secs) as usize + 1;
    }
    println!("{} took {:.2} us", name, secs*1e6);
}

fn bench_random_nonce() {
    bench_function("random_nonce", 1, |_, _| {
        crypto::random_nonce().unwrap();
    });
}

fn bench_cryptobox(len: usize) {
    let k1 = crypto::box_keypair().unwrap();
    let k2 = crypto::box_keypair().unwrap();
    let n = crypto::random_nonce().unwrap();
    bench_function(&format!("cryptobox({})", len), len, |c,p| {
        crypto::box_up(c, p, &n, &k1.public, &k2.secret).unwrap();
    });
}

fn bench_secretbox(len: usize) {
    let k = crypto::random_nonce().unwrap();
    let n = crypto::random_nonce().unwrap();
    bench_function(&format!("secretbox({})", len), len, |c,p| {
        crypto::secretbox(c, p, &n, &k.0).unwrap();
    });
}
