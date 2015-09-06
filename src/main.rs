extern crate time;
extern crate onionsalt;
extern crate sodiumoxide;

use time::PreciseTime;
use onionsalt::crypto;

mod nacl;

fn main() {
    bench_random_nonce();
    bench_sodium_gen_nonce();
    for i in &[33usize, 64, 100, 1000, 10000] {
        println!("");
        bench_secretbox(*i);
        bench_sodium_secretbox(*i);
        bench_nacl_secretbox(*i);
        println!("");
        bench_cryptobox(*i);
        bench_sodium_cryptobox(*i);
        bench_nacl_cryptobox(*i);
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

fn bench_sodium_gen_nonce() {
    bench_function("sodium gen_nonce", 1, |_, _| {
        sodiumoxide::crypto::secretbox::gen_nonce();
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

fn bench_nacl_cryptobox(len: usize) {
    let k1 = crypto::box_keypair().unwrap();
    let k2 = crypto::box_keypair().unwrap();
    let n = crypto::random_nonce().unwrap();
    bench_function(&format!("nacl cryptobox({})", len), len, |c,p| {
        nacl::box_up(c, p, &n.0, &k1.public.0, &k2.secret.0);
    });
}

fn bench_secretbox(len: usize) {
    let k = crypto::random_nonce().unwrap();
    let n = crypto::random_nonce().unwrap();
    bench_function(&format!("secretbox({})", len), len, |c,p| {
        crypto::secretbox(c, p, &n, &k.0).unwrap();
    });
}

fn bench_nacl_secretbox(len: usize) {
    let k = crypto::random_nonce().unwrap();
    let n = crypto::random_nonce().unwrap();
    bench_function(&format!("nacl secretbox({})", len), len, |c,p| {
        nacl::secretbox(c, p, &n.0, &k.0);
    });
}

fn bench_sodium_secretbox(len: usize) {
    let k = sodiumoxide::crypto::secretbox::gen_key();
    let n = sodiumoxide::crypto::secretbox::gen_nonce();
    bench_function(&format!("sodium secretbox({})", len), len, |c,p| {
        let ciphertext = sodiumoxide::crypto::secretbox::seal(&p[32..], &n, &k);
        for i in 0..len-32 {
            c[i+32] = ciphertext[i];
        }
    });
}

fn bench_sodium_cryptobox(len: usize) {
    let (_, oursk) = sodiumoxide::crypto::box_::gen_keypair();
    // normally theirpk is sent by the other party
    let (theirpk, _) = sodiumoxide::crypto::box_::gen_keypair();
    let nonce = sodiumoxide::crypto::box_::gen_nonce();
    bench_function(&format!("cryptobox({})", len), len, |c,p| {
        let ciphertext = sodiumoxide::crypto::box_::seal(&p[32..], &nonce, &theirpk, &oursk);
        for i in 0..len-32 {
            c[i+32] = ciphertext[i];
        }
    });
}

