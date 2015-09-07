extern crate libc;

#[link(name = "tweetnacl")]
extern {
    fn tweetnacl_secretbox(c: *mut u8,
                           p: *const u8,
                           len: libc::c_longlong,
                           n: *const u8,
                           k: *const u8) -> libc::c_int;
    fn tweetnacl_box(c: *mut u8,
                     p: *const u8,
                     len: libc::c_longlong,
                     n: *const u8,
                     pk: *const u8,
                     sk: *const u8) -> libc::c_int;
    fn tweetnacl_box_beforenm(k: *mut u8,
                              y: *const u8,
                              x: *const u8) -> libc::c_int;
    fn tweetnacl_scalarmult(k: *mut u8,
                            y: *const u8,
                            x: *const u8) -> libc::c_int;
    // fn tweetnacl_pack25519(o: *mut u8, y: *const i64);

    // fn tweetnacl_sel25519(x: *mut i64, y: *mut i64, b: libc::c_int);
    // fn tweetnacl_inv25519(o: *mut i64, i: *const i64);
}

// pub fn inv25519(i: &[i64;16]) -> [i64;16] {
//     unsafe {
//         let mut o = [0i64;16];
//         tweetnacl_inv25519((&mut o).as_mut_ptr(), i.as_ptr());
//         o
//     }
// }

// pub fn sel25519(x: &mut[i64;16], y: &mut[i64;16], b: i64) {
//     unsafe {
//         tweetnacl_sel25519(x.as_mut_ptr(), y.as_mut_ptr(), b as libc::c_int);
//     }
// }

// pub fn pack25519(o: &mut[u8;32], i: &[i64;16]) {
//     unsafe {
//         tweetnacl_pack25519(o.as_mut_ptr(), i.as_ptr());
//     }
// }

pub fn scalarmult(o: &mut[u8;32], pk: &[u8;32], sk: &[u8;32]) {
    o[0] = 3;
    unsafe {
        tweetnacl_scalarmult(o.as_mut_ptr(), pk.as_ptr(), sk.as_ptr());
    }
}

pub fn box_beforenm(pk: &[u8;32], sk: &[u8;32]) -> [u8;32] {
    let mut k: [u8; 32] = [0; 32];
    unsafe {
        tweetnacl_box_beforenm(k.as_mut_ptr(), pk.as_ptr(), sk.as_ptr());
    }
    k
}

pub fn box_up(c: &mut [u8],
              p: &[u8],
              n: &[u8; 24],
              pk: &[u8; 32],
              sk: &[u8; 32]) {
    assert_eq!(c.len(), p.len());
    unsafe {
        tweetnacl_box(c.as_mut_ptr(),
                      p.as_ptr(),
                      c.len() as libc::c_longlong,
                      n.as_ptr(),
                      pk.as_ptr(),
                      sk.as_ptr());
    }
}

pub fn secretbox(c: &mut [u8],
                 p: &[u8],
                 n: &[u8; 24],
                 k: &[u8; 32]) {
    assert_eq!(c.len(), p.len());
    unsafe {
        tweetnacl_secretbox(c.as_mut_ptr(),
                            p.as_ptr(),
                            c.len() as libc::c_longlong,
                            n.as_ptr(),
                            k.as_ptr());
    }
}
