extern crate libc;

#[link(name = "tweetnacl")]
extern {
    fn crypto_secretbox(c: *mut u8,
                        p: *const u8,
                        len: libc::c_longlong,
                        n: *const u8,
                        k: *const u8) -> libc::c_int;
    fn crypto_box(c: *mut u8,
                  p: *const u8,
                  len: libc::c_longlong,
                  n: *const u8,
                  pk: *const u8,
                  sk: *const u8) -> libc::c_int;
}

pub fn box_up(c: &mut [u8],
              p: &[u8],
              n: &[u8; 32],
              pk: &[u8; 32],
              sk: &[u8; 32]) {
    assert_eq!(c.len(), p.len());
    unsafe {
        crypto_box(c.as_mut_ptr(),
                   p.as_ptr(),
                   c.len() as libc::c_longlong,
                   n.as_ptr(),
                   pk.as_ptr(),
                   sk.as_ptr());
    }
}

pub fn secretbox(c: &mut [u8],
                 p: &[u8],
                 n: &[u8; 32],
                 k: &[u8; 32]) {
    assert_eq!(c.len(), p.len());
    unsafe {
        crypto_secretbox(c.as_mut_ptr(),
                         p.as_ptr(),
                         c.len() as libc::c_longlong,
                         n.as_ptr(),
                         k.as_ptr());
    }
}
