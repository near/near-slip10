#![no_std]

pub mod ffi {
    #![allow(
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        dead_code
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub const ML_DSA_65_SEED_LENGTH: usize = ffi::MLDSA65_SEEDBYTES as usize; // 32
pub const ML_DSA_65_PUBLIC_KEY_LENGTH: usize = ffi::MLDSA65_PUBLICKEYBYTES as usize; // 1952
pub const ML_DSA_65_SECRET_KEY_LENGTH: usize = ffi::MLDSA65_SECRETKEYBYTES as usize; // 4032

#[derive(Debug, Clone, Copy)]
pub struct Error(i32);

impl Error {
    pub fn code(&self) -> i32 {
        self.0
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self.0 {
            ffi::MLD_ERR_OUT_OF_MEMORY => "out of memory",
            ffi::MLD_ERR_PCT_FAIL => "pairwise consistency test failed",
            ffi::MLD_ERR_INVALID_ARG => "invalid argument",
            _ => "unknown error",
        };

        write!(f, "mldsa-native: {name} (code {})", self.0)
    }
}

impl core::error::Error for Error {}

pub fn ml_dsa_65_keypair_from_seed(
    seed: &[u8; ML_DSA_65_SEED_LENGTH],
    pk: &mut [u8; ML_DSA_65_PUBLIC_KEY_LENGTH],
    sk: &mut [u8; ML_DSA_65_SECRET_KEY_LENGTH],
) -> Result<(), Error> {
    // SAFETY: pointers come from references to arrays of exactly the sizes the C
    // prototype declares (constants read from the same header the C was compiled
    // against); distinct &mut so no aliasing; C retains no pointer past the call.
    let rc =
        unsafe { ffi::mldsa65_keypair_internal(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
    if rc == 0 { Ok(()) } else { Err(Error(rc)) }
}
