//! Encryption at rest for the workspace file.
//!
//! On Windows the data is sealed with DPAPI (`CryptProtectData`), which ties it to the
//! current Windows user account: other users on the machine, and anyone who copies
//! the file to another computer, cannot read it. On other systems the data is kept as
//! is (FreeTerm currently targets Windows only).

/// Seals `plain`. Returns `None` if the operating system refused.
pub fn seal(plain: &[u8]) -> Option<Vec<u8>> {
    imp::seal(plain)
}

/// Opens data made by [`seal`]. Returns `None` if it cannot be decrypted
/// (for example: a different Windows user or a damaged file).
pub fn open(sealed: &[u8]) -> Option<Vec<u8>> {
    imp::open(sealed)
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    /// Extra entropy so other programs using plain DPAPI calls for this user
    /// cannot open the file by accident.
    const ENTROPY: &[u8] = b"FreeTerm workspace v1";

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: on success DPAPI returns a LocalAlloc'd buffer of `cbData` bytes,
        // which we copy and then free exactly once.
        unsafe {
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData as HLOCAL);
            v
        }
    }

    pub fn seal(plain: &[u8]) -> Option<Vec<u8>> {
        let input = blob(plain);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: all pointers refer to live buffers for the duration of the call.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 { None } else { Some(take(out)) }
    }

    pub fn open(sealed: &[u8]) -> Option<Vec<u8>> {
        let input = blob(sealed);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: all pointers refer to live buffers for the duration of the call.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 { None } else { Some(take(out)) }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn seal(plain: &[u8]) -> Option<Vec<u8>> {
        Some(plain.to_vec())
    }
    pub fn open(sealed: &[u8]) -> Option<Vec<u8>> {
        Some(sealed.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip() {
        let data = b"{\"hosts\":[]}";
        let sealed = super::seal(data).expect("seal");
        #[cfg(windows)]
        assert_ne!(sealed.as_slice(), data.as_slice());
        assert_eq!(super::open(&sealed).expect("open"), data);
    }
}
