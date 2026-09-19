/// Encryption parameters for a specific WeChat version.
pub struct CryptoParams {
    pub page_size: usize,
    pub kdf_iter: u32,
    pub hmac_size: usize,
    pub reserve: usize,
    pub key_size: usize,
    pub salt_size: usize,
    pub iv_size: usize,
}

/// WeChat 4.x desktop (Windows/macOS/Linux): the shared SQLCipher 4 parameters
/// (PBKDF2-HMAC-SHA512 with 256k iterations) used on every platform.
pub const WECHAT_4_X: CryptoParams = CryptoParams {
    page_size: 4096,
    kdf_iter: 256_000,
    hmac_size: 64, // SHA-512 output
    reserve: 80,   // IV(16) + HMAC(64)
    key_size: 32,
    salt_size: 16,
    iv_size: 16,
};

/// macOS WeChat 4.1.7.31. Identical to [`WECHAT_4_X`]; kept as an alias for
/// backwards compatibility (the parameters apply to Windows/Linux too).
pub const MACOS_4_1_7_31: CryptoParams = WECHAT_4_X;
