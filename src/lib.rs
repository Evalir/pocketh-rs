use ethers::core::types::*;
use ethers::signers::coins_bip39::{English, Mnemonic};
use ethers::utils::keccak256;
use rayon::prelude::*;
use std::path::Path;
use std::sync::mpsc;

mod util;

#[derive(Debug, Default)]
pub struct Pocketh {}

impl Pocketh {
    pub fn new() -> Self {
        Self {}
    }

    /// Generates a random mnemonic phrase that can then be used to generate accounts.
    ///
    /// ```no_run
    /// use pocketh::Pocketh;
    ///
    /// fn foo() -> eyre::Result<()> {
    ///     let pocketh = Pocketh::new();
    ///     let mnemonic = pocketh.generate_random_phrase();
    ///     println!("{}", mnemonic);
    ///     Ok(())
    /// }
    /// ````
    pub fn generate_random_phrase(&self) -> String {
        let mut rng = rand::thread_rng();

        let mnemonic = Mnemonic::<English>::new(&mut rng);

        mnemonic.to_phrase().unwrap()
    }

    /// Converts from wei, to a different denomination (gwei, ether)
    ///
    /// ```no_run
    /// use pocketh::Pocketh;
    ///
    /// fn foo() -> eyre::Result<()> {
    ///     let pocketh = Pocketh::new();
    ///     let wei = 1;
    ///     let gwei = pocketh.from_wei(1.into(), "gwei".to_string())?; // 0.000000001
    ///     let eth = pocketh.from_wei(1.into(), "eth".to_string())?; // 0.000000000000000001
    ///     println!("gwei: {}", gwei);
    ///     println!("eth: {}", eth);
    ///     Ok(())
    /// }
    /// ```
    pub fn from_wei(&self, value: U256, unit: String) -> eyre::Result<String> {
        Ok(match &unit[..] {
            "gwei" => ethers::core::utils::format_units(value, 9),
            "eth" | "ether" => ethers::core::utils::format_units(value, 18),
            _ => ethers::core::utils::format_units(value, 18),
        }?)
    }

    /// Converts to wei, from a different denomination (gwei, ether)
    ///
    /// ```no_run
    /// use pocketh::Pocketh;
    ///
    /// fn foo() -> eyre::Result<()> {
    ///     let pocketh = Pocketh::new();
    ///     let wei = 1;
    ///     let gwei = pocketh.to_wei(1.into(), "gwei".to_string())?; // 1000000000
    ///     let eth = pocketh.to_wei(1.into(), "eth".to_string())?; // 1000000000000000000
    ///     println!("gwei: {}", gwei);
    ///     println!("eth: {}", eth);
    ///     Ok(())
    /// }
    /// ```
    pub fn to_wei(&self, value: f64, unit: String) -> eyre::Result<String> {
        let val = value.to_string();
        Ok(match &unit[..] {
            "gwei" => ethers::core::utils::parse_units(val, 9),
            "eth" | "ether" => ethers::core::utils::parse_units(val, 18),
            _ => ethers::core::utils::parse_units(val, 18),
        }?
        .to_string())
    }

    /// Calculates the selector from a function signature
    ///
    /// ```no_run
    /// use pocketh::Pocketh;
    ///
    /// fn foo() -> eyre::Result<()> {
    ///     let pocketh = Pocketh::new();
    ///     let fn_sig = "createAndOpen(address,address)";
    ///     let selector = pocketh.get_selector(fn_sig)?;
    ///
    ///     println!("{}", selector);
    ///
    ///     Ok(())
    /// }
    pub fn get_selector(&self, sig: &str) -> eyre::Result<String> {
        let hashed_sig = keccak256(sig).to_vec();

        Ok(format!("0x{}", hex::encode(&hashed_sig[..4])))
    }

    /// Calculates the keccak256 hash of the provided payload.
    ///
    /// ```no_run
    /// use pocketh::Pocketh;
    ///
    /// fn foo() -> eyre::Result<()> {
    ///     let pocketh = Pocketh::new();
    ///     let payload = "vitalik_masternode";
    ///     let hashed_payload = pocketh.get_hash(payload)?;
    ///
    ///     println!("{}", hashed_payload);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn get_hash(&self, payload: &str) -> eyre::Result<String> {
        let hashed_payload = keccak256(payload).to_vec();

        Ok(format!("0x{}", hex::encode(hashed_payload)))
    }

    /// Converts a number to a hex string.
    pub fn uint_to_hex(&self, value: usize) -> eyre::Result<String> {
        Ok(format!("{value:#x}"))
    }

    /// Converts a hex string into a number.
    pub fn hex_to_uint(&self, value: &str) -> eyre::Result<usize> {
        Ok(usize::from_str_radix(strip_0x(value), 16)?)
    }

    /// Converts a string into a valid hex string.
    pub fn str_to_hex(&self, value: &str) -> eyre::Result<String> {
        Ok(format!("0x{}", hex::encode(value)))
    }

    /// Brute-force finds a matching selector from the one provided
    pub fn get_matching_selector(
        &self,
        selector: &str,
        args: &str,
        prefix: &str,
        rnd_len: usize,
    ) -> eyre::Result<String> {
        let alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes();
        let selector = self.get_selector(selector).expect("Invalid selector");

        let possible_chars = alphabet.len();
        let possible_perms = possible_chars.pow(rnd_len.try_into().unwrap());

        let (tx, rx) = mpsc::sync_channel(1000);

        (0..possible_perms).into_par_iter().find_any(|&p| {
            let mut rand_string: Vec<u8> = Vec::with_capacity(rnd_len);

            let mut i = 0;
            while i < rnd_len {
                let idx = p / possible_chars.pow(i.try_into().unwrap()) % possible_chars;
                rand_string.push(alphabet[idx]);
                i += 1;
            }

            let random_sig = format!(
                "{}{}({})",
                prefix,
                std::str::from_utf8(&rand_string).unwrap(),
                args
            );

            let rand_selector = self.get_selector(&random_sig).unwrap();

            if rand_selector == selector {
                println!("match {} and {}", rand_selector, selector);
                tx.send(random_sig).unwrap();
                return true;
            }
            false
        });

        let random_sig = rx.recv().expect("No selector found");

        Ok(random_sig)
    }

    pub fn compile_contract(&self, path: impl AsRef<Path>) -> eyre::Result<String> {
        todo!("wip")
    }
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::Pocketh;

    #[test]
    fn test_selector() {
        let pocketh = Pocketh::new();
        assert_eq!(
            pocketh
                .get_selector("createAndOpen(address,address)")
                .unwrap(),
            "0x581f3c50"
        )
    }

    #[test]
    fn test_hash() {
        let pocketh = Pocketh::new();
        assert_eq!(
            pocketh.get_hash("").unwrap(),
            // base keccak256 response
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            pocketh.get_hash("cafeconleche").unwrap(),
            "0x1f19fbea2f63e76368ec292dc853b4c51ada1012666af5435995e15e7f564d2d"
        );
    }

    #[test]
    fn test_uint_to_hex() {
        let pocketh = Pocketh::new();
        assert_eq!(pocketh.uint_to_hex(1).unwrap(), "0x1");
        assert_eq!(pocketh.uint_to_hex(16).unwrap(), "0x10");
        assert_eq!(pocketh.uint_to_hex(100).unwrap(), "0x64");
    }

    #[test]
    fn test_hex_to_uint() {
        let pocketh = Pocketh::new();
        assert_eq!(pocketh.hex_to_uint("01").unwrap(), 1);
        assert_eq!(pocketh.hex_to_uint("10").unwrap(), 16);
        assert_eq!(pocketh.hex_to_uint("0100").unwrap(), 256);
        assert_eq!(pocketh.hex_to_uint("1000").unwrap(), 4096);
        assert_eq!(pocketh.hex_to_uint("1000").unwrap(), 4096);
    }

    #[test]
    pub fn test_str_to_hex() {
        let pocketh = Pocketh::new();
        assert_eq!(pocketh.str_to_hex("foobar").unwrap(), "0x666f6f626172");
    }
}
