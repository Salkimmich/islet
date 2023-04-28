#![deny(warnings)]
#![warn(rust_2018_idioms)]

pub mod attester;
pub mod claim;
pub mod error;
pub mod report;
pub mod verifier;

mod config;
mod mock;
mod parser;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attest_verify() {
        let report = attester::attest().unwrap();
        assert_eq!(report.len(), mock::REPORT_LEN);
        verifier::verify(&report).unwrap();
    }
}