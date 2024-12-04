#![deny(clippy::cargo)]
//! This repo is not properly implemented
//! Transcript APIs are placeholders; the actual logic is to be implemented later.
#![feature(generic_arg_infer)]

pub mod basic;
pub mod syncronized;
pub use basic::Transcript;
pub use syncronized::TranscriptSyncronized;

mod hasher;

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub struct Challenge<F> {
    pub elements: F,
}
