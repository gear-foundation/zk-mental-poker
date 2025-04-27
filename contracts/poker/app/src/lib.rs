#![no_std]

mod services;
use sails_rs::prelude::*;
use services::{PokerService, Config};

pub struct PokerProgram(());

#[sails_rs::program]
impl PokerProgram {
    // Program's constructor
    pub fn new(config: Config) -> Self {
        PokerService::init(config);
        Self(())
    }

    // Exposed service
    pub fn poker(&self) -> PokerService {
        PokerService::new()
    }
}
