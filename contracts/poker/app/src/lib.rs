#![no_std]

mod services;
use sails_rs::prelude::*;
use services::{Config, PokerService, PublicKey};

pub struct PokerProgram(());

#[sails_rs::program]
impl PokerProgram {
    // Program's constructor
    pub fn new(config: Config, pk: PublicKey) -> Self {
        PokerService::init(config, pk);
        Self(())
    }

    // Exposed service
    pub fn poker(&self) -> PokerService {
        PokerService::new()
    }
}
