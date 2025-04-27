#![no_std]
#![warn(clippy::new_without_default)]
#![allow(static_mut_refs)]
mod services;
use crate::services::{Config, PokerFactoryService};

pub struct PokerFactoryProgram(());

#[sails_rs::program]
impl PokerFactoryProgram {
    pub fn new(config: Config) -> Self {
        PokerFactoryService::init(config);
        Self(())
    }

    pub fn poker_factory(&self) -> PokerFactoryService {
        PokerFactoryService::new()
    }

}
