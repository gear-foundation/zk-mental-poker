#![no_std]

mod services;
use sails_rs::prelude::*;
use services::{Config, PokerService, PublicKey, VerifyingKeyBytes};

pub struct PokerProgram(());

#[sails_rs::program]
impl PokerProgram {
    // Program's constructor
    pub fn new(config: Config, pts_actor_id: ActorId, pk: PublicKey, vk_shuffle_bytes: VerifyingKeyBytes, vk_decrypt_bytes: VerifyingKeyBytes) -> Self {
        PokerService::init(config, pts_actor_id, pk, vk_shuffle_bytes, vk_decrypt_bytes);
        Self(())
    }

    // Exposed service
    pub fn poker(&self) -> PokerService {
        PokerService::new()
    }
}
