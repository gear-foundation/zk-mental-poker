#![no_std]
#![warn(clippy::new_without_default)]
#![allow(static_mut_refs)]
mod services;
use crate::services::{Config, PokerFactoryService};
use sails_rs::{ActorId, Vec};
pub struct PokerFactoryProgram(());

#[sails_rs::program]
impl PokerFactoryProgram {
    pub fn new(
        config: Config,
        pts_actor_id: ActorId,
        vk_shuffle_bytes: Vec<u8>,
        vk_decrypt_bytes: Vec<u8>,
    ) -> Self {
        PokerFactoryService::init(config, pts_actor_id, vk_shuffle_bytes, vk_decrypt_bytes);
        Self(())
    }

    pub fn poker_factory(&self) -> PokerFactoryService {
        PokerFactoryService::new()
    }
}
