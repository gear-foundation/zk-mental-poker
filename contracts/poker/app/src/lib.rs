#![no_std]

pub mod services;
use sails_rs::prelude::*;
use services::session::{Config as SessionConfig, SessionService, SignatureInfo};
use services::{Config, PokerService, VerifyingKeyBytes, ZkPublicKey};
use session_service::*;

pub struct PokerProgram(());

#[sails_rs::program]
impl PokerProgram {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: Config,
        session_config: SessionConfig,
        pts_actor_id: ActorId,
        pk: ZkPublicKey,
        vk_shuffle_bytes: VerifyingKeyBytes,
        vk_decrypt_bytes: VerifyingKeyBytes,
        session_for_admin: Option<SignatureInfo>,
    ) -> Self {
        let admin_id = config.admin_id;
        PokerService::init(config, pts_actor_id, pk, vk_shuffle_bytes, vk_decrypt_bytes);
        SessionService::init(session_config);
        if let Some(SignatureInfo {
            signature_data,
            signature,
        }) = session_for_admin
        {
            SessionService::create_session_for_admin(signature_data, signature, admin_id);
        }
        Self(())
    }

    pub fn poker(&self) -> PokerService {
        PokerService::new()
    }

    pub fn session(&self) -> SessionService {
        SessionService::new()
    }
}
