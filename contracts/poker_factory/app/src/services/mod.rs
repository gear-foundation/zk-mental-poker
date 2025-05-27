use gstd::prog::ProgramGenerator;
use poker_client::{PublicKey, VerifyingKeyBytes};
use sails_rs::collections::{HashMap, HashSet};
use sails_rs::gstd::msg;
use sails_rs::prelude::*;
mod utils;
use crate::services::utils::panic;
use pts_client::pts::io as pts_io;
use sails_rs::calls::ActionIo;

#[derive(Debug, Clone)]
struct Storage {
    lobbies: HashMap<ActorId, LobbyConfig>,
    admins: HashSet<ActorId>,
    config: Config,
    pts_actor_id: ActorId,
    vk_shuffle_bytes: Vec<u8>,
    vk_decrypt_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct Config {
    pub lobby_code_id: CodeId,
    pub gas_for_program: u64,
    pub gas_for_reply_deposit: u64,
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct LobbyConfig {
    admin_id: ActorId,
    admin_name: String,
    lobby_name: String,
    small_blind: u128,
    big_blind: u128,
    number_of_participants: u16,
    starting_bank: u128,
}

static mut STORAGE: Option<Storage> = None;

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Event {
    LobbyCreated {
        lobby_address: ActorId,
        admin: ActorId,
        lobby_config: LobbyConfig,
    },
    LobbyDeleted {
        lobby_address: ActorId,
    },
}

pub struct PokerFactoryService(());

impl PokerFactoryService {
    pub fn init(
        config: Config,
        pts_actor_id: ActorId,
        vk_shuffle_bytes: Vec<u8>,
        vk_decrypt_bytes: Vec<u8>,
    ) -> Self {
        unsafe {
            STORAGE = Some(Storage {
                admins: HashSet::from([msg::source()]),
                config,
                lobbies: HashMap::new(),
                pts_actor_id,
                vk_shuffle_bytes,
                vk_decrypt_bytes,
            });
        }
        Self(())
    }
    fn get_mut(&mut self) -> &'static mut Storage {
        unsafe { STORAGE.as_mut().expect("Storage is not initialized") }
    }
    fn get(&self) -> &'static Storage {
        unsafe { STORAGE.as_ref().expect("Storage is not initialized") }
    }
}

#[sails_rs::service(events = Event)]
impl PokerFactoryService {
    pub fn new() -> Self {
        Self(())
    }

    pub async fn create_lobby(&mut self, init_lobby: LobbyConfig, pk: PublicKey) {
        let storage = self.get_mut();
        let msg_src = msg::source();

        let request = pts_io::GetBalance::encode_call(msg_src);

        let bytes_reply_balance = msg::send_bytes_for_reply(storage.pts_actor_id, request, 0, 0)
            .expect("Error in async message to PTS contract")
            .await
            .expect("PTS: Error getting balance from the contract");

        let balance: u128 = pts_io::GetBalance::decode_reply(bytes_reply_balance).unwrap();

        sails_rs::gstd::debug!("AFTER PTS REPLY");
        if balance < init_lobby.starting_bank {
            panic!("Low pts balance");
        }
        sails_rs::gstd::debug!("BEFORE PAYLOAD");
        let payload = [
            "New".encode(),
            init_lobby.encode(),
            storage.pts_actor_id.encode(),
            pk.encode(),
            storage.vk_shuffle_bytes.clone(),
            storage.vk_decrypt_bytes.clone(),
        ]
        .concat();
        let create_program_future = ProgramGenerator::create_program_bytes_with_gas_for_reply(
            storage.config.lobby_code_id,
            payload,
            storage.config.gas_for_program,
            1_000_000_000_000,
            storage.config.gas_for_reply_deposit,
        )
        .unwrap_or_else(|e| panic(e));

        let (lobby_address, _) = create_program_future.await.unwrap_or_else(|e| panic(e));

        let request = pts_io::AddAdmin::encode_call(lobby_address);

        msg::send_bytes_for_reply(storage.pts_actor_id, request, 0, 0)
            .expect("Error in async message to PTS contract")
            .await
            .expect("PTS: Error adding new admin");

        let request =
            pts_io::Transfer::encode_call(msg_src, lobby_address, init_lobby.starting_bank);

        msg::send_bytes_for_reply(storage.pts_actor_id, request, 0, 0)
            .expect("Error in async message to PTS contract")
            .await
            .expect("PTS: Error transfer points to contract");

        storage.lobbies.insert(lobby_address, init_lobby.clone());

        self.emit_event(Event::LobbyCreated {
            lobby_address,
            admin: msg_src,
            lobby_config: init_lobby,
        })
        .expect("Notification Error");
    }

    pub async fn delete_lobby(&mut self, lobby_address: ActorId) {
        let storage = self.get_mut();
        let msg_src = msg::source();
        let lobby = storage.lobbies.get(&lobby_address).unwrap();
        if msg_src != lobby.admin_id && msg_src != lobby_address {
            panic!();
        }
        storage.lobbies.remove(&lobby_address);

        self.emit_event(Event::LobbyDeleted { lobby_address })
            .expect("Notification Error");
    }

    pub fn pts_actor_id(&self) -> ActorId {
        self.get().pts_actor_id
    }
}
