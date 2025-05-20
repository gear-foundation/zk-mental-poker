use gclient::{GearApi, Result};
use sails_rs::{ActorId, Decode, Encode};
mod utils_gclient;
use utils_gclient::*;

#[tokio::test]
async fn test_basic_function() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    make_zk_actions(&api, &mut listener).await?;

    Ok(())
}
