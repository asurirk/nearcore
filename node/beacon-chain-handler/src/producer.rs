//! ConsensusHandler consumes consensuses, retrieves the most recent state, computes the new
//! state, signs it and puts in on the BeaconChain.
use std::sync::Arc;

use futures::{Future, future, Stream};
use futures::sync::mpsc::Receiver;
use parking_lot::RwLock;

use beacon::types::{BeaconBlock, BeaconBlockChain};
use node_runtime::{ApplyState, Runtime};
use primitives::traits::{Block, Header};
use primitives::traits::Signer;
use primitives::types::{BlockId, ReceiptTransaction, SignedTransaction};
use primitives::types::ConsensusBlockBody;
use shard::{ShardBlock, ShardBlockChain};
use storage::StateDb;

pub fn create_beacon_block_producer_task(
    beacon_chain: Arc<BeaconBlockChain>,
    shard_chain: Arc<ShardBlockChain>,
    runtime: Arc<RwLock<Runtime>>,
    signer: Arc<Signer>,
    state_db: Arc<StateDb>,
    receiver: Receiver<BeaconChainConsensusBlockBody>
) -> impl Future<Item = (), Error = ()> {
    let beacon_block_producer = BeaconBlockProducer::new(
        beacon_chain,
        shard_chain,
        runtime,
        signer,
        state_db,
    );
    receiver.fold(beacon_block_producer, |beacon_block_producer, body| {
        beacon_block_producer.produce_block(body);
        future::ok(beacon_block_producer)
    }).and_then(|_| Ok(()))
}

pub trait ConsensusHandler<B: Block, P>: Send + Sync {
    fn produce_block(&self, body: ConsensusBlockBody<P>) -> B;
}

pub struct BeaconBlockProducer {
    beacon_chain: Arc<BeaconBlockChain>,
    shard_chain: Arc<ShardBlockChain>,
    runtime: Arc<RwLock<Runtime>>,
    signer: Arc<Signer>,
    state_db: Arc<StateDb>,
}

impl BeaconBlockProducer {
    pub fn new(
        beacon_chain: Arc<BeaconBlockChain>,
        shard_chain: Arc<ShardBlockChain>,
        runtime: Arc<RwLock<Runtime>>,
        signer: Arc<Signer>,
        state_db: Arc<StateDb>,
    ) -> Self {
        Self {
            beacon_chain,
            shard_chain,
            runtime,
            signer,
            state_db,
        }
    }
}

pub type ShardChainPayload = (Vec<SignedTransaction>, Vec<ReceiptTransaction>);
pub type BeaconChainConsensusBlockBody = ConsensusBlockBody<ShardChainPayload>;

impl ConsensusHandler<BeaconBlock, ShardChainPayload> for BeaconBlockProducer {
    fn produce_block(&self, body: BeaconChainConsensusBlockBody) -> BeaconBlock {
        // TODO: verify signature
        let transactions = body.messages.iter()
            .flat_map(|message| message.body.payload.0.clone())
            .collect();
        let receipts = body.messages.iter()
            .flat_map(|message| message.body.payload.1.clone())
            .collect();

        // TODO: compute actual merkle root and state, as well as signature, and
        // use some reasonable fork-choice rule
        let last_block = self.beacon_chain.best_block();
        let last_shard_block = self.shard_chain.get_header(&BlockId::Hash(last_block.body.header.shard_block_hash)).expect("At the moment we should have shard blocks accompany beacon blocks");
        let apply_state = ApplyState {
            root: last_shard_block.body.merkle_root_state,
            parent_block_hash: last_block.hash(),
            block_index: last_block.body.header.index + 1,
        };
        let (filtered_transactions, filtered_receipts, mut apply_result) =
            self.runtime.write().apply(&apply_state, transactions, receipts);
        self.state_db.commit(&mut apply_result.transaction).ok();
        let mut shard_block = ShardBlock::new(
            last_shard_block.body.index + 1,
            last_shard_block.hash(),
            apply_result.root,
            filtered_transactions,
            filtered_receipts
        );
        let mut block = BeaconBlock::new(
            last_block.body.header.index + 1,
            last_block.hash(),
            apply_result.authority_proposals,
            shard_block.hash()
        );
        shard_block.signature = shard_block.sign(&self.signer);
        block.signature = block.sign(&self.signer);
        self.shard_chain.insert_block(shard_block.clone());
        self.beacon_chain.insert_block(block.clone());
        info!(target: "block_producer", "Block body: {:?}", block.body);
        block
    }
}