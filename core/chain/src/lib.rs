extern crate parking_lot;
extern crate primitives;
extern crate storage;

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use primitives::hash::CryptoHash;
use primitives::traits::{Block, Decode, Encode, Header};
use primitives::types::BlockId;
use primitives::utils::index_to_bytes;
use storage::Storage;

const BLOCKCHAIN_BEST_BLOCK: &[u8] = b"best";

/// General BlockChain container.
pub struct BlockChain<B: Block> {
    /// Storage backend.
    storage: Arc<Storage>,
    /// Genesis hash
    pub genesis_hash: CryptoHash,
    /// Tip of the known chain.
    best_block: RwLock<B>,
    /// Headers indexed by hash
    headers: RwLock<HashMap<Vec<u8>, B::Header>>,
    /// Blocks indexed by hash
    blocks: RwLock<HashMap<Vec<u8>, B>>,
    /// Maps block index to hash.
    index_to_hash: RwLock<HashMap<Vec<u8>, CryptoHash>>,
    // TODO: state?
}

fn write_with_cache<T: Clone + Encode>(
    storage: &Arc<Storage>,
    col: Option<u32>,
    cache: &RwLock<HashMap<Vec<u8>, T>>,
    key: &[u8],
    value: &T,
) {
    let data = Encode::encode(value).expect("Error serializing data");
    cache.write().insert(key.to_vec(), value.clone());

    let mut db_transaction = storage.transaction();
    db_transaction.put(col, key, &data);
    storage.write(db_transaction).expect("Database write failed");
}

fn read_with_cache<T: Clone + Decode>(
    storage: &Arc<Storage>,
    col: Option<u32>,
    cache: &RwLock<HashMap<Vec<u8>, T>>,
    key: &[u8],
) -> Option<T> {
    {
        let read = cache.read();
        if let Some(v) = read.get(key) {
            return Some(v.clone());
        }
    }

    match storage.get(col, key) {
        Ok(Some(value)) => Decode::decode(value.as_ref()).map(|value: T| {
            let mut write = cache.write();
            write.insert(key.to_vec(), value.clone());
            value
        }),
        _ => None,
    }
}

impl<B: Block> BlockChain<B> {
    pub fn new(genesis: B, storage: Arc<Storage>) -> Self {
        let genesis_hash = genesis.hash();
        let bc = BlockChain {
            storage,
            genesis_hash,
            best_block: RwLock::new(genesis.clone()),
            headers: RwLock::new(HashMap::new()),
            blocks: RwLock::new(HashMap::new()),
            index_to_hash: RwLock::new(HashMap::new()),
        };

        // Load best block hash from storage.
        let best_block_hash = match bc.storage.get(storage::COL_EXTRA, BLOCKCHAIN_BEST_BLOCK)
        {
            Ok(Some(best_hash)) => CryptoHash::new(best_hash.as_ref()),
            _ => {
                // Insert genesis block into cache.
                bc.insert_block(genesis.clone());
                bc.update_best_block(genesis);
                genesis_hash
            }
        };

        {
            let mut best_block = bc.best_block.write();
            *best_block = bc
                .get_block(&BlockId::Hash(best_block_hash))
                .expect("Not found best block in the chain");
        }

        // Load best block into cache.
        bc
    }

    pub fn best_block(&self) -> B {
        self.best_block.read().clone()
    }

    /// Check if block already is known.
    pub fn is_known(&self, hash: &CryptoHash) -> bool {
        if self.headers.read().contains_key(hash.as_ref()) {
            return true;
        }
        match self.storage.get(storage::COL_HEADERS, hash.as_ref()) {
            Ok(Some(_)) => true,
            _ => false,
        }
    }

    fn update_best_block(&self, block: B) {
        let block_hash = block.hash();
        let mut best_block = self.best_block.write();
        *best_block = block;
        let mut db_transaction = self.storage.transaction();
        db_transaction.put(
            storage::COL_EXTRA,
            BLOCKCHAIN_BEST_BLOCK,
            block_hash.as_ref(),
        );
        self.storage.write(db_transaction).expect("Database write failed");
    }

    /// Inserts a verified block.
    /// Returns true if block is disconnected.
    pub fn insert_block(&self, block: B) -> bool {
        let block_hash = block.hash();
        if self.is_known(&block_hash) {
            // TODO: known header but not known block.
            return false;
        }

        // Store block in db.
        write_with_cache(
            &self.storage,
            storage::COL_BLOCKS,
            &self.blocks,
            block_hash.as_ref(),
            &block,
        );
        write_with_cache(
            &self.storage,
            storage::COL_HEADERS,
            &self.headers,
            block_hash.as_ref(),
            &block.header(),
        );
        write_with_cache(
            &self.storage,
            storage::COL_BLOCK_INDEX,
            &self.index_to_hash,
            &index_to_bytes(block.header().index()),
            &block_hash,
        );

        let maybe_parent = self.get_header(&BlockId::Hash(block.header().parent_hash()));
        if let Some(_parent_details) = maybe_parent {
            // TODO: rewind parents if they were not processed somehow?
            if block.weight() > self.best_block.read().weight() {
                self.update_best_block(block);
            }
            false
        } else {
            true
        }
    }

    fn get_block_hash_by_index(&self, index: u64) -> Option<CryptoHash> {
        read_with_cache(
            &self.storage,
            storage::COL_BLOCK_INDEX,
            &self.index_to_hash,
            &index_to_bytes(index),
        )
    }

    fn get_block_by_hash(&self, block_hash: &CryptoHash) -> Option<B> {
        read_with_cache(
            &self.storage,
            storage::COL_BLOCKS,
            &self.blocks,
            block_hash.as_ref(),
        )
    }

    pub fn get_block(&self, id: &BlockId) -> Option<B> {
        match id {
            BlockId::Number(num) => self.get_block_by_hash(&self.get_block_hash_by_index(*num)?),
            BlockId::Hash(hash) => self.get_block_by_hash(hash),
        }
    }

    fn get_block_header_by_hash(&self, block_hash: &CryptoHash) -> Option<B::Header> {
        read_with_cache(
            &self.storage,
            storage::COL_HEADERS,
            &self.headers,
            block_hash.as_ref(),
        )
    }

    pub fn get_header(&self, id: &BlockId) -> Option<B::Header> {
        match id {
            BlockId::Number(num) => {
                self.get_block_header_by_hash(&self.get_block_hash_by_index(*num)?)
            }
            BlockId::Hash(hash) => self.get_block_header_by_hash(hash),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate beacon;

    use primitives::signer::InMemorySigner;
    use primitives::traits::{Header,Signer};
    use primitives::types::MerkleHash;
    use std::collections::HashMap;
    use storage::test_utils::create_memory_db;
    use tests::beacon::types::{AuthorityProposal, BeaconBlock};

    use super::*;

    #[test]
    fn test_genesis() {
        let storage = Arc::new(create_memory_db());
        let genesis = BeaconBlock::new(0, CryptoHash::default(), MerkleHash::default(), vec![]);
        let bc = BlockChain::new(genesis.clone(), storage);
        assert_eq!(bc.get_block(&BlockId::Hash(genesis.hash())).unwrap(), genesis);
        assert_eq!(bc.get_block(&BlockId::Number(0)).unwrap(), genesis);
    }

    #[test]
    fn test_restart_chain() {
        let storage = Arc::new(create_memory_db());
        let genesis = BeaconBlock::new(0, CryptoHash::default(), MerkleHash::default(), vec![]);
        let bc = BlockChain::new(genesis.clone(), storage.clone());
        let block1 = BeaconBlock::new(1, genesis.hash(), MerkleHash::default(), vec![]);
        assert_eq!(bc.insert_block(block1.clone()), false);
        assert_eq!(bc.best_block().hash(), block1.hash());
        assert_eq!(bc.best_block().header().index(), 1);
        // Create new BlockChain that reads from the same storage.
        let other_bc = BlockChain::new(genesis.clone(), storage.clone());
        assert_eq!(other_bc.best_block().hash(), block1.hash());
        assert_eq!(other_bc.best_block().header().index(), 1);
        assert_eq!(other_bc.get_block(&BlockId::Hash(block1.hash())).unwrap(), block1);
    }

    fn test_fork_choice_rule_helper(graph: Vec<(u32,u32,u32)>, expect: u32) {
        let storage = Arc::new(create_memory_db());
        let signers = (0..100).map(|_| InMemorySigner::new()).collect::<Vec<_>>();
        let authorities = signers.iter().map(|s| AuthorityProposal{public_key: s.public_key(), amount: 1}).collect::<Vec<_>>();

        let genesis = BeaconBlock::new(0, CryptoHash::default(), MerkleHash::default(), vec![]);
        let bc = BlockChain::new(genesis.clone(), storage.clone());
        let mut blocks: HashMap<u32, CryptoHash> = HashMap::new();
        blocks.insert(0, genesis.hash());

        for (self_id, parent_id, sign_count) in graph.iter() {
            let parent = bc.get_block_by_hash(blocks.get(parent_id).unwrap()).unwrap();
            let mut block = BeaconBlock::new(parent.header.index() + 1, parent.hash(), MerkleHash::default(), vec![]);
            for i in 0..*sign_count {
                block.header.sign(&authorities, &signers[i as usize]);
            }
            assert!(block.header.verify_signature(&authorities));
            block.update_weight(parent.weight, &authorities);
            blocks.insert(*self_id, block.hash());
            assert_eq!(bc.insert_block(block.clone()), false);
        }
        let best_hash = bc.best_block().hash();
        for i in 0..=graph.len() {
            println!("{} {}", i, blocks[&(i as u32)]);
        }
        assert_eq!(best_hash, *blocks.get(&expect).unwrap());
    }

    #[test]
    fn test_fork_choice_rule() {
        // specific examples from https://ethresear.ch/t/immediate-message-driven-ghost-as-ffg-fork-choice-rule/2561
        test_fork_choice_rule_helper(vec![(1, 0, 15), (2, 1, 16), (3, 2, 65), (4, 0, 55), (5, 4, 56)], 5);
        test_fork_choice_rule_helper(vec![(4, 0, 55), (5, 4, 56), (1, 0, 15), (2, 1, 16), (3, 2, 65)], 5);

        test_fork_choice_rule_helper(vec![(1, 0, 15), (2, 0, 65), (3, 1, 51), (4, 2, 20)], 4);

        test_fork_choice_rule_helper(vec![(1, 0, 40), (2, 0, 60), (3, 1, 51), (4, 2, 5)], 3);
    }
}
