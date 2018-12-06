use primitives::hash::{hash_struct, CryptoHash};
use primitives::signature::{PublicKey, Signature, verify_signature};
use primitives::traits::{Block, Header, Signer};
use primitives::types::{MerkleHash, SignedTransaction};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AuthorityProposal {
    /// Public key of the proposed authority.
    pub public_key: PublicKey,
    /// Stake / weight of the authority.
    pub amount: u64,
}

//pub struct BeaconBlockBody {
//    /// Parent hash.
//    pub parent_hash: CryptoHash,
//    /// Block index.
//    pub index: u64,
//    /// Authority proposals.
//    pub authority_proposal: Vec<AuthorityProposal>,
//    /// Shard block hash.
//    pub shard_block_hash: CryptoHash,
//}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BeaconBlockHeaderBody {
    /// Parent hash.
    pub parent_hash: CryptoHash,
    /// Block index.
    pub index: u64,
    pub merkle_root_tx: MerkleHash,
    pub merkle_root_state: MerkleHash,
    pub authority_proposal: Vec<AuthorityProposal>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    pub body: BeaconBlockHeaderBody,
    pub signatures: Vec<Signature>,
    pub authority_mask: Vec<bool>,
}

impl BeaconBlockHeader {
    pub fn new(
        index: u64,
        parent_hash: CryptoHash,
        merkle_root_tx: MerkleHash,
        merkle_root_state: MerkleHash,
        signatures: Vec<Signature>,
        authority_mask: Vec<bool>,
        authority_proposal: Vec<AuthorityProposal>,
    ) -> Self {
        BeaconBlockHeader {
            body: BeaconBlockHeaderBody {
                index,
                parent_hash,
                merkle_root_tx,
                merkle_root_state,
                authority_proposal,
            },
            signatures,
            authority_mask,
        }
    }
    pub fn empty(index: u64, parent_hash: CryptoHash, merkle_root_state: MerkleHash) -> Self {
        BeaconBlockHeader {
            body: BeaconBlockHeaderBody {
                index,
                parent_hash,
                merkle_root_tx: MerkleHash::default(),
                merkle_root_state,
                authority_proposal: vec![],
            },
            signatures: vec![],
            authority_mask: vec![],
        }
    }
    // Since the signature is contained in the header, we need a hash that omits it
    pub fn hash_for_signing(&self) -> CryptoHash {
        hash_struct(&self.body)
    }

    pub fn sign(&mut self, authorities: &Vec<AuthorityProposal>, signer: &dyn Signer) -> bool {
        let sig = signer.sign(&self.hash_for_signing());
        let mut ret = false;
        if self.authority_mask.len() < authorities.len() {
            self.authority_mask.resize(authorities.len(), false);
        }
        let mut insert_pos = 0;
        for (present, authority) in self.authority_mask.iter_mut().zip(authorities.iter()) {
            if *present {
                insert_pos += 1;
                continue;
            }
            if signer.public_key() != authority.public_key {
                continue;
            }
            self.signatures.insert(insert_pos, sig);
            *present = true;
            insert_pos += 1;
            ret = true;
        }
        ret
    }

    pub fn verify_signature(&self, authorities: &Vec<AuthorityProposal>) -> bool {
        if self.authority_mask.len() != authorities.len() {
            return false;
        }
        if self.signatures.is_empty() {
            return false;
        }
        let hash = self.hash_for_signing();
        let mut signature_pos = 0;
        for (present, authority) in self.authority_mask.iter().zip(authorities.iter()) {
            if *present {
                if signature_pos >= self.signatures.len() {
                    return false;
                }
                if !verify_signature(&self.signatures[signature_pos], &hash, &authority.public_key) {
                    return false;
                }
                signature_pos += 1;
            }
        }
        signature_pos == self.signatures.len()
    }

    pub fn signature_weight(&self, authorities: &Vec<AuthorityProposal>) -> u64 {
        self.authority_mask.iter().zip(authorities.iter()).filter(|x| *x.0).map(|x| x.1.amount).sum()
    }
}

impl Header for BeaconBlockHeader {
    fn hash(&self) -> CryptoHash {
        hash_struct(&self)
    }

    fn index(&self) -> u64 {
        self.body.index
    }

    fn parent_hash(&self) -> CryptoHash {
        self.body.parent_hash
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BeaconBlock {
    pub header: BeaconBlockHeader,
    pub transactions: Vec<SignedTransaction>,
    pub weight: u128,
}

impl BeaconBlock {
    pub fn new(
        index: u64,
        parent_hash: CryptoHash,
        merkle_root_state: MerkleHash,
        transactions: Vec<SignedTransaction>,
    ) -> Self {
        // TODO setting weight to index is a dirty hack to make tests easier to write
        let weight = index as u128;
        BeaconBlock {
            header: BeaconBlockHeader::empty(index, parent_hash, merkle_root_state),
            transactions,
            weight, // weight
        }
    }

    pub fn update_weight(&mut self, parent_weight: u128, authorities: &Vec<AuthorityProposal>) {
        self.weight = parent_weight + self.header.signature_weight(authorities) as u128;
    }
}

impl Block for BeaconBlock {
    type Header = BeaconBlockHeader;
    type Body = Vec<SignedTransaction>;
    type Weight = u128;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn body(&self) -> &Self::Body {
        &self.transactions
    }

    fn deconstruct(self) -> (Self::Header, Self::Body) {
        (self.header, self.transactions)
    }

    fn new(header: Self::Header, body: Self::Body) -> Self {
        // TODO setting weight to index is a dirty hack to make tests easier to write
        let weight = header.index() as u128;
        BeaconBlock { header, transactions: body, weight }
    }

    fn hash(&self) -> CryptoHash {
        self.header.hash()
    }

    fn weight(&self) -> u128 {
        self.weight
    }
}
