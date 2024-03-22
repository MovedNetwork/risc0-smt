use {
    crate::{Key, NodeIndex, Value},
    risc0_zkvm::sha::Sha256,
    std::{collections::BTreeMap, marker::PhantomData},
};

pub const LEAF_DEPTH: u8 = 64;

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SmtLeaf<H> {
    index: LeafIndex,
    kvs: BTreeMap<Key, Value>,
    hasher: PhantomData<H>,
}

impl<H> Clone for SmtLeaf<H> {
    fn clone(&self) -> Self {
        Self {
            index: self.index,
            kvs: self.kvs.clone(),
            hasher: PhantomData,
        }
    }
}

impl<H> SmtLeaf<H> {
    pub const fn new(index: LeafIndex) -> Self {
        Self {
            index,
            kvs: BTreeMap::new(),
            hasher: PhantomData,
        }
    }

    pub fn new_single(key: Key, value: Value) -> Self {
        let index = key_to_leaf_index(&key);
        let mut kvs = BTreeMap::new();
        kvs.insert(key, value);
        Self {
            index,
            kvs,
            hasher: PhantomData,
        }
    }

    /// If the index of the given key matches the index of this leaf
    /// then get the associated value (returning the default value if
    /// none is already present).
    pub fn get(&self, key: &Key) -> Option<&Value> {
        if key_to_leaf_index(key) != self.index {
            return None;
        }

        Some(self.kvs.get(key).unwrap_or(Value::empty()))
    }

    /// Must only be called with keys that map to the leaf's index.
    pub(super) fn get_direct(&self, key: &Key) -> Option<&Value> {
        debug_assert_eq!(key_to_leaf_index(key), self.index);
        self.kvs.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.kvs.is_empty()
    }

    pub fn index(&self) -> LeafIndex {
        self.index
    }

    pub fn insert(&mut self, key: Key, value: Value) -> Value {
        // Invariant: all keys in the one leaf have the same index
        debug_assert_eq!(key_to_leaf_index(&key), self.index);

        self.kvs.insert(key, value).unwrap_or(Value::EMPTY)
    }

    pub fn remove(&mut self, key: &Key) -> Option<Value> {
        self.kvs.remove(key)
    }
}

impl<H: Sha256> SmtLeaf<H> {
    pub fn hash(&self) -> Option<H::DigestPtr> {
        let words: Vec<u32> = self
            .kvs
            .iter()
            .flat_map(|(k, v)| {
                let mut buf = [0; 16];
                buf[0..8].copy_from_slice(&k.0);
                buf[8..16].copy_from_slice(&v.0);
                buf
            })
            .collect();
        if words.is_empty() {
            None
        } else {
            Some(H::hash_words(&words))
        }
    }
}

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct LeafIndex {
    pub value: u64,
}

impl From<LeafIndex> for NodeIndex {
    fn from(leaf: LeafIndex) -> Self {
        Self {
            depth: LEAF_DEPTH,
            value: leaf.value,
        }
    }
}

pub(super) fn key_to_leaf_index(key: &Key) -> LeafIndex {
    let mut value = [0u8; 8];
    // TODO: byte order?
    value[0..4].copy_from_slice(&key.0[6].to_le_bytes());
    value[4..8].copy_from_slice(&key.0[7].to_le_bytes());
    LeafIndex {
        value: u64::from_le_bytes(value),
    }
}
