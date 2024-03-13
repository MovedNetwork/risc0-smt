use {
    self::leaf::{key_to_leaf_index, SmtLeaf, LEAF_DEPTH},
    empty_roots::EmptySubtreeRoots,
    leaf::LeafIndex,
    risc0_zkvm::sha::{Digest, Sha256},
    std::{
        borrow::Cow,
        collections::{btree_map::Entry, BTreeMap},
        marker::PhantomData,
        ops::Deref,
    },
};

mod empty_roots;
pub mod leaf;
#[cfg(test)]
mod tests;

/// A key-value store with cryptographic proofs of inclusion.
/// The keys and values are both 256-bit.
/// The data structure is based on a sparse merkle tree where
/// all leaves exist at depth 64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smt<H: Sha256> {
    hasher: PhantomData<H>,
    root: H::DigestPtr,
    leaves: BTreeMap<u64, SmtLeaf<H>>,
    inner_nodes: BTreeMap<NodeIndex, InnerNode>,
}

impl<H: Sha256> Default for Smt<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Sha256> Smt<H> {
    pub fn new() -> Self {
        let empty_subtree = EmptySubtreeRoots::entry(LEAF_DEPTH, 1);
        let root = H::hash_pair(empty_subtree, empty_subtree);
        Self {
            hasher: PhantomData,
            root,
            leaves: BTreeMap::new(),
            inner_nodes: BTreeMap::new(),
        }
    }

    /// Get the value associated with the key, along with a proof this lookup is correct.
    /// Note: by default all keys are associated with `Value::EMPTY`.
    pub fn get(&self, key: &Key) -> (Value, SmtProof<H>) {
        let leaf_index = key_to_leaf_index(key);
        let leaf = self
            .leaves
            .get(&leaf_index.value)
            .cloned()
            .unwrap_or_else(|| SmtLeaf::new(leaf_index));
        let value = leaf.get_direct(key).copied().unwrap_or(Value::EMPTY);

        let mut index: NodeIndex = leaf_index.into();
        // Get all the sibling nodes to include in the path
        let path_nodes: Vec<Digest> = (0..LEAF_DEPTH)
            .map(|_| {
                let side = index.get_side();
                index.move_up();
                let inner_node = self.get_inner_node(&index);
                let InnerNode { left, right } = inner_node.as_ref();
                match side {
                    Side::Left => *right,
                    Side::Right => *left,
                }
            })
            .collect();

        let proof = SmtProof {
            path: MerklePath::new(path_nodes),
            leaf,
        };
        (value, proof)
    }

    /// Insert a key-value pair into the SMT, returning the old value
    /// associated with that key.
    /// Note: by default all keys are associated with `Value::EMPTY`.
    pub fn insert(&mut self, key: Key, value: Value) -> Value {
        if value == Value::EMPTY {
            return self.remove(&key);
        }

        let leaf_index = key_to_leaf_index(&key);

        let leaf = self
            .leaves
            .entry(leaf_index.value)
            .or_insert_with(|| SmtLeaf::new(leaf_index));
        let old_value = leaf.insert(key, value);

        if old_value == value {
            return value;
        }

        let leaf_hash = leaf.hash();
        self.recompute_nodes_from_leaf_to_root(leaf_index, leaf_hash);

        old_value
    }

    /// Remove a key from the SMT.
    /// Note: even after this operation the key is associated with `Value::EMPTY`.
    pub fn remove(&mut self, key: &Key) -> Value {
        let leaf_index = key_to_leaf_index(key);

        let (old_value, leaf_hash) = match self.leaves.entry(leaf_index.value) {
            Entry::Vacant(_) => return Value::EMPTY,
            Entry::Occupied(mut leaf) => {
                let old_value = match leaf.get_mut().remove(key) {
                    None => return Value::EMPTY,
                    Some(old_value) => old_value,
                };
                (old_value, leaf.get().hash())
            }
        };

        self.recompute_nodes_from_leaf_to_root(leaf_index, leaf_hash);

        old_value
    }

    /// Get the root of the SMT.
    pub fn get_root(&self) -> &Digest {
        &self.root
    }

    fn recompute_nodes_from_leaf_to_root(
        &mut self,
        leaf_index: LeafIndex,
        leaf_hash: Option<H::DigestPtr>,
    ) {
        let (mut node_hash, mut index): (H::DigestPtr, NodeIndex) = match leaf_hash {
            Some(digest) => (digest, leaf_index.into()),
            None => {
                let node_hash = &Digest::ZERO;
                let mut index: NodeIndex = leaf_index.into();
                let side = index.get_side();
                index.move_up();
                let inner_node = self.get_inner_node(&index);
                let InnerNode { left, right } = inner_node.as_ref();
                let (left, right) = match side {
                    Side::Left => (node_hash, right),
                    Side::Right => (left, node_hash),
                };
                (H::hash_pair(left, right), index)
            }
        };
        for node_depth in (0..index.depth).rev() {
            let side = index.get_side();
            index.move_up();
            let inner_node = self.get_inner_node(&index);
            let InnerNode { left, right } = inner_node.as_ref();
            let (left, right) = match side {
                Side::Left => (node_hash.deref(), right),
                Side::Right => (left, node_hash.deref()),
            };
            let new_inner_node = InnerNode {
                left: *left,
                right: *right,
            };
            node_hash = H::hash_pair(left, right);

            if node_hash.deref() == EmptySubtreeRoots::entry(LEAF_DEPTH, node_depth) {
                self.inner_nodes.remove(&index);
            } else {
                self.inner_nodes.insert(index, new_inner_node);
            }
        }
        self.root = node_hash;
    }

    fn get_inner_node<'a>(&'a self, index: &NodeIndex) -> Cow<'a, InnerNode> {
        self.inner_nodes
            .get(index)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| {
                let node = EmptySubtreeRoots::entry(LEAF_DEPTH, index.depth + 1);
                Cow::Owned(InnerNode {
                    left: *node,
                    right: *node,
                })
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key(pub [u32; 8]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Value(pub [u32; 8]);

impl Value {
    pub const EMPTY: Self = Value([0; 8]);

    pub const fn empty() -> &'static Self {
        &Self::EMPTY
    }
}

pub struct SmtProof<H> {
    pub path: MerklePath,
    pub leaf: SmtLeaf<H>,
}

impl<H: Sha256> SmtProof<H> {
    pub fn verify(&self, key: &Key, value: &Value, root: &Digest) -> bool {
        let leaf_value = match self.leaf.get(key) {
            Some(v) => v,
            None => return false,
        };

        if leaf_value != value {
            return false;
        }

        let proof_root = self.compute_root();

        proof_root.deref() == root
    }

    pub fn compute_root(&self) -> H::DigestPtr {
        let leaf_hash = self.leaf.hash();
        self.path.compute_root::<H>(
            self.leaf.index().value,
            leaf_hash.as_deref().unwrap_or(&Digest::ZERO),
        )
    }
}

pub struct MerklePath {
    pub nodes: Vec<Digest>,
}

impl MerklePath {
    pub fn new(nodes: Vec<Digest>) -> Self {
        Self { nodes }
    }

    pub fn compute_root<H: Sha256>(&self, index: u64, init_hash: &Digest) -> H::DigestPtr {
        let mut index = NodeIndex {
            depth: self.nodes.len() as u8,
            value: index,
        };
        let mut nodes = self.nodes.iter();
        let side = index.get_side();
        index.move_up();
        let sibling = nodes.next().expect("Merkle Path must not be empty");
        let init_hash = match side {
            Side::Left => H::hash_pair(init_hash, sibling),
            Side::Right => H::hash_pair(sibling, init_hash),
        };
        nodes.fold(init_hash, |node, sibling| {
            let side = index.get_side();
            index.move_up();
            match side {
                Side::Left => H::hash_pair(&node, sibling),
                Side::Right => H::hash_pair(sibling, &node),
            }
        })
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NodeIndex {
    depth: u8,
    value: u64,
}

impl NodeIndex {
    pub fn move_up(&mut self) {
        self.depth -= 1;
        self.value /= 2;
    }

    pub fn get_side(&self) -> Side {
        if self.value % 2 == 0 {
            Side::Left
        } else {
            Side::Right
        }
    }
}

enum Side {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InnerNode {
    left: Digest,
    right: Digest,
}
