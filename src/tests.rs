use {super::*, risc0_zkvm::sha::Impl};

#[test]
fn test_create_empty_tree() {
    let smt = Smt::<Impl>::new();
    assert_eq!(smt.get_root(), EmptySubtreeRoots::entry(LEAF_DEPTH, 0));

    let key = Key([0; 8]);
    let (value, proof) = smt.get(&key);
    assert_eq!(value, Value::EMPTY);
    assert!(proof.verify(&key, &value, smt.get_root()));
}

#[test]
fn test_insert() {
    let mut smt = Smt::<Impl>::new();
    let empty_root = *smt.get_root();

    let key_1 = Key([1, 0, 0, 0, 0, 0, 0, 0]);
    let value_1 = Value(Impl::hash_words(&[]).as_words().try_into().unwrap());

    let key_2 = Key([0, 0, 0, 0, 0, 0, 0, 1]);
    let value_2 = Value(Impl::hash_words(&[7]).as_words().try_into().unwrap());

    let old_value = insert_and_check_proof(&mut smt, key_1, value_1);
    assert_eq!(old_value, Value::EMPTY);
    let single_insert_root = *smt.get_root();

    let old_value = insert_and_check_proof(&mut smt, key_2, value_2);
    assert_eq!(old_value, Value::EMPTY);

    let removed_value = smt.remove(&key_2);
    assert_eq!(removed_value, value_2);
    assert_eq!(&single_insert_root, smt.get_root());

    let removed_value = smt.remove(&key_1);
    assert_eq!(removed_value, value_1);
    assert_eq!(&empty_root, smt.get_root());

    for key in KeyIter::default() {
        let value = Value(key.0);
        insert_and_check_proof(&mut smt, key, value);
    }
}

fn insert_and_check_proof(smt: &mut Smt<Impl>, key: Key, value: Value) -> Value {
    let old_value = smt.insert(key, value);

    let (inserted_value, proof) = smt.get(&key);
    assert_eq!(inserted_value, value);
    assert!(proof.verify(&key, &value, smt.get_root()));

    old_value
}

struct KeyIter {
    state: Key,
}

impl Default for KeyIter {
    fn default() -> Self {
        Self { state: Key([0; 8]) }
    }
}

impl KeyIter {
    const MAX_VALUE: u32 = 2;
}

impl Iterator for KeyIter {
    type Item = Key;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.0[7] > Self::MAX_VALUE {
            return None;
        }

        let result = Some(self.state);

        let mut i = 0;
        self.state.0[i] += 1;
        while (i < 7) && self.state.0[i] > Self::MAX_VALUE {
            self.state.0[i] = 0;
            i += 1;
            self.state.0[i] += 1;
        }

        result
    }
}
