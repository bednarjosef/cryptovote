//! Byte storage behind the Log: append-ordered item bytes plus a small
//! metadata map. `MemoryStore` for tests and simulation, `RedbStore` for
//! nodes (pure Rust, single file, ACID).

use redb::{Database, ReadableDatabase, TableDefinition};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage error: {0}")]
    Backend(String),
}

impl From<redb::Error> for StoreError {
    fn from(e: redb::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

macro_rules! redb_err {
    ($t:ty) => {
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self {
                StoreError::Backend(e.to_string())
            }
        }
    };
}
redb_err!(redb::DatabaseError);
redb_err!(redb::TransactionError);
redb_err!(redb::TableError);
redb_err!(redb::StorageError);
redb_err!(redb::CommitError);

pub trait Store: Send + Sync {
    fn put_item(&self, seq: u64, bytes: &[u8]) -> Result<(), StoreError>;
    fn delete_item(&self, seq: u64) -> Result<(), StoreError>;
    /// All items in sequence order.
    fn items(&self) -> Result<Vec<(u64, Vec<u8>)>, StoreError>;
    fn put_meta(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError>;
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn meta_with_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, StoreError>;
}

#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<BTreeMap<u64, Vec<u8>>>,
    meta: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn put_item(&self, seq: u64, bytes: &[u8]) -> Result<(), StoreError> {
        self.items.lock().unwrap().insert(seq, bytes.to_vec());
        Ok(())
    }
    fn delete_item(&self, seq: u64) -> Result<(), StoreError> {
        self.items.lock().unwrap().remove(&seq);
        Ok(())
    }
    fn items(&self) -> Result<Vec<(u64, Vec<u8>)>, StoreError> {
        Ok(self
            .items
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect())
    }
    fn put_meta(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.meta
            .lock()
            .unwrap()
            .insert(key.to_string(), bytes.to_vec());
        Ok(())
    }
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.meta.lock().unwrap().get(key).cloned())
    }
    fn meta_with_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        Ok(self
            .meta
            .lock()
            .unwrap()
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

const ITEMS: TableDefinition<u64, &[u8]> = TableDefinition::new("items");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        {
            txn.open_table(ITEMS)?;
            txn.open_table(META)?;
        }
        txn.commit()?;
        Ok(RedbStore { db })
    }
}

impl Store for RedbStore {
    fn put_item(&self, seq: u64, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        txn.open_table(ITEMS)?.insert(seq, bytes)?;
        txn.commit()?;
        Ok(())
    }
    fn delete_item(&self, seq: u64) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        txn.open_table(ITEMS)?.remove(seq)?;
        txn.commit()?;
        Ok(())
    }
    fn items(&self) -> Result<Vec<(u64, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(ITEMS)?;
        let mut out = Vec::new();
        for entry in t.range::<u64>(..)? {
            let (k, v) = entry?;
            out.push((k.value(), v.value().to_vec()));
        }
        Ok(out)
    }
    fn put_meta(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        txn.open_table(META)?.insert(key, bytes)?;
        txn.commit()?;
        Ok(())
    }
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        Ok(t.get(key)?.map(|v| v.value().to_vec()))
    }
    fn meta_with_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        let mut out = Vec::new();
        for entry in t.range::<&str>(prefix..)? {
            let (k, v) = entry?;
            if !k.value().starts_with(prefix) {
                break;
            }
            out.push((k.value().to_string(), v.value().to_vec()));
        }
        Ok(out)
    }
}
