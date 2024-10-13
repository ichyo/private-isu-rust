use std::fmt::Debug;

use async_trait::async_trait;
use tower_sessions::{
    cookie::time::OffsetDateTime,
    session::{Id, Record},
    session_store, SessionStore,
};

#[derive(Clone)]
pub struct MemcachedStore(memcache::Client);

impl Debug for MemcachedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemcachedStore").finish()
    }
}

impl MemcachedStore {
    pub fn new(client: memcache::Client) -> Self {
        Self(client)
    }
}

#[async_trait]
impl SessionStore for MemcachedStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        let expire_secs = (record.expiry_date - OffsetDateTime::now_utc())
            .whole_seconds()
            .max(0);
        let data =
            rmp_serde::to_vec(record).map_err(|e| session_store::Error::Encode(e.to_string()))?;
        self.0
            .add(&record.id.to_string(), data.as_slice(), expire_secs as u32)
            .map_err(|e| session_store::Error::Backend(e.to_string()))?;
        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        let expire_secs = (record.expiry_date - OffsetDateTime::now_utc())
            .whole_seconds()
            .max(0);
        let data =
            rmp_serde::to_vec(record).map_err(|e| session_store::Error::Encode(e.to_string()))?;
        self.0
            .set(&record.id.to_string(), data.as_slice(), expire_secs as u32)
            .map_err(|e| session_store::Error::Backend(e.to_string()))?;
        Ok(())
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let data = self
            .0
            .get::<Vec<u8>>(&session_id.to_string())
            .map_err(|e| session_store::Error::Backend(e.to_string()))?;

        let data = match data {
            Some(data) => {
                let record: Record = rmp_serde::from_slice(&data)
                    .map_err(|e| session_store::Error::Decode(e.to_string()))?;
                Some(record)
            }
            None => None,
        };

        Ok(data)
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        self.0
            .delete(&session_id.to_string())
            .map_err(|e| session_store::Error::Backend(e.to_string()))?;
        Ok(())
    }
}
