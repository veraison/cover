use std::collections::HashMap;
use std::fs::{File, remove_file};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use log::debug;

use crate::result::{Error, Result};

// A store interface for keys used by the verifier.
pub trait KeyStore {
    fn add(&mut self, kid: &[u8], key: &[u8]) -> Result<()>;
    fn get(&self, kid: &[u8]) -> Result<Vec<u8>>;
    fn delete(&mut self, kid: &[u8]) -> Result<()>;
}

pub struct FsKeyStore {
    base: String,
}

// Simple [KeyStore] that uses the file system. It interprets kid as a path relative to its base (set
// on creation).
impl FsKeyStore {
    pub fn create(base: &str) -> Result<Self> {
        let path = Path::new(base);

        match path.try_exists() {
            Ok(true) => match path.is_dir() {
                true => Ok(()),
                false => Err(Error::custom(format!("path {} is not a directory", base))),
            },
            Ok(false) => Err(Error::custom(format!("directory {} does not exist", base))),
            Err(err) => Err(err.into()),
        }?;

        Ok(FsKeyStore {
            base: base.to_string(),
        })
    }

    fn key_path(&self, kid: &[u8]) -> Result<PathBuf> {
        let base_path = Path::new(self.base.as_str());
        let kid_str = std::str::from_utf8(kid)
            .map_err(|_| Error::custom("kid is not a valid UTF-8 string"))?;
        Ok(base_path.join(kid_str))
    }
}

impl KeyStore for FsKeyStore {
    fn add(&mut self, kid: &[u8], key: &[u8]) -> Result<()> {
        let key_path = self.key_path(kid)?;
        debug!("writing key to {}...", key_path.to_string_lossy());

        let mut file = File::create(key_path)?;
        file.write_all(key)?;
        file.sync_all()?;

        Ok(())
    }

    fn get(&self, kid: &[u8]) -> Result<Vec<u8>> {
        let key_path = self.key_path(kid)?;
        println!("reading key from {}...", key_path.to_string_lossy());

        let mut file = File::open(key_path)?;
        let mut buf: Vec<u8> = vec![];
        file.read_to_end(&mut buf)?;

        Ok(buf)
    }

    fn delete(&mut self, kid: &[u8]) -> Result<()> {
        let key_path = self.key_path(kid)?;
        debug!("deleting key file {}...", key_path.to_string_lossy());

        remove_file(key_path)?;

        Ok(())
    }
}

// In-memory implementation of [KeyStore].
pub struct MemKeyStore {
    items: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemKeyStore {
    pub fn new() -> Self {
        MemKeyStore {
            items: HashMap::new(),
        }
    }
}

impl KeyStore for MemKeyStore {
    fn add(&mut self, kid: &[u8], key: &[u8]) -> Result<()> {
        debug!("adding kid {:x?}", kid);
        self.items.insert(kid.to_vec(), key.to_vec());
        Ok(())
    }

    fn get(&self, kid: &[u8]) -> Result<Vec<u8>> {
        match self.items.get(kid) {
            Some(found) => Ok(found.clone()),
            None => Err(Error::KidNotFound(kid.to_vec())),
        }
    }

    fn delete(&mut self, kid: &[u8]) -> Result<()> {
        match self.items.remove(kid) {
            Some(_) => Ok(()),
            None => Err(Error::KidNotFound(kid.to_vec())),
        }
    }
}

impl Default for MemKeyStore {
    fn default() -> Self {
        Self::new()
    }
}
