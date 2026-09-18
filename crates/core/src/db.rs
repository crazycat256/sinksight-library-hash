use std::sync::Mutex;

use crate::hash::bytes_to_slh1;
use crate::types::{DbContents, DbHashRecord, LibInfo};

const MAGIC: &[u8; 3] = b"SLH";
const DB_VERSION: u8 = 1;

/// Handles are indices into this global vec.
static DB_STORE: Mutex<Vec<Option<Db>>> = Mutex::new(Vec::new());

pub struct Db {
    pub min_statements: u8,
    pub libs: Vec<LibEntry>,
    /// Sorted by hash bytes (binary search).
    pub file_hashes: Vec<HashEntry>,
    /// Sorted by hash bytes (binary search).
    pub func_hashes: Vec<HashEntry>,
    bloom: BloomFilter,
}

pub struct LibEntry {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Clone)]
pub struct HashEntry {
    pub hash: [u8; 32],
    pub lib_id: u16,
    pub version_index: u16,
}

pub struct LookupResult {
    pub lib_name: String,
    pub version: String,
}

struct BloomFilter {
    data: Vec<u8>,
    hash_count: u8,
}

impl BloomFilter {
    fn maybe_contains(&self, hash: &[u8; 32]) -> bool {
        if self.data.is_empty() || self.hash_count == 0 {
            return true;
        }
        let m_bits = self.data.len() as u64 * 8;
        let h1 = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);
        let h2 = u64::from_le_bytes([
            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
        ]);
        for i in 0..self.hash_count as u64 {
            let bit_pos = h1.wrapping_add(i.wrapping_mul(h2)) % m_bits;
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = (bit_pos % 8) as u8;
            if self.data[byte_idx] & (1 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    fn empty() -> Self {
        Self {
            data: Vec::new(),
            hash_count: 0,
        }
    }

    fn build(hashes: &[([u8; 32], u16, u16)]) -> Self {
        if hashes.is_empty() {
            return Self::empty();
        }
        let hash_count: u8 = 7;
        let m_bytes = (hashes.len() as u64 * 10).div_ceil(8).max(1) as usize;
        let mut data = vec![0u8; m_bytes];
        let m_bits = m_bytes as u64 * 8;
        for (hash, _, _) in hashes {
            let h1 = u64::from_le_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            let h2 = u64::from_le_bytes([
                hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
            ]);
            for i in 0..hash_count as u64 {
                let bit_pos = h1.wrapping_add(i.wrapping_mul(h2)) % m_bits;
                let byte_idx = (bit_pos / 8) as usize;
                let bit_idx = (bit_pos % 8) as u8;
                data[byte_idx] |= 1 << bit_idx;
            }
        }
        Self { data, hash_count }
    }
}

impl Db {
    pub fn lookup_file_hash(&self, hash: &[u8; 32]) -> Vec<LookupResult> {
        self.lookup_all(&self.file_hashes, hash)
    }

    pub fn lookup_func_hash(&self, hash: &[u8; 32]) -> Vec<LookupResult> {
        if !self.bloom.maybe_contains(hash) {
            return Vec::new();
        }
        self.lookup_all(&self.func_hashes, hash)
    }

    /// Binary-search for `hash`, then scan left/right to collect all entries
    /// with the same hash (the table is sorted, so duplicates are contiguous).
    fn lookup_all(&self, table: &[HashEntry], hash: &[u8; 32]) -> Vec<LookupResult> {
        let idx = match table.binary_search_by(|entry| entry.hash.cmp(hash)) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };

        let mut start = idx;
        while start > 0 && table[start - 1].hash == *hash {
            start -= 1;
        }

        let mut results = Vec::new();
        for entry in &table[start..] {
            if entry.hash != *hash {
                break;
            }
            if let Some(lib) = self.libs.get(entry.lib_id as usize) {
                if let Some(version) = lib.versions.get(entry.version_index as usize) {
                    results.push(LookupResult {
                        lib_name: lib.name.clone(),
                        version: version.clone(),
                    });
                }
            }
        }
        results
    }
}

pub fn load_db(data: &[u8]) -> Result<u32, String> {
    let db = parse_db(data)?;
    let mut store = DB_STORE.lock().unwrap();
    for (i, slot) in store.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(db);
            return Ok(i as u32);
        }
    }
    let idx = store.len();
    store.push(Some(db));
    Ok(idx as u32)
}

pub fn free_db(handle: u32) {
    let mut store = DB_STORE.lock().unwrap();
    if let Some(slot) = store.get_mut(handle as usize) {
        *slot = None;
    }
}

pub fn with_db<F, R>(handle: u32, f: F) -> Option<R>
where
    F: FnOnce(&Db) -> R,
{
    let store = DB_STORE.lock().unwrap();
    store
        .get(handle as usize)
        .and_then(|slot| slot.as_ref())
        .map(f)
}

/// Extract all libraries and hash records from a loaded database.
pub fn extract_db_contents(handle: u32) -> Option<DbContents> {
    with_db(handle, |db| {
        let libs: Vec<LibInfo> = db
            .libs
            .iter()
            .map(|lib| LibInfo {
                name: lib.name.clone(),
                versions: lib.versions.clone(),
            })
            .collect();

        let resolve = |entry: &HashEntry| -> Option<DbHashRecord> {
            let lib = db.libs.get(entry.lib_id as usize)?;
            let version = lib.versions.get(entry.version_index as usize)?;
            Some(DbHashRecord {
                hash: bytes_to_slh1(&entry.hash),
                lib: lib.name.clone(),
                version: version.clone(),
            })
        };

        let file_hashes: Vec<DbHashRecord> = db.file_hashes.iter().filter_map(resolve).collect();
        let func_hashes: Vec<DbHashRecord> = db.func_hashes.iter().filter_map(resolve).collect();

        DbContents {
            libs,
            file_hashes,
            func_hashes,
        }
    })
}

fn parse_db(data: &[u8]) -> Result<Db, String> {
    if data.len() < 17 {
        return Err("Database too small for header".into());
    }

    // Header
    if &data[0..3] != MAGIC {
        return Err(format!(
            "Invalid magic number: expected SLH, got {:?}",
            &data[0..3]
        ));
    }

    let db_version = data[3];
    if db_version != DB_VERSION {
        return Err(format!(
            "Unsupported DB version: expected {DB_VERSION}, got {db_version}. \
             Hash algorithm version mismatch - the DB was built with a different slh version."
        ));
    }

    let min_statements = data[4];
    let lib_count = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
    let file_hash_count = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);
    let func_hash_count = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);

    let mut offset = 17usize;

    let mut libs = Vec::with_capacity(lib_count as usize);
    for _ in 0..lib_count {
        if offset + 3 > data.len() {
            return Err("Truncated lib table".into());
        }
        let _lib_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let name_len = data[offset] as usize;
        offset += 1;
        if offset + name_len > data.len() {
            return Err("Truncated lib name".into());
        }
        let name = String::from_utf8(data[offset..offset + name_len].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in lib name: {e}"))?;
        offset += name_len;

        if offset + 2 > data.len() {
            return Err("Truncated version count".into());
        }
        let version_count = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut versions = Vec::with_capacity(version_count as usize);
        for _ in 0..version_count {
            if offset + 1 > data.len() {
                return Err("Truncated version entry".into());
            }
            let version_len = data[offset] as usize;
            offset += 1;
            if offset + version_len > data.len() {
                return Err("Truncated version string".into());
            }
            let version = String::from_utf8(data[offset..offset + version_len].to_vec())
                .map_err(|e| format!("Invalid UTF-8 in version: {e}"))?;
            offset += version_len;
            versions.push(version);
        }

        libs.push(LibEntry { name, versions });
    }

    let file_hash_expected_size = file_hash_count as usize * 36;
    if offset + file_hash_expected_size > data.len() {
        return Err("Truncated file hash table".into());
    }
    let mut file_hashes = Vec::with_capacity(file_hash_count as usize);
    for _ in 0..file_hash_count {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        let lib_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        let version_index = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        file_hashes.push(HashEntry {
            hash,
            lib_id,
            version_index,
        });
    }

    let func_hash_expected_size = func_hash_count as usize * 36;
    if offset + func_hash_expected_size > data.len() {
        return Err("Truncated function hash table".into());
    }
    let mut func_hashes = Vec::with_capacity(func_hash_count as usize);
    for _ in 0..func_hash_count {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        let lib_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        let version_index = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        func_hashes.push(HashEntry {
            hash,
            lib_id,
            version_index,
        });
    }

    for w in file_hashes.windows(2) {
        if w[0].hash > w[1].hash {
            return Err("File hash table is not sorted".into());
        }
    }
    for w in func_hashes.windows(2) {
        if w[0].hash > w[1].hash {
            return Err("Function hash table is not sorted".into());
        }
    }

    validate_parsed_hash_refs("file hash", &libs, &file_hashes)?;
    validate_parsed_hash_refs("function hash", &libs, &func_hashes)?;

    let bloom = if offset + 5 <= data.len() {
        let bloom_size = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let bloom_hash_count = data[offset];
        offset += 1;
        if bloom_size > 0 {
            if offset + bloom_size > data.len() {
                return Err("Truncated bloom filter data".into());
            }
            BloomFilter {
                data: data[offset..offset + bloom_size].to_vec(),
                hash_count: bloom_hash_count,
            }
        } else {
            BloomFilter::empty()
        }
    } else {
        BloomFilter::empty()
    };

    Ok(Db {
        min_statements,
        libs,
        file_hashes,
        func_hashes,
        bloom,
    })
}

pub fn build_db(
    min_statements: u8,
    libs: &[(String, Vec<String>)],
    file_hashes: Vec<([u8; 32], u16, u16)>,
    func_hashes: Vec<([u8; 32], u16, u16)>,
) -> Vec<u8> {
    try_build_db(min_statements, libs, file_hashes, func_hashes)
        .expect("invalid .slhdb build inputs")
}

pub fn try_build_db(
    min_statements: u8,
    libs: &[(String, Vec<String>)],
    mut file_hashes: Vec<([u8; 32], u16, u16)>,
    mut func_hashes: Vec<([u8; 32], u16, u16)>,
) -> Result<Vec<u8>, String> {
    validate_build_inputs(libs, &file_hashes, &func_hashes)?;

    file_hashes.sort_by_key(|entry| entry.0);
    func_hashes.sort_by_key(|entry| entry.0);

    let mut buf = Vec::new();

    buf.extend_from_slice(MAGIC);
    buf.push(DB_VERSION);
    buf.push(min_statements);
    buf.extend_from_slice(&(libs.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(file_hashes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(func_hashes.len() as u32).to_le_bytes());

    for (i, (name, versions)) in libs.iter().enumerate() {
        buf.extend_from_slice(&(i as u16).to_le_bytes());
        buf.push(name.len() as u8);
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&(versions.len() as u16).to_le_bytes());
        for v in versions {
            buf.push(v.len() as u8);
            buf.extend_from_slice(v.as_bytes());
        }
    }

    for (hash, lib_id, version_index) in &file_hashes {
        buf.extend_from_slice(hash);
        buf.extend_from_slice(&lib_id.to_le_bytes());
        buf.extend_from_slice(&version_index.to_le_bytes());
    }

    for (hash, lib_id, version_index) in &func_hashes {
        buf.extend_from_slice(hash);
        buf.extend_from_slice(&lib_id.to_le_bytes());
        buf.extend_from_slice(&version_index.to_le_bytes());
    }

    let bloom = BloomFilter::build(&func_hashes);
    buf.extend_from_slice(&(bloom.data.len() as u32).to_le_bytes());
    buf.push(bloom.hash_count);
    buf.extend_from_slice(&bloom.data);

    Ok(buf)
}

fn validate_build_inputs(
    libs: &[(String, Vec<String>)],
    file_hashes: &[([u8; 32], u16, u16)],
    func_hashes: &[([u8; 32], u16, u16)],
) -> Result<(), String> {
    if libs.len() > u16::MAX as usize + 1 {
        return Err(format!(
            "too many libraries for .slhdb v1: {} > {}",
            libs.len(),
            u16::MAX as usize + 1
        ));
    }

    for (lib_index, (name, versions)) in libs.iter().enumerate() {
        if name.len() > u8::MAX as usize {
            return Err(format!(
                "library name at index {lib_index} is too long for .slhdb v1: {} bytes > {}",
                name.len(),
                u8::MAX
            ));
        }
        if versions.len() > u16::MAX as usize {
            return Err(format!(
                "library `{name}` has too many versions for .slhdb v1: {} > {}",
                versions.len(),
                u16::MAX
            ));
        }
        for version in versions {
            if version.len() > u8::MAX as usize {
                return Err(format!(
                    "version `{version}` for library `{name}` is too long for .slhdb v1: {} bytes > {}",
                    version.len(),
                    u8::MAX
                ));
            }
        }
    }

    validate_hash_refs("file hash", libs, file_hashes)?;
    validate_hash_refs("function hash", libs, func_hashes)
}

fn validate_hash_refs(
    label: &str,
    libs: &[(String, Vec<String>)],
    hashes: &[([u8; 32], u16, u16)],
) -> Result<(), String> {
    for (_, lib_id, version_index) in hashes {
        let Some((name, versions)) = libs.get(*lib_id as usize) else {
            return Err(format!(
                "{label} references missing library id {lib_id}; database has {} libraries",
                libs.len()
            ));
        };
        if versions.get(*version_index as usize).is_none() {
            return Err(format!(
                "{label} references missing version index {version_index} for library `{name}`; library has {} versions",
                versions.len()
            ));
        }
    }
    Ok(())
}

fn validate_parsed_hash_refs(
    label: &str,
    libs: &[LibEntry],
    hashes: &[HashEntry],
) -> Result<(), String> {
    for entry in hashes {
        let Some(lib) = libs.get(entry.lib_id as usize) else {
            return Err(format!(
                "{label} table references missing library id {}; database has {} libraries",
                entry.lib_id,
                libs.len()
            ));
        };
        if lib.versions.get(entry.version_index as usize).is_none() {
            return Err(format!(
                "{label} table references missing version index {} for library `{}`; library has {} versions",
                entry.version_index,
                lib.name,
                lib.versions.len()
            ));
        }
    }
    Ok(())
}
