//! One row of the control page's list, and what the page is sent for it.
//!
//! Its own file because `gui/mod.rs` is over the size ceiling and may not grow (`check:size`), and
//! the network name (owner, 2026-09-23) was one field more than it could take.

use nmts_crypto::manifest::Item;
use serde_json::{json, Value};

/// One row in the page's list.
pub(super) struct ItemView {
    pub(super) name: String,
    pub(super) path: String,
    pub(super) size: u64,
    parts: usize,
    /// "Walrus" or "Filecoin" — where the file is kept. The page shows it as sent.
    network: String,
}

impl ItemView {
    pub(super) fn of(i: &Item) -> Self {
        Self {
            name: i.name.clone(),
            path: i.path.clone(),
            size: i.size,
            parts: i.parts.len(),
            network: crate::restore::networks_of(i),
        }
    }

    pub(super) fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "parts": self.parts,
            "network": self.network,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page is sent the network as a person reads it, per file.
    #[test]
    fn a_row_names_where_its_file_is_kept() {
        let doc = br#"{"v":5,"generated_at":"t","account_id":"a","items":[
            {"id":"w","name":"a.txt","path":"/","size":1,"dek":"d","kind":"file",
             "parts":[{"part_index":0,"blob_id":"b","plaintext_len":1}]},
            {"id":"f","name":"b.bin","path":"/","size":1,"dek":"d","kind":"file",
             "parts":[{"part_index":0,"blob_id":"bafkzcibxyz","plaintext_len":1,
               "network":"filecoin","chain":"mainnet","copies":[{"provider_id":"1",
               "data_set_id":"2","piece_id":"3",
               "retrieval_url":"https://sp.example/piece/bafkzcibxyz"}]}]}]}"#;
        let m = nmts_crypto::manifest::RecoveryManifest::from_json(doc).expect("a v5 list");
        let rows: Vec<Value> = m.items.iter().map(|i| ItemView::of(i).to_json()).collect();
        assert_eq!(rows[0]["network"], "Walrus");
        assert_eq!(rows[1]["network"], "Filecoin");
        assert_eq!(rows[1]["parts"], 1);
    }
}
