// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use consensus_types::{
    quorum_cert::QuorumCert,
};
use libra_crypto::HashValue;
use libra_logger::prelude::*;
use libra_trace::prelude::*;
use libra_types::{
    block_info::Round,
};

use schemadb::{ColumnFamilyName, ReadOptions, SchemaBatch, DB, DEFAULT_CF_NAME};
use std::{collections::HashMap, iter::Iterator, path::Path, time::Instant};
use crate::consensusdb::QCSchema;
use libra_infallible::RwLock;

const QC_CF_NAME: ColumnFamilyName = "quorum_certificate";

/// Forensic
pub trait ForensicStorage: Send + Sync {
    /// Forensic
    fn save_quorum_cert(&self, quorum_certs: &[QuorumCert]) -> Result<()>;
    /// Forensic
    fn get_quorum_cert_at_round(&self, round: Round) -> Result<Vec<QuorumCert>>;
}

/// Forensic
pub struct ForensicDB {
    db: DB,
    round_to_qcs: RwLock<HashMap<Round,Vec<HashValue>>>
}

impl ForensicDB {
    /// Forensic
    pub fn new<P: AsRef<Path> + Clone>(db_root_path: P) -> Self {
        let column_families = vec![
            /* UNUSED CF = */ DEFAULT_CF_NAME,
            QC_CF_NAME,
        ];

        let path = db_root_path.as_ref().join("forensicdb");
        let instant = Instant::now();
        let db = DB::open(path.clone(), "forensic", column_families)
            .expect("ForensicDB open failed; unable to continue");
        let mut round_to_qcs: HashMap<Round,Vec<HashValue>> = HashMap::new();
        {
            let mut iter = db.iter::<QCSchema>(ReadOptions::default()).expect("ForensicDB iteration failed");
            iter.seek_to_first();
            let hashmap: HashMap<HashValue, QuorumCert> = iter.collect::<Result<HashMap<HashValue, QuorumCert>>>().expect("ForensicDB iteration failed");
            for qc in hashmap.values() {
                let round = qc.vote_data().proposed().round();
                round_to_qcs.entry(round).or_default().push(qc.vote_data().proposed().id());
            }
        }

        info!(
            "Opened ForensicDB at {:?} in {} ms",
            path,
            instant.elapsed().as_millis()
        );

        let round_to_qcs = RwLock::new(round_to_qcs);
        Self { db, round_to_qcs }
    }

    /// Get QC
    fn get_quorum_cert(&self, hash: &HashValue) -> Result<Option<QuorumCert>> {
        self.db.get::<QCSchema>(hash)
    }
}

impl ForensicStorage for ForensicDB {

    fn save_quorum_cert(
        &self,
        qc_data: &[QuorumCert],
    ) -> Result<()> {
        if qc_data.is_empty() {
            return Err(anyhow::anyhow!("qc data is empty!").into());
        }
        let mut batch = SchemaBatch::new();
        qc_data
            .iter()
            .map(|qc| batch.put::<QCSchema>(&qc.vote_data().proposed().id(), qc))
            .collect::<Result<()>>()?;
        self.db.write_schemas(batch)?;
        let mut round_to_qcs = self.round_to_qcs.write();
        qc_data.iter().for_each(|qc|
            round_to_qcs.entry(qc.vote_data().proposed().round()).or_default().push(qc.vote_data().proposed().id())
        );
        Ok(())
    }

    fn get_quorum_cert_at_round(&self, round: u64) -> Result<Vec<QuorumCert>> {
        let round_to_qcs = self.round_to_qcs.read();
        if let Some(hashes) = round_to_qcs.get(&round) {
            let mut v = Vec::new();
            for h in hashes.iter() {//.map(|h| {
                let qc: Option<QuorumCert> = self.get_quorum_cert(h)?;
                qc.map(|x|v.push(x));
            }
            Ok(v)
        } else {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use consensus_types::block::block_test_utils::certificate_for_genesis;
    use libra_temppath::TempPath;

    #[test]
    fn test_put_get() {
        let tmp_dir = TempPath::new();
        let db = ForensicDB::new(&tmp_dir);

        let qcs = vec![certificate_for_genesis()];
        db.save_quorum_cert(&qcs)
            .unwrap();

        assert_eq!(db.get_quorum_cert_at_round(0).unwrap().len(), 1);
    }
}