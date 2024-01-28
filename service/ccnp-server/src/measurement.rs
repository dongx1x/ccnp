use anyhow::Error;
use cctrusted_base::tcg::{IMA_MEASUREMENT_EVENT, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384};
use openssl::hash::Hasher;
use regex::Regex;
use std::collections::HashMap;
use std::fs;

use crate::{
    ccnp_pb::{TcgDigest, TcgImrEvent},
    policy::PolicyConfig,
};

#[derive(Clone)]
pub struct Measurement {
    policy: PolicyConfig,
    imr: TcgDigest,
    eventlogs: Vec<TcgImrEvent>,
}

impl Measurement {
    pub fn new(mut policy: PolicyConfig) -> Measurement {
        let algo_id: u32 = match policy.get_alogrithm().as_str() {
            "sha1" => TPM_ALG_SHA1.into(),
            "sha256" => TPM_ALG_SHA256.into(),
            "sha384" => TPM_ALG_SHA384.into(),
            _ => 0,
        };

        let algo_len = match policy.get_alogrithm().as_str() {
            "sha1" => 20,
            "sha256" => 32,
            "sha384" => 48,
            _ => 0,
        };

        let hash = vec![0; algo_len];

        Measurement {
            policy,
            imr: TcgDigest { algo_id, hash },
            eventlogs: vec![],
        }
    }

    pub fn get_imr(&mut self) -> TcgDigest {
        self.imr.clone()
    }

    pub fn get_eventlogs(&mut self) -> Vec<TcgImrEvent> {
        self.eventlogs.clone()
    }

    fn extend_imr(&mut self, val: &[u8],) -> Result<(), Error> {
        let mut hasher = Hasher::new(self.imr.clone().into()).expect("Hasher initialzation failed");
        hasher.update(&val).expect("Hasher update failed");
        let val_hash = hasher.finish().expect("Hasher finish failed").to_vec();

        let new_val = [self.imr.hash.clone(), val_hash.to_vec()].concat();
        hasher.update(&new_val).expect("Hasher update failed");
        self.imr.hash = hasher.finish().expect("Hasher finish failed").to_vec();

        let digests: Vec<TcgDigest> = vec![TcgDigest {
            algo_id: self.imr.algo_id,
            hash: val_hash.to_vec(),
        }];
        let eventlog = TcgImrEvent {
            imr_index: 3,
            event_type: IMA_MEASUREMENT_EVENT,
            event_size: val.len().try_into().unwrap(),
            event: val.to_vec(),
            digests,
            digest:vec![]
        };

        self.eventlogs.push(eventlog);

        Ok(())
    }

    fn get_processes(&mut self, procfs: String) -> Result<HashMap<String, String>, Error> {
        let mut processes = HashMap::new();
        let pattern = Regex::new(r".*/[0-9]").unwrap();
        let paths = fs::read_dir(procfs)
            .unwrap()
            .map(|r| r.unwrap().path())
            .filter(|r| pattern.is_match(r.to_str().unwrap()));

        for path in paths {
            let cmdline_path = path.to_str().unwrap().to_owned() + "/cmdline";
            let cmdline =
                fs::read_to_string(cmdline_path).expect("Failed to read process cmdline.");

            if cmdline.is_empty() {
                continue;
            }

            let (name, parameter) = cmdline.split_once('\0').unwrap();
            processes.insert(name.to_string(), parameter.to_string());
        }

        Ok(processes)
    }

    fn measure_system(&mut self) -> Result<(), Error> {
        let processes = self.get_processes("/proc".to_string()).unwrap();
        let process_policy = self.policy.get_system_processes();
        for p in process_policy {
            if processes.contains_key(&p) {
                let mut proc = p.clone();
                if self.policy.system_with_parameter() {
                    proc = format!("{}\0{}", p, processes[&p]);
                }
                let _ = self.extend_imr(proc.as_bytes());
            }
        }
        Ok(())
    }

    pub fn measure(&mut self) -> Result<(), Error> {
        self.measure_system()
    }

    pub fn container_isolated(&mut self) -> Result<bool, Error> {
        Ok(self.policy.container_isolated())
    }
}
