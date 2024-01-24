use std::collections::HashMap;
use std::fs;
use std::io::Error;

use log;
use regex::Regex;
use sha2::{Sha384, Digest};

use crate::policy::PolicyConfig;

pub struct Measurement {
    policy: PolicyConfig,
    algo: String,
    imr: Vec<u8>,
    event_log: String,
}

impl Measurement {
    pub fn new(mut policy: PolicyConfig) -> Measurement {
        let algo = policy.get_alogrithm();
        let algo_len = match policy.get_alogrithm().as_str() {
            "sha1" => 20,
            "sha384"=> 48,
            _ => 0,
        };

        Measurement {
            policy,
            algo,
            imr: vec![0; algo_len],
            event_log: String::new(),
        }
    }

    fn extend_imr(&mut self, hash: Vec<u8>) -> Result<(), Error> {
        if hash.len() != self.imr.len() {
            log::error!("Hash algorighm does not match IMR");
        }
        println!("{} {}", hash.len(), self.imr.len());

        Ok(())
    }

    fn get_processes(&mut self, procfs: String) -> Result<HashMap<String, String>, Error> {
        let mut processes = HashMap::new();
        let pattern = Regex::new(r".*/[0-9]").unwrap();
        let paths = fs::read_dir(procfs)
            .unwrap()
            .into_iter()
            .map(|r| r.unwrap().path())
            .filter(|r| pattern.is_match(r.to_str().unwrap()));
    
        for path in paths {
            let cmdline_path = path.to_str().unwrap().to_owned() + "/cmdline";
            let cmdline = fs::read_to_string(cmdline_path)
                .expect("Failed to read process cmdline.");
    
            if cmdline.is_empty() {
                continue;
            }
    
            let (name, parameter) = cmdline.split_once('\0').unwrap();
            processes.insert(name.to_string(), parameter.to_string());
        }
    
        Ok(processes)
    }
    pub fn measure (&mut self) -> Result<(), Error> {
        let processes = self.get_processes("/proc".to_string()).unwrap();
        let mut hasher = Sha384::new();
        // let mut hasher = match self.algo.as_str() {
        //     "sha384" => sha2::Sha384::new(),
        //     _ => sha2::Sha384::new(),
        // };
        let process_policy = self.policy.get_system_processes();
        for p in process_policy {
            if processes.contains_key(&p) {
                println!("process: {}, {}", p, processes[&p]);
                hasher.update(p.as_bytes());
                if self.policy.system_process_parameter() {
                    hasher.update(processes[&p].as_bytes());
                    println!("param: {}, {}", p, processes[&p]);
                }

                let hash = hasher.clone().finalize();
                let val = hash[..].to_vec();
                let _ = self.extend_imr(val);
            }
        }
        Ok(())
    }
}
