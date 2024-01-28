use crate::ccnp_pb::{TcgDigest, TcgImrEvent};
use cctrusted_base::tcg;
use openssl::hash::{Hasher, MessageDigest};
use regex::Regex;

impl From<TcgDigest> for MessageDigest {
    fn from(digest: TcgDigest) -> Self {
        let algo_id: u16 = digest.algo_id.try_into().unwrap();
        match algo_id {
            tcg::TPM_ALG_SHA1 => MessageDigest::sha1(),
            tcg::TPM_ALG_SHA256 => MessageDigest::sha256(),
            tcg::TPM_ALG_SHA384 => MessageDigest::sha384(),
            _ => MessageDigest::sha256(),
        }
    }
}

pub struct Container {
    id: String,
    pod_id: String,
    imr: TcgDigest,
    eventlogs: Vec<TcgImrEvent>,
}

impl Container {
    pub fn new(cgpath: Vec<&str>, digest: TcgDigest) -> Self {
        if cgpath[1].starts_with("/kubepods") {
            let pod_id_re1 = Regex::new(r"kubepods-pod|.slice").unwrap();
            let pod_id_re2 = Regex::new(r"kubepods-besteffort-pod|.slice").unwrap();
            let container_id_re = Regex::new(r"cri-containerd-|.scope").unwrap();

            let cgroup: Vec<&str> = cgpath[1].split('/').collect();
            let (pod_id, id) = match cgroup.len() {
                4 => (pod_id_re1.replace_all(cgroup[2], "").to_string(), container_id_re.replace_all(cgroup[3], "").to_string()),
                5 => (pod_id_re2.replace_all(cgroup[3], "").to_string(), container_id_re.replace_all(cgroup[4], "").to_string()),
                _ => ("".to_string(), "".to_string()),
            };
            let algo_id = digest.algo_id;
            let hash = vec![0; digest.hash.len()];

            Container {
                id: id,
                pod_id: pod_id,
                imr: TcgDigest { algo_id, hash },
                eventlogs: vec![],
            }
        } else {
            let container_id_re = Regex::new(r"/system.slice/docker-|.scope").unwrap();
            let id = container_id_re.replace_all(cgpath[1], "");
            let algo_id = digest.algo_id;
            let hash = vec![0; digest.hash.len()];

            Container {
                id: id.to_string(),
                pod_id: id.to_string(),
                imr: TcgDigest { algo_id, hash },
                eventlogs: vec![],
            }
        }
    }

    pub fn get_id(&mut self) -> String {
        self.pod_id.clone()
    }

    pub fn get_imr(&mut self) -> TcgDigest {
        self.imr.clone()
    }

    pub fn set_imr(&mut self, imr: TcgDigest) {
        self.imr = imr
    }

    pub fn get_eventlogs(&mut self) -> Vec<TcgImrEvent> {
        self.eventlogs.clone()
    }

    pub fn set_eventlogs(&mut self, eventlogs: Vec<TcgImrEvent>) {
        self.eventlogs = eventlogs
    }

    pub fn extend_imr(&mut self, mut event: TcgImrEvent) {
        let digests = event.clone().digests;
        for digest in digests {
            if self.imr.hash.len() != digest.hash.len() {
                return;
            }
            let new_val = [self.imr.hash.clone(), digest.hash.clone()].concat();
            let mut hasher =
                Hasher::new(digest.clone().into()).expect("Hasher initialzation failed");
            hasher.update(&new_val).expect("Hasher update failed");
            self.imr.hash = hasher.finish().expect("Hasher finish failed").to_vec();
        }
        event.imr_index = 3;
        self.eventlogs.push(event);
    }
}