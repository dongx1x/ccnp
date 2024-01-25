use anyhow::{anyhow, Error};
use cctrusted_base::{
    api::CCTrustedApi,
    api_data::ExtraArgs,
    tcg::{EventLogEntry, IMA_MEASUREMENT_EVENT},
};
use cctrusted_vm::sdk::API;
use std::collections::HashMap;

use crate::{
    ccnp_pb::{TcgDigest, TcgImrEvent},
    container::Container,
    measurement::Measurement,
};

pub struct Agent {
    pub measurement: Option<Measurement>,
    pub containers: Option<HashMap<String, Container>>,
    pub eventlogs: Option<Vec<TcgImrEvent>>,
}

impl Agent {
    pub fn init(&mut self, mut m: Measurement) {
        let _ = m.measure();
        self.measurement = Some(m);
        self.containers = Some(HashMap::new());
        self.eventlogs = Some(vec![]);
        let _ = self.get_all_eventlogs();
    }

    pub fn get_all_eventlogs(&mut self) -> Result<(), Error> {
        let start: u32 = match self
            .eventlogs
            .as_ref()
            .expect("The eventlog is None.")
            .len()
        {
            0 => 1,
            1 => 2,
            v => v as u32 - 1,
        };

        let entries = match API::get_cc_eventlog(Some(start), None) {
            Ok(q) => q,
            Err(e) => return Err(e),
        };

        if entries.len() <= 2 {
            return Ok(());
        }

        for entry in entries {
            match entry {
                EventLogEntry::TcgImrEvent(event) => {
                    let mut digests: Vec<TcgDigest> = vec![];
                    for d in event.digests {
                        digests.push(TcgDigest {
                            algo_id: d.algo_id as u32,
                            hash: d.hash,
                        })
                    }
                    let tcg_event = TcgImrEvent {
                        imr_index: event.imr_index,
                        event_type: event.event_type,
                        event_size: event.event_size,
                        event: event.event,
                        digests,
                    };
                    if tcg_event.event_type == IMA_MEASUREMENT_EVENT {
                        self.filter_container(tcg_event.clone());
                    }
                    self.eventlogs
                        .as_mut()
                        .expect("Change eventlog to mut failed.")
                        .push(tcg_event)
                }
                EventLogEntry::TcgPcClientImrEvent(event) => self
                    .eventlogs
                    .as_mut()
                    .expect("Change eventlog to mut failed.")
                    .push(TcgImrEvent {
                        imr_index: event.imr_index,
                        event_type: event.event_type,
                        event_size: event.event_size,
                        event: event.event,
                        digests: vec![],
                    }),
                EventLogEntry::TcgCanonicalEvent(_event) => {
                    todo!();
                }
            }
        }
        Ok(())
    }

    pub fn filter_container(&mut self, event: TcgImrEvent) {
        let data =
            String::from_utf8(event.clone().event).expect("Convert event data to string failed.");
        let cgpath: Vec<&str> = data.split(' ').collect();

        if cgpath.len() != 4 {
            return;
        }
        if cgpath[1].starts_with("/kubepods") || cgpath[1].starts_with("/system.slice/docker-") {
            let imr = match self.measurement.clone() {
                Some(mut v) => v.get_imr(),
                None => return,
            };
            let mut container = Container::new(cgpath, imr);
            let id = container.get_id();
            if !self
                .containers
                .as_ref()
                .expect("Container hashmap check failed.")
                .contains_key(&id)
            {
                container.extend_imr(event.clone());
                self.containers
                    .as_mut()
                    .expect("Container hashmap insert failed.")
                    .insert(id.clone(), container);
                println!("continer exist: {}", id.clone());
            } else {
                let container = self
                    .containers
                    .as_mut()
                    .expect("Container hashmap get_mut failed.")
                    .get_mut(&id.clone());
                container
                    .expect("Container is None.")
                    .extend_imr(event.clone());
            }
            println!("continer: {}", id.clone());
        }
    }

    pub fn get_eventlog(
        &mut self,
        id: String,
        start: u32,
        count: u32,
    ) -> Result<Vec<TcgImrEvent>, Error> {
        let _ = self.get_all_eventlogs();

        let s: usize = start.try_into().unwrap();
        let mut e: usize = (start + count).try_into().unwrap();

        if self
            .measurement
            .clone()
            .expect("The Measuement is None.")
            .container_isolated()
            .unwrap()
        {
            if self
                .containers
                .as_ref()
                .expect("The container is None.")
                .contains_key(&id)
            {
                let container = self
                    .containers
                    .as_mut()
                    .expect("Container hashmap get_mut failed.")
                    .get_mut(&id.clone());
                let eventlogs = container.expect("Container is None.").get_eventlogs();
                if s >= eventlogs.len() {
                    return Err(anyhow!("Invalid input start. Start must be number larger than 0 and smaller than total event log count."));
                }
                if e >= eventlogs.len() {
                    return Err(anyhow!("Invalid input count. count must be number larger than 0 and smaller than total event log count."));
                }
                if e == 0 {
                    e = eventlogs.len();
                }
                return Ok(eventlogs[s..e].to_vec());
            } else {
                return Err(anyhow!("Container cannot be found."));
            }
        }
        let eventlogs = self.eventlogs.as_ref().expect("The eventlog is None.");
        if s >= eventlogs.len() {
            return Err(anyhow!("Invalid input start. Start must be number larger than 0 and smaller than total event log count."));
        }
        if e >= eventlogs.len() {
            return Err(anyhow!("Invalid input count. count must be number larger than 0 and smaller than total event log count."));
        }
        if e == 0 {
            e = eventlogs.len();
        }
        Ok(eventlogs[s..e].to_vec())
    }

    pub fn get_report(
        &mut self,
        id: String,
        nonce: String,
        user_data: String,
    ) -> Result<Vec<u8>, Error> {
        let _ = self.get_all_eventlogs();
        let mut new_nonce = nonce.clone();

        if self
            .measurement
            .clone()
            .expect("The Measuement is None.")
            .container_isolated()
            .unwrap()
        {
            if self
                .containers
                .as_ref()
                .expect("The container is None.")
                .contains_key(&id)
            {
                let mut container = self
                    .containers
                    .as_mut()
                    .expect("Container hashmap get_mut failed.")
                    .get_mut(&id.clone());
                let decoded_nonce = match base64::decode(new_nonce) {
                    Ok(v) => v,
                    Err(e) => return Err(anyhow!("nonce is not base64 encoded: {:?}", e)),
                };
                new_nonce = base64::encode(
                    [
                        container
                            .as_mut()
                            .expect("Container is None.")
                            .get_imr()
                            .hash,
                        decoded_nonce,
                    ]
                    .concat(),
                );
            } else {
                return Err(anyhow!("Container cannot be found."));
            }
        }

        let report = API::get_cc_report(Some(new_nonce), Some(user_data), ExtraArgs {})
            .map_or_else(Err, |val| Ok(val.cc_report))
            .unwrap();
        Ok(report)
    }

    pub fn get_measurement(
        &mut self,
        id: String,
        index: u32,
        algo_id: u32,
    ) -> Result<Vec<u8>, Error> {
        let _ = self.get_all_eventlogs();
        if self
            .measurement
            .clone()
            .expect("The Measuement is None.")
            .container_isolated()
            .unwrap()
        {
            if self
                .containers
                .as_ref()
                .expect("The container is None.")
                .contains_key(&id)
            {
                let container = self
                    .containers
                    .as_mut()
                    .expect("Container hashmap get_mut failed.")
                    .get_mut(&id.clone());
                return Ok(container.expect("Container is None.").get_imr().hash);
            } else {
                return Err(anyhow!("Container cannot be found."));
            }
        }
        let measurement =
            API::get_cc_measurement(index.try_into().unwrap(), algo_id.try_into().unwrap())
                .map_or_else(Err, |val| Ok(val.get_hash()))
                .unwrap();
        Ok(measurement)
    }
}
