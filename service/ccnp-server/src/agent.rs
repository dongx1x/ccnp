use anyhow::{anyhow, Error};
use cctrusted_base::{
    api::CCTrustedApi,
    api_data::ExtraArgs,
    tcg::{EventLogEntry, IMA_MEASUREMENT_EVENT},
};
use cctrusted_vm::sdk::API;
use log::info;
use std::collections::HashMap;

use crate::{
    ccnp_pb::{TcgDigest, TcgImrEvent},
    container::Container,
    measurement::Measurement,
};

pub struct Agent {
    pub measurement: Option<Measurement>,
    pub containers: Option<HashMap<String, Container>>,
    pub event_logs: Option<Vec<TcgImrEvent>>,
}

impl Agent {
    pub fn init(&mut self, mut m: Measurement) -> Result<(), Error> {
        let _ = m.measure();
        self.measurement = Some(m);
        self.containers = Some(HashMap::new());
        self.event_logs = Some(vec![]);
        self.fetch_all_event_logs()
    }

    pub fn get_default_algorithm(&mut self) -> Result<u32, Error> {
        let algo = match API::get_default_algorithm() {
            Ok(q) => q,
            Err(e) => return Err(e),
        };
        Ok(algo.algo_id.into())
    }

    pub fn get_measurement_count(&mut self) -> Result<u32, Error> {
        let count = match API::get_measurement_count() {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        Ok(count.into())
    }

    pub fn fetch_all_event_logs(&mut self) -> Result<(), Error> {
        let start: u32 = self
            .event_logs
            .as_ref()
            .expect("The event_logs is None.")
            .len() as u32;

        let entries = match API::get_cc_eventlog(Some(start), None) {
            Ok(q) => q,
            Err(e) => return Err(e),
        };

        if entries.len() == 0 {
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
                        digest:vec![],
                        digests,
                    };
                    if tcg_event.event_type == IMA_MEASUREMENT_EVENT {
                        self.filter_container(tcg_event.clone());
                    }
                    self.event_logs
                        .as_mut()
                        .expect("Change eventlog to mut failed.")
                        .push(tcg_event)
                }
                EventLogEntry::TcgPcClientImrEvent(event) => self
                    .event_logs
                    .as_mut()
                    .expect("Change eventlog to mut failed.")
                    .push(TcgImrEvent {
                        imr_index: event.imr_index,
                        event_type: event.event_type,
                        event_size: event.event_size,
                        event: event.event,
                        digest: event.digest.to_vec(), 
                        digests: vec![],
                    }),
                EventLogEntry::TcgCanonicalEvent(_event) => {
                    todo!();
                }
            }
        }
        info!("Loaded {} event logs.", self.event_logs.as_ref().expect("Change eventlog to ref failed.").len());

        Ok(())
    }

    pub fn filter_container(&mut self, event: TcgImrEvent) {
        let data =
            String::from_utf8(event.clone().event).expect("Convert event data to string failed.");
        let cgpath: Vec<&str> = data.split(' ').collect();

        if cgpath.len() != 4 {
            return;
        }
        if cgpath[1].starts_with("/kubepods.slice/kubepods") || cgpath[1].starts_with("/system.slice/docker-") {
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
                container.set_imr(self.measurement.as_mut().unwrap().get_imr());
                container.set_eventlogs(self.measurement.as_mut().unwrap().get_eventlogs());
                container.extend_imr(event.clone());
                self.containers
                    .as_mut()
                    .expect("Container hashmap insert failed.")
                    .insert(id.clone(), container);
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
        }
    }

    pub fn get_cc_eventlog(
        &mut self,
        id: String,
        start: u32,
        count: u32,
    ) -> Result<Vec<TcgImrEvent>, Error> {
        let _ = self.fetch_all_event_logs();
        let mut event_logs: Vec<TcgImrEvent> = vec![];
        let s: usize = start.try_into().unwrap();
        let mut e: usize = (start + count).try_into().unwrap();
        let container_isolated = self
            .measurement
            .clone()
            .expect("The Measuement is None.")
            .container_isolated()
            .unwrap();

        if container_isolated {
            for event_log in self.event_logs.as_ref().expect("The eventlog is None.") {
                if event_log.imr_index == 0 || event_log.imr_index == 1 {
                    event_logs.push(event_log.clone());
                }
            }
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
                let out_event_logs = [event_logs, container.expect("Container is None.").get_eventlogs()].concat();
                if s >= out_event_logs.len() {
                    return Err(anyhow!("Invalid input start. Start must be smaller than total event log count."));
                }
                if e >= out_event_logs.len() {
                    return Err(anyhow!("Invalid input count. count must be smaller than total event log count."));
                }
                if e == 0 {
                    e = out_event_logs.len();
                }
                return Ok(out_event_logs[s..e].to_vec());
            } else {
                return Err(anyhow!("Container cannot be found."));
            }
        }
        event_logs = self.event_logs.as_ref().expect("The eventlog is None.").to_vec();
        if s >= event_logs.len() {
            return Err(anyhow!("Invalid input start. Start must be smaller than total event log count."));
        }
        if e >= event_logs.len() {
            return Err(anyhow!("Invalid input count. count must be smaller than total event log count."));
        }
        if e == 0 {
            e = event_logs.len();
        }
        Ok(event_logs[s..e].to_vec())
    }

    pub fn get_cc_report(
        &mut self,
        id: String,
        nonce: String,
        user_data: String,
    ) -> Result<(Vec<u8>, u32), Error> {
        let _ = self.fetch_all_event_logs();
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

        let (report, cc_type) = API::get_cc_report(Some(new_nonce), Some(user_data), ExtraArgs {})
            .map_or_else(Err, |val| Ok((val.cc_report, val.cc_type as u32)))
            .unwrap();
        Ok((report, cc_type))
    }

    pub fn get_cc_measurement(
        &mut self,
        id: String,
        index: u32,
        algo_id: u32,
    ) -> Result<TcgDigest, Error> {
        let _ = self.fetch_all_event_logs();
        let container_isolated = self
            .measurement
            .clone()
            .expect("The Measuement is None.")
            .container_isolated()
            .unwrap();

        if index == 2 && container_isolated {
            return Err(anyhow!("Cannot access IMR according to the policy."))
        }

        if index == 3 && container_isolated {
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
                return Ok(container.expect("Container is None.").get_imr());
            } else {
                return Err(anyhow!("Container cannot be found."));
            }
        }
        let measurement =
            API::get_cc_measurement(index.try_into().unwrap(), algo_id.try_into().unwrap())
                .map_or_else(Err, |val| {
                    Ok(TcgDigest {
                        algo_id: val.algo_id.into(),
                        hash: val.hash,
                    })
                })
                .unwrap();
        Ok(measurement)
    }
}
