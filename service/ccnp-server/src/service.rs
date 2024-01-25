use anyhow::Result;
use lazy_static::lazy_static;
use std::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::{
    agent::Agent,
    ccnp_pb::{
        ccnp_server::Ccnp, GetEventlogRequest, GetEventlogResponse, GetMeasurementRequest,
        GetMeasurementResponse, GetReportRequest, GetReportResponse,
    },
    measurement::Measurement,
};

lazy_static! {
    static ref AGENT: Mutex<Agent> = Mutex::new(Agent {
        measurement: None,
        containers: None,
        eventlogs: None,
    });
}

pub struct Service;
impl Service {
    pub fn new(m: Measurement) -> Self {
        AGENT.lock().unwrap().init(m);
        Service {}
    }
}

#[tonic::async_trait]
impl Ccnp for Service {
    async fn get_measurement(
        &self,
        request: Request<GetMeasurementRequest>,
    ) -> Result<Response<GetMeasurementResponse>, Status> {
        let req = request.into_inner();
        let measurement =
            match AGENT
                .lock()
                .unwrap()
                .get_measurement(req.container_id, req.index, req.algo_id)
            {
                Ok(v) => v,
                Err(e) => return Err(Status::internal(e.to_string())),
            };

        Ok(Response::new(GetMeasurementResponse { measurement }))
    }

    async fn get_eventlog(
        &self,
        request: Request<GetEventlogRequest>,
    ) -> Result<Response<GetEventlogResponse>, Status> {
        let req = request.into_inner();
        let eventlogs =
            match AGENT
                .lock()
                .unwrap()
                .get_eventlog(req.container_id, req.start, req.count)
            {
                Ok(v) => v,
                Err(e) => return Err(Status::internal(e.to_string())),
            };

        Ok(Response::new(GetEventlogResponse { eventlogs }))
    }

    async fn get_report(
        &self,
        request: Request<GetReportRequest>,
    ) -> Result<Response<GetReportResponse>, Status> {
        let req = request.into_inner();
        let report =
            match AGENT
                .lock()
                .unwrap()
                .get_report(req.container_id, req.nonce, req.user_data)
            {
                Ok(v) => v,
                Err(e) => return Err(Status::internal(e.to_string())),
            };

        Ok(Response::new(GetReportResponse { report }))
    }
}

// todo: unit test
