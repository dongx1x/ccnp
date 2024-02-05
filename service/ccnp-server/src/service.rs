use anyhow::Result;
use lazy_static::lazy_static;
use std::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::{
    agent::Agent,
    ccnp_pb::{
        ccnp_server::Ccnp, GetDefaultAlgorithmRequest, GetDefaultAlgorithmResponse,
        GetCcEventlogRequest, GetCcEventlogResponse, GetMeasurementCountRequest,
        GetMeasurementCountResponse, GetCcMeasurementRequest, GetCcMeasurementResponse,
        GetCcReportRequest, GetCcReportResponse,
    },
    measurement::Measurement,
};

lazy_static! {
    static ref AGENT: Mutex<Agent> = Mutex::new(Agent {
        measurement: None,
        containers: None,
        event_logs: None,
    });
}

pub struct Service;
impl Service {
    pub fn new(m: Measurement) -> Self {
        match AGENT.lock().expect("Agent lock() failed.").init(m) {
            Err(e) => panic!("Server panic {:?}", e),
            Ok(_v) => _v,
        }
        Service {}
    }
}

#[tonic::async_trait]
impl Ccnp for Service {
    async fn get_default_algorithm(
        &self,
        _request: Request<GetDefaultAlgorithmRequest>,
    ) -> Result<Response<GetDefaultAlgorithmResponse>, Status> {
        let algo_id = match AGENT
            .lock()
            .expect("Agent lock() failed.")
            .get_default_algorithm()
        {
            Ok(v) => v,
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        Ok(Response::new(GetDefaultAlgorithmResponse { algo_id }))
    }

    async fn get_measurement_count(
        &self,
        _request: Request<GetMeasurementCountRequest>,
    ) -> Result<Response<GetMeasurementCountResponse>, Status> {
        let count = match AGENT
            .lock()
            .expect("Agent lock() failed.")
            .get_measurement_count()
        {
            Ok(v) => v,
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        Ok(Response::new(GetMeasurementCountResponse { count }))
    }

    async fn get_cc_measurement(
        &self,
        request: Request<GetCcMeasurementRequest>,
    ) -> Result<Response<GetCcMeasurementResponse>, Status> {
        let req = request.into_inner();
        let measurement = match AGENT
            .lock()
            .expect("Agent lock() failed.")
            .get_cc_measurement(req.container_id, req.index, req.algo_id)
        {
            Ok(v) => v,
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        Ok(Response::new(GetCcMeasurementResponse {
            measurement: Some(measurement),
        }))
    }

    async fn get_cc_eventlog(
        &self,
        request: Request<GetCcEventlogRequest>,
    ) -> Result<Response<GetCcEventlogResponse>, Status> {
        let req = request.into_inner();
        let event_logs = match AGENT.lock().expect("Agent lock() failed.").get_cc_eventlog(
            req.container_id,
            req.start,
            req.count,
        ) {
            Ok(v) => v,
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        Ok(Response::new(GetCcEventlogResponse { event_logs }))
    }

    async fn get_cc_report(
        &self,
        request: Request<GetCcReportRequest>,
    ) -> Result<Response<GetCcReportResponse>, Status> {
        let req = request.into_inner();
        let (cc_report, cc_type) = match AGENT.lock().expect("Agent lock() failed.").get_cc_report(
            req.container_id,
            req.nonce,
            req.user_data,
        ) {
            Ok(v) => v,
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        Ok(Response::new(GetCcReportResponse { cc_report, cc_type }))
    }
}
