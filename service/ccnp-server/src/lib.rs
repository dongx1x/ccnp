pub mod ccnp_server_pb;
pub mod container;
pub mod measurement;
pub mod policy;
pub mod service;

pub mod ccnp_pb {
    tonic::include_proto!("ccnp_server_pb");

    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("ccnp_server_descriptor");
}
