use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
struct SystemPolicy {
    with_parameter: bool,
    configs: Vec<String>,
    processes: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
struct KubernetesPolicy {
    with_parameter: bool,
    version: Vec<String>,
    configs: Vec<String>,
    pods: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
struct ContainerPolicy {
    with_parameter: bool,
    isolated: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
struct MeasurePolicy {
    system: SystemPolicy,
    kubernetes: KubernetesPolicy,
    container: ContainerPolicy,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    backend: String,
    algorithm: String,
    measure: MeasurePolicy,
}

impl PolicyConfig {
    pub fn new(path: String) -> PolicyConfig {
        let file = std::fs::File::open(path).expect("Failed to open policy file.");
        serde_yaml::from_reader(file).expect("Failed to serialize policy file.")
    }
    pub fn get_alogrithm(&mut self) -> String {
        self.algorithm.clone()
    }
    pub fn get_system_processes(&mut self) -> Vec<String> {
        self.measure.system.processes.clone()
    }
    pub fn get_system_configs(&mut self) -> Vec<String> {
        self.measure.system.configs.clone()
    }
    pub fn system_with_parameter(&mut self) -> bool {
        self.measure.system.with_parameter
    }
    pub fn get_kubernetes_pods(&mut self) -> Vec<String> {
        self.measure.kubernetes.pods.clone()
    }
    pub fn kubernetes_pods_parameter(&mut self) -> bool {
        self.measure.kubernetes.with_parameter
    }
    pub fn container_with_parameter(&mut self) -> bool {
        self.measure.container.with_parameter
    }
    pub fn container_isolated(&mut self) -> bool {
        self.measure.container.isolated
    }
}
