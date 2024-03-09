use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::read_to_string, net::SocketAddr, path::PathBuf};
use testcontainers::{core::WaitFor, Image, ImageArgs};
use uuid::Uuid;

const NAME: &str = "letsencrypt/pebble";
const TAG: &str = "v2.3.1";

const CONFIG_FILE_CONTAINER_PATH: &str = "/etc/pebble-config.json";

#[derive(Serialize, Deserialize)]
pub struct PebbleConfig {
  pub pebble: PebbleConfigInner,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PebbleConfigInner {
  pub listen_address: SocketAddr,
  pub management_listen_address: SocketAddr,
  pub certificate: PathBuf,
  pub private_key: PathBuf,
  pub http_port: u16,
  pub tls_port: u16,
  #[serde(rename = "ocspResponderURL")]
  pub ocsp_responder_url: String,
  pub external_account_binding_required: bool,
  #[serde(rename = "externalAccountMACKeys")]
  pub external_account_mac_keys: HashMap<String, String>,
}

impl Default for PebbleConfig {
  fn default() -> Self {
    Self {
      pebble: PebbleConfigInner {
        listen_address: "0.0.0.0:14000".parse().unwrap(),
        management_listen_address: "0.0.0.0:15000".parse().unwrap(),
        certificate: PathBuf::from("test/certs/localhost/cert.pem"),
        private_key: PathBuf::from("test/certs/localhost/key.pem"),
        http_port: 5002,
        tls_port: 5001,
        ocsp_responder_url: "".to_owned(),
        external_account_binding_required: false,
        external_account_mac_keys: HashMap::new(),
      },
    }
  }
}

#[derive(Debug, Clone)]
pub struct PebbleArgs;

impl ImageArgs for PebbleArgs {
    fn into_iterator(self) -> Box<dyn Iterator<Item = String>> {
        let v = vec![
            "pebble".to_string(),
            "-config".to_owned(),
            CONFIG_FILE_CONTAINER_PATH.to_owned(),
        ];
        Box::new(v.into_iter())
    }
}

pub struct PebbleImage {
  scratch_dir: PathBuf,
  config: PebbleConfig,
  config_file_host_path: String,
  config_file_container_path: String,
}

impl Default for PebbleImage {
  fn default() -> Self {
    let config = PebbleConfig::default();
    let tempdir_name = Uuid::new_v4().to_string();
    let scratch_dir = std::env::temp_dir().join(tempdir_name);
    std::fs::create_dir_all(&scratch_dir).unwrap();

    Self {
      config_file_host_path: scratch_dir
        .join("pebble.json")
        .to_str()
        .unwrap()
        .to_owned(),
      scratch_dir,
      config,
      config_file_container_path: CONFIG_FILE_CONTAINER_PATH.to_owned(),
    }
  }
}

impl PebbleImage {
  pub fn with_eab_config(mut self, key_id: &str, private_key: &str) -> Self {
    self.config.pebble.external_account_binding_required = true;
    self
      .config
      .pebble
      .external_account_mac_keys
      .insert(key_id.to_owned(), private_key.to_owned());
    self
  }

  pub fn with_http_port(mut self, port: u16) -> Self {
    self.config.pebble.http_port = port;
    self
  }

  pub fn build(self) -> (Self, PebbleArgs) {
    (self, PebbleArgs)
  }
}

impl Image for PebbleImage {
  type Args = PebbleArgs;

  fn name(&self) -> String {
    NAME.to_string()
  }

  fn tag(&self) -> String {
    TAG.to_string()
  }

  fn ready_conditions(&self) -> Vec<testcontainers::core::WaitFor> {
    vec![WaitFor::message_on_stdout("ACME directory available at:")]
  }

  fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
    // write config to scratch dir
    let config_path = self.scratch_dir.join("pebble.json");
    let mut config_file = std::fs::File::create(&config_path).unwrap();
    serde_json::to_writer(&mut config_file, &self.config).unwrap();

    Box::new(std::iter::once((
      &self.config_file_host_path,
      &self.config_file_container_path,
    )))
  }
}
