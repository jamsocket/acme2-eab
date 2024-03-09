use testcontainers::{core::WaitFor, Image};

const NAME: &str = "letsencrypt/pebble-challtestsrv";
const TAG: &str = "v2.3.1";

pub struct ChalTestServerImage {
}

impl Default for ChalTestServerImage {
  fn default() -> Self {
    Self {}
  }
}

impl Image for ChalTestServerImage {
  type Args = ();

  fn name(&self) -> String {
    NAME.to_string()
  }

  fn tag(&self) -> String {
    TAG.to_string()
  }

  fn ready_conditions(&self) -> Vec<testcontainers::core::WaitFor> {
    vec![WaitFor::message_on_stdout("Starting challenge servers")]
  }

  fn expose_ports(&self) -> Vec<u16> {
      vec![8055]
  }
}
