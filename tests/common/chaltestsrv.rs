use super::{docker::Container, test_env::TestEnv, wait::wait_for_url};
use anyhow::Result;
use bollard::container::Config;
use reqwest::Url;
use std::collections::HashMap;

const TESTSERV_IMAGE: &str = "letsencrypt/pebble-challtestsrv:v2.3.1";
const TESTSERV_PORT: u16 = 8055;
const HTTP_PORT: u16 = 5002;

pub struct TestServ {
  container: Container,
  pub management_url: Url,
  pub http_port: u16,
}

impl TestServ {
  pub async fn new(env: &mut TestEnv) -> Result<Self> {
    let config = Config {
      image: Some(TESTSERV_IMAGE.to_string()),
      exposed_ports: Some(
        vec![
          (format!("{}/tcp", TESTSERV_PORT), HashMap::new()),
          (format!("{}/tcp", HTTP_PORT), HashMap::new()),
        ]
        .into_iter()
        .collect(),
      ),
      host_config: Some(bollard::service::HostConfig {
        port_bindings: Some(
          vec![
            (
              format!("{}/tcp", TESTSERV_PORT),
              Some(vec![bollard::service::PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: None,
              }]),
            ),
            (
              format!("{}/tcp", HTTP_PORT),
              Some(vec![bollard::service::PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: None,
              }]),
            ),
          ]
          .into_iter()
          .collect(),
        ),
        ..Default::default()
      }),
      ..Default::default()
    };

    let container = env.start_container("testserv", &config).await?;
    let port = container.get_port(TESTSERV_PORT).await?;

    let url = Url::parse(&format!("http://localhost:{}", port)).unwrap();
    wait_for_url(&url, 5).await?;

    let http_port = container.get_port(HTTP_PORT).await?;

    Ok(Self {
      container,
      management_url: url,
      http_port,
    })
  }
}
