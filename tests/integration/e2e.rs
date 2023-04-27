use reqwest::Client;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

use http::header::ACCEPT;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use rvcr::VCRMiddleware;
use tracing_subscriber::{
    filter, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, Layer,
};

lazy_static::lazy_static! {
    static ref SCOPE: TestScope = TestScope::default();
    static ref ADDRESS: String = String::from("http://127.0.0.1:38282");
}

#[derive(Clone)]
pub struct TestScope {
    pub initialized: Arc<Mutex<bool>>,
}

impl Default for TestScope {
    fn default() -> Self {
        Self {
            initialized: Arc::new(Mutex::new(false)),
        }
    }
}

impl TestScope {
    pub async fn init(self) {
        let mut inited = self.initialized.lock().await;
        if *inited == false {
            if std::env::var("TEST_LOG").is_ok() {
                let stdout_log = tracing_subscriber::fmt::layer().pretty();
                tracing_subscriber::registry()
                    .with(
                        stdout_log
                            // Add an `INFO` filter to the stdout logging layer
                            .with_filter(filter::LevelFilter::DEBUG),
                    )
                    .init();
            }
            *inited = true;
        }
    }
}

async fn send_and_compare(
    method: reqwest::Method,
    path: &str,
    headers: Vec<(http::HeaderName, &str)>,
    body: Option<&str>,
    vcr_client: ClientWithMiddleware,
    real_client: reqwest::Client,
) {
    let mut req1 = vcr_client.request(method.clone(), format!("{}{}", ADDRESS.to_string(), path));

    let mut req2 = real_client.request(method, format!("{}{}", ADDRESS.to_string(), path));

    for (header_name, header_value) in headers {
        req1 = req1.header(header_name.clone(), header_value);
        req2 = req2.header(header_name, header_value);
    }

    match body {
        Some(text) => {
            req1 = req1.body(text.to_string());
            req2 = req2.body(text.to_string());
        }
        None => (),
    }

    let req1 = req1.build().unwrap();
    let req2 = req2.build().unwrap();

    let vcr_response = vcr_client.execute(req1).await.unwrap();
    let real_response = reqwest::Client::new().execute(req2).await.unwrap();

    let vcr_status = vcr_response.status().clone();
    let real_status = real_response.status().clone();

    let mut vcr_headers = vcr_response.headers().clone();
    let mut real_headers = real_response.headers().clone();

    vcr_headers.remove("date".to_string());
    real_headers.remove("date".to_string());

    assert_eq!(
        vcr_response.bytes().await.unwrap(),
        real_response.bytes().await.unwrap()
    );
    assert_eq!(vcr_status, real_status);
    assert_eq!(vcr_headers, real_headers);
}

#[tokio::test]
async fn test_rvcr_replay() {
    SCOPE.clone().init().await;
    let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bundle.push("tests/resources/test.vcr");

    let middleware = VCRMiddleware::try_from(bundle.clone()).unwrap();

    let vcr_client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
        .with(middleware)
        .build();

    let real_client = Client::new();

    send_and_compare(
        reqwest::Method::GET,
        "/get",
        vec![(ACCEPT, "application/json")],
        None,
        vcr_client.clone(),
        real_client.clone(),
    )
    .await;

    send_and_compare(
        reqwest::Method::POST,
        "/post",
        vec![(ACCEPT, "application/json")],
        Some("test1"),
        vcr_client.clone(),
        real_client.clone(),
    )
    .await;

    send_and_compare(
        reqwest::Method::POST,
        "/post",
        vec![(ACCEPT, "application/json")],
        Some("test2"),
        vcr_client,
        real_client,
    )
    .await;
}
