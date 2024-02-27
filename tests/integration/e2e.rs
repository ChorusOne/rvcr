use reqwest::Client;
use std::{path::PathBuf, time::Duration};

use http::header::ACCEPT;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use rvcr::VCRMiddleware;

async fn send_and_compare(
    method: reqwest::Method,
    path: &str,
    headers: Vec<(http::HeaderName, &str)>,
    body: Option<&str>,
    vcr_client: ClientWithMiddleware,
    real_client: reqwest::Client,
) {
    let mut req1 = vcr_client.request(
        method.clone(),
        format!("{}{}", crate::ADDRESS.to_string(), path),
    );

    let mut req2 = real_client.request(method, format!("{}{}", crate::ADDRESS.to_string(), path));

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

    // Server date is different for recorded and live requests
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
    crate::SCOPE.clone().init().await;
    let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bundle.push("tests/resources/replay.vcr.json");

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

#[tracing_test::traced_test]
#[tokio::test]
async fn test_rvcr_failed_debug() {
    crate::SCOPE.clone().init().await;
    let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bundle.push("tests/resources/replay.vcr.json");

    let middleware = VCRMiddleware::try_from(bundle.clone())
        .unwrap()
        .with_rich_diff(true);

    let vcr_client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
        .with(middleware)
        .build();

    let mut unmatched_req = vcr_client.request(
        reqwest::Method::POST,
        format!("{}/post", crate::ADDRESS.to_string()),
    );

    unmatched_req = unmatched_req.header(ACCEPT, "text/html");
    unmatched_req = unmatched_req.body("Something different".to_string());
    let unmatched_req = unmatched_req.build().unwrap();

    let result = vcr_client.execute(unmatched_req).await;
    assert!(result.is_err());

    let expected_logs = r#"Did not match Get to http://127.0.0.1:38282/get:
  Method differs: recorded Get, got Post
  URI differs:
    recorded: "http://127.0.0.1:38282/get"
    got:      "http://127.0.0.1:38282/post"
  Headers differ:
    accept:
      recorded: "application/json"
      got:      "text/html"
  Body differs:
    recorded: ""
    got:      "Something different""#;
    logs_assert(|lines: &[&str]| {
        let processed_logs = lines
            .iter()
            .map(|line| line.split("rvcr: ").collect::<Vec<&str>>()[1])
            .collect::<Vec<&str>>()
            .join("\n");
        assert!(processed_logs.contains(expected_logs));
        Ok(())
    });
}

#[tokio::test]
async fn test_rvcr_replay_search_all() {
    crate::SCOPE.clone().init().await;
    let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bundle.push("tests/resources/search-all.vcr.json");

    let middleware = VCRMiddleware::try_from(bundle.clone())
        .unwrap()
        .with_search(rvcr::VCRReplaySearch::SearchAll);

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
        Some("test93"),
        vcr_client.clone(),
        real_client.clone(),
    )
    .await;

    send_and_compare(
        reqwest::Method::POST,
        "/post",
        vec![(ACCEPT, "application/json")],
        Some("test93"),
        vcr_client.clone(),
        real_client,
    )
    .await;

    let req1 = vcr_client
        .request(
            reqwest::Method::POST,
            format!("{}{}", crate::ADDRESS.to_string(), "/post"),
        )
        .send()
        .await
        .expect("Failed to get response");

    // Ensure next request will get Date with 1 second more
    // when recording
    tokio::time::sleep(Duration::from_secs(1)).await;

    let req2 = vcr_client
        .request(
            reqwest::Method::POST,
            format!("{}{}", crate::ADDRESS.to_string(), "/post"),
        )
        .send()
        .await
        .expect("Failed to get response");

    let header_date_1 = req1.headers().get("date").unwrap();
    let header_date_2 = req2.headers().get("date").unwrap();

    // Since first request was identical to second, first response
    // was returned for second request with SearchAll
    assert_eq!(header_date_1, header_date_2);
}

#[tokio::test]
async fn test_rvcr_replay_skip_found() {
    crate::SCOPE.clone().init().await;
    let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bundle.push("tests/resources/skip-found.vcr.json");

    let middleware = VCRMiddleware::try_from(bundle.clone())
        .unwrap()
        .with_search(rvcr::VCRReplaySearch::SkipFound);

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
        Some("test93"),
        vcr_client.clone(),
        real_client.clone(),
    )
    .await;

    send_and_compare(
        reqwest::Method::POST,
        "/post",
        vec![(ACCEPT, "application/json")],
        Some("test93"),
        vcr_client.clone(),
        real_client,
    )
    .await;

    let req1 = vcr_client
        .request(
            reqwest::Method::POST,
            format!("{}{}", crate::ADDRESS.to_string(), "/post"),
        )
        .send()
        .await
        .expect("Failed to get response");

    tokio::time::sleep(Duration::from_secs(1)).await;

    let req2 = vcr_client
        .request(
            reqwest::Method::POST,
            format!("{}{}", crate::ADDRESS.to_string(), "/post"),
        )
        .send()
        .await
        .expect("Failed to get response");

    let header_date_1 = req1.headers().get("date").unwrap();
    let header_date_2 = req2.headers().get("date").unwrap();

    // Despite first request was identical to second, second response
    // was returned for second request with SkipFound
    assert_ne!(header_date_1, header_date_2);
}

#[cfg(feature = "compress")]
#[tokio::test]
async fn test_rvcr_replay_compressed() {
    crate::SCOPE.clone().init().await;
    let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bundle.push("tests/resources/replay.vcr.zip");

    let middleware = VCRMiddleware::try_from(bundle.clone())
        .unwrap()
        .compressed(true);

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
}
