use std::borrow::Cow;
use std::fs;
use std::path::PathBuf;

use reqwest_middleware::ClientBuilder;
use reqwest_middleware::ClientWithMiddleware;
use rvcr::VCRMiddleware;
use rvcr::VCRMode;
use vcr_cassette::{Request, Response};

// Replace access_token and secret header values with dummy ones
fn filter_query_params(mut uri: url::Url) -> url::Url {
    let sensitive_query_params = ["access_token", "secret"];
    let cloned = uri.clone();
    let filtered_query_params = cloned.query_pairs().map(|(k, v)| {
        if sensitive_query_params.contains(&k.as_ref()) {
            (k.clone(), Cow::from(format!("__{}__", k.to_uppercase())))
        } else {
            (k, v)
        }
    });
    uri.query_pairs_mut()
        .clear()
        .extend_pairs(filtered_query_params)
        .finish();
    uri
}

fn request_modifier(req: &mut Request) {
    // Overwrite query params with filtered ones
    req.uri = filter_query_params(req.uri.clone());
}

fn response_modifier(resp: &mut Response) {
    for (name, value) in &mut resp.headers {
        if name == "server" {
            (*value).pop().unwrap();
            (*value).push("Test Server Header Emulated Expect".to_string());
        }
    }
}

fn saved_fixture_path(path: &str) -> PathBuf {
    let mut bundle = PathBuf::from(std::env::temp_dir());
    bundle.push(path);

    if bundle.exists() {
        std::fs::remove_file(bundle.clone()).unwrap();
    }
    bundle
}

#[tokio::test]
pub async fn test_modifier_request() {
    crate::SCOPE.clone().init().await;
    let bundle = saved_fixture_path("request-modifer-test-case.vcr.json");

    let middleware = VCRMiddleware::try_from(bundle.clone())
        .unwrap()
        .with_mode(VCRMode::Record)
        .with_modify_request(request_modifier);

    let vcr_client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
        .with(middleware)
        .build();

    vcr_client
        .request(
            reqwest::Method::POST,
            format!(
                "{}{}",
                crate::ADDRESS.to_string(),
                "/post?access_token=s3cr3t&spam=eggs&secret=s3cr3t",
            ),
        )
        .send()
        .await
        .expect("Can not send request");
    // Drop triggers recording
    drop(vcr_client);

    let vcr_content = fs::read(bundle.clone()).expect("VCR file not created during test case");

    let cassette: vcr_cassette::Cassette = serde_json::from_slice(&vcr_content).unwrap();
    let interaction = cassette.http_interactions.first().unwrap();
    let recorded_url = interaction.request.uri.to_string();
    // Secret parameters were replaced
    assert_eq!(
        format!(
            "{}/post?access_token=__ACCESS_TOKEN__&spam=eggs&secret=__SECRET__",
            crate::ADDRESS.to_string()
        ),
        recorded_url,
    )
}

#[tokio::test]
pub async fn test_modifier_response() {
    crate::SCOPE.clone().init().await;
    let bundle = saved_fixture_path("response-modifer-test-case.vcr.json");
    let middleware = VCRMiddleware::try_from(bundle.clone())
        .unwrap()
        .with_mode(VCRMode::Record)
        .with_modify_response(response_modifier);

    let vcr_client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
        .with(middleware)
        .build();

    vcr_client
        .request(
            reqwest::Method::POST,
            format!("{}{}", crate::ADDRESS.to_string(), "/post",),
        )
        .send()
        .await
        .expect("Can not send request");
    // Drop triggers recording
    drop(vcr_client);

    let vcr_content = fs::read(bundle.clone()).expect("VCR file not created during test case");

    let cassette: vcr_cassette::Cassette = serde_json::from_slice(&vcr_content).unwrap();
    let interaction = cassette.http_interactions.first().unwrap();
    let recorded_server_header = interaction
        .response
        .headers
        .get("server")
        .unwrap()
        .clone()
        .pop()
        .unwrap();
    // Server header was replaced
    assert_eq!(recorded_server_header, "Test Server Header Emulated Expect",)
}
