//! Record-and-replay middleware for reqwest http client.
//!
//! Inspired by [https://github.com/vcr/vcr](Ruby-VCR) and
//! [https://git.sr.ht/~rjframe/surf-vcr](Surf-VCR) Rust client.
//!
//! # Examples
//!
//! To record the requests, initialize client like following
//! ```rust
//!         use std::path::PathBuf;
//!         use reqwest::Client;
//!         use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
//!         use rvcr::{VCRMiddleware, VCRMode};
//!
//!         let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//!         bundle.push("tests/resources/test.vcr");
//!
//!         let middleware: VCRMiddleware = VCRMiddleware::try_from(bundle.clone())
//!             .unwrap()
//!             .with_mode(VCRMode::Record);
//!
//!         let vcr_client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
//!             .with(middleware)
//!             .build();
//! ```
//!
//! To use recorded VCR cassette files, replace `.with_mode(VCRMode::Record)`
//!  with `.with_mode(VCRMode::Replay)`
use std::{collections::HashMap, fs, path::PathBuf, str::FromStr, sync::Mutex};

use base64::{engine::general_purpose, Engine};
use reqwest_middleware::Middleware;
use vcr_cassette::RecorderId;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

lazy_static::lazy_static! {
    static ref RECORDER: RecorderId = format!("rVCR {VERSION}");
    static ref BASE64: String = String::from("base64");
}

/// Pluggable VCR middleware for record-and-replay for reqwest items
pub struct VCRMiddleware {
    path: Option<PathBuf>,
    storage: Mutex<vcr_cassette::Cassette>,
    mode: VCRMode,
    skip: Mutex<usize>,
}

/// VCR mode switcher
#[derive(Eq, PartialEq)]
pub enum VCRMode {
    /// Record requests to the local VCR cassette files
    Record,
    /// Replay requests using local files
    Replay,
}

pub type VCRError = &'static str;

/// Implements boilerplate for converting between vcr_cassette
/// and reqwest structures.
///
/// Carries methods to find response in a cassette, and to record
/// an interaction.
impl VCRMiddleware {
    /// Adjust mode in the middleware and return it
    pub fn with_mode(mut self, mode: VCRMode) -> Self {
        self.mode = mode;
        self
    }

    /// Adjust path in the middleware and return it
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    fn convert_version_to_vcr(&self, version: http::Version) -> vcr_cassette::Version {
        if version == http::Version::HTTP_10 {
            vcr_cassette::Version::Http1_0
        } else if version == http::Version::HTTP_11 {
            vcr_cassette::Version::Http1_1
        } else if version == http::Version::HTTP_2 {
            vcr_cassette::Version::Http2_0
        } else {
            panic!("rVCR only supports http 1.0, 1.1 and 2.0")
        }
    }

    fn convert_version_from_vcr(&self, version: vcr_cassette::Version) -> http::Version {
        match version {
            vcr_cassette::Version::Http1_0 => http::Version::HTTP_10,
            vcr_cassette::Version::Http1_1 => http::Version::HTTP_11,
            vcr_cassette::Version::Http2_0 => http::Version::HTTP_2,
            _ => {
                panic!("rVCR only supports http 1.0, 1.1 and 2.0")
            }
        }
    }

    fn bytes_to_vcr_body(&self, body_bytes: &[u8]) -> vcr_cassette::Body {
        // Try to parse UTF-8 string from the body;
        // if it fails, body bytes are base64 encoded before saving

        // FIXME: detecting support more encodings
        match String::from_utf8(body_bytes.to_vec()) {
            Ok(body_str) => vcr_cassette::Body::from_str(&body_str).unwrap(),
            Err(e) => {
                tracing::debug!("Can not deserialize utf-8 string: {e:?}");
                let base64_str = general_purpose::STANDARD_NO_PAD.encode(body_bytes);
                vcr_cassette::Body {
                    string: base64_str,
                    encoding: Some(BASE64.to_string()),
                }
            }
        }
    }

    fn headers_to_vcr(&self, headers: &reqwest::header::HeaderMap) -> vcr_cassette::Headers {
        let mut vcr_headers = vcr_cassette::Headers::new();
        for (header_name, header_value) in headers {
            let header_name_string = header_name.to_string();
            let header_value_bytes = header_value.as_bytes();
            let header_value = String::from_utf8(header_value_bytes.to_vec())
                .unwrap_or_else(|_| panic!("Non utf header value for header named {header_name}; header values are supposed to be ASCII encoded"));
            vcr_headers.insert(header_name_string, vec![header_value]);
        }
        vcr_headers
    }

    fn request_to_vcr(&self, req: reqwest::Request) -> vcr_cassette::Request {
        let body = match req.body() {
            Some(body) => match body.as_bytes() {
                Some(body_bytes) => self.bytes_to_vcr_body(body_bytes),
                None => vcr_cassette::Body::from_str("").unwrap(),
            },
            None => vcr_cassette::Body::from_str("").unwrap(),
        };

        let method_str = req.method().to_string().to_lowercase();

        let method: vcr_cassette::Method = serde_json::from_str(&format!("\"{method_str}\""))
            .unwrap_or_else(|_| panic!("Unknown HTTP method passed from reqwest: {method_str}"));

        let headers = self.headers_to_vcr(req.headers());

        vcr_cassette::Request {
            body,
            method,
            uri: req.url().to_owned(),
            headers,
        }
    }

    async fn response_to_vcr(&self, resp: reqwest::Response) -> vcr_cassette::Response {
        let http_version = Some(self.convert_version_to_vcr(resp.version()));
        let status_code = resp.status();
        let headers = self.headers_to_vcr(resp.headers());
        let response_text = resp.bytes().await.expect("Can not fetch response bytes");
        let body = self.bytes_to_vcr_body(&response_text);

        let status = vcr_cassette::Status {
            code: status_code.as_u16(),
            message: status_code
                .canonical_reason()
                .unwrap_or("Unknown")
                .to_string(),
        };

        vcr_cassette::Response {
            body,
            http_version,
            status,
            headers,
        }
    }

    fn find_response_in_vcr(&self, req: vcr_cassette::Request) -> Option<vcr_cassette::Response> {
        let cassette = self.storage.lock().unwrap();
        let skip = *self.skip.lock().unwrap();
        *self.skip.lock().unwrap() += 1;
        for interaction in cassette.http_interactions.iter().skip(skip) {
            if interaction.request == req {
                return Some(interaction.response.clone());
            }
        }
        None
    }

    fn vcr_to_response(&self, response: vcr_cassette::Response) -> reqwest::Response {
        let code = response.status.code;
        let mut builder = http::Response::builder().status(code);
        for (header_name, header_values) in response.headers {
            builder = builder.header(header_name, header_values.first().unwrap());
        }
        let http_version = self.convert_version_from_vcr(
            response
                .http_version
                .unwrap_or(vcr_cassette::Version::Http1_1),
        );
        let builder = builder.version(http_version);

        match response.body.encoding {
            None => {
                if !response.body.string.is_empty() {
                    reqwest::Response::from(builder.body(response.body.string).unwrap())
                } else {
                    reqwest::Response::from(builder.body("".as_bytes()).unwrap())
                }
            }
            Some(encoding) => {
                if encoding == "base64" {
                    let decoded = general_purpose::STANDARD_NO_PAD
                        .decode(encoding)
                        .expect("Invalid response body base64 can not be decoded");
                    reqwest::Response::from(builder.body(decoded).unwrap())
                } else {
                    // FIXME: support more encodings
                    panic!("Unsupported encoding: {encoding}");
                }
            }
        }
    }

    fn record(&self, request: vcr_cassette::Request, response: vcr_cassette::Response) {
        let mut cassette = self.storage.lock().unwrap();
        cassette
            .http_interactions
            .push(vcr_cassette::HttpInteraction {
                response,
                request,
                recorded_at: chrono::Utc::now().into(),
            });
    }
}

/// Reqwest middleware implementation
///
/// It receives request, converts it to internal VCR format,
/// and saves data in the internal.
#[async_trait::async_trait]
impl Middleware for VCRMiddleware {
    async fn handle(
        &self,
        req: reqwest::Request,
        extensions: &mut task_local_extensions::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let vcr_request = self.request_to_vcr(req.try_clone().unwrap());

        match self.mode {
            VCRMode::Record => {
                let response = next.run(req, extensions).await?;
                let vcr_response = self.response_to_vcr(response).await;
                let converted_response = self.vcr_to_response(vcr_response.clone());
                self.record(vcr_request, vcr_response);
                Ok(converted_response)
            }
            VCRMode::Replay => {
                let vcr_response = self.find_response_in_vcr(vcr_request).unwrap_or(
                    // Empty 404 response
                    vcr_cassette::Response {
                        body: vcr_cassette::Body::from_str("").unwrap(),
                        http_version: Some(vcr_cassette::Version::Http1_1),
                        status: vcr_cassette::Status {
                            code: 404,
                            message: "Not found in VCR".to_string(),
                        },
                        headers: HashMap::new(),
                    },
                );
                let response = self.vcr_to_response(vcr_response);
                Ok(response)
            }
        }
    }
}

/// Create middleware instance from Cassette
impl From<vcr_cassette::Cassette> for VCRMiddleware {
    fn from(cassette: vcr_cassette::Cassette) -> Self {
        VCRMiddleware {
            storage: Mutex::new(cassette),
            mode: VCRMode::Replay,
            path: None,
            skip: Mutex::new(0),
        }
    }
}

/// Save cassette interactions after the run
impl Drop for VCRMiddleware {
    fn drop(&mut self) {
        if self.mode == VCRMode::Record {
            let path = self
                .path
                .clone()
                .unwrap_or(format!(".rvcr-{}.vcr", chrono::Utc::now().timestamp()).into());
            let cassette = self.storage.lock().unwrap();
            fs::write(
                path.clone(),
                serde_json::to_string_pretty(&*cassette).unwrap(),
            )
            .unwrap_or_else(|_| panic!("Can not write cassette contents to {path:?}"));
            tracing::info!("Written VCR cassette file at {path:?}");
        }
    }
}

/// Load VCR cassette for filesystem
//
/// For simplicity, support JSON format only for now
impl TryFrom<PathBuf> for VCRMiddleware {
    fn try_from(pb: PathBuf) -> Result<Self, Self::Error> {
        let cassette: vcr_cassette::Cassette = if !pb.exists() {
            vcr_cassette::Cassette {
                http_interactions: vec![],
                recorded_with: RECORDER.to_string(),
            }
        } else {
            let content = fs::read_to_string(pb.clone()).map_err(|e| {
                tracing::error!("Failed reading VCR cassette: {e}");
                format!(
                    "Failed to read VCR cassette from path {}",
                    pb.to_str().unwrap()
                )
            })?;

            serde_json::from_str(&content).map_err(|e| {
                tracing::error!("Failed deserializing VCR cassette: {e}");
                format!(
                    "Failed to deserialize VCR cassette from path {}",
                    pb.to_str().unwrap()
                )
            })?
        };

        let mut mw = Self::from(cassette);
        mw.path = Some(pb);
        Ok(mw)
    }

    type Error = String;
}
