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
//!         bundle.push("tests/resources/replay.vcr.json");
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
#[cfg(feature = "compress")]
use std::io::Read;
#[cfg(feature = "compress")]
use std::io::Write;
use std::{fs, path::PathBuf, str::FromStr, sync::Mutex};

use base64::{engine::general_purpose, Engine};
use reqwest_middleware::Middleware;
use vcr_cassette::{HttpInteraction, RecorderId};

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
    search: VCRReplaySearch,
    skip: Mutex<usize>,
    compress: bool,
    rich_diff: bool,
    modify_request: Option<Box<RequestModifier>>,
    modify_response: Option<Box<ResponseModifier>>,
}

type RequestModifier = dyn Fn(&mut vcr_cassette::Request) + Send + Sync + 'static;
type ResponseModifier = dyn Fn(&mut vcr_cassette::Response) + Send + Sync + 'static;

/// VCR mode switcher
#[derive(Eq, PartialEq, Clone)]
pub enum VCRMode {
    /// Record requests to the local VCR cassette files. Existing files will be overwritten
    Record,
    /// Replay requests using local files
    Replay,
}

/// Skip requests
#[derive(Eq, PartialEq)]
pub enum VCRReplaySearch {
    /// Skip requests which already have been found. Useful for
    /// verifying use-cases with strict request order.
    SkipFound,
    /// Search through all requests every time
    SearchAll,
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

    pub fn with_modify_request<F>(mut self, modifier: F) -> Self
    where
        F: Fn(&mut vcr_cassette::Request) + Send + Sync + 'static,
    {
        self.modify_request.replace(Box::new(modifier));
        self
    }

    pub fn with_modify_response<F>(mut self, modifier: F) -> Self
    where
        F: Fn(&mut vcr_cassette::Response) + Send + Sync + 'static,
    {
        self.modify_response.replace(Box::new(modifier));
        self
    }

    /// Adjust search behavior for responses
    pub fn with_search(mut self, search: VCRReplaySearch) -> Self {
        self.search = search;
        self
    }

    /// Adjust path in the middleware and return it
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Adjust rich diff in the middleware and return it
    pub fn with_rich_diff(mut self, rich_diff: bool) -> Self {
        self.rich_diff = rich_diff;
        self
    }

    /// Make VCR files to be compressed before creating
    #[cfg(feature = "compress")]
    pub fn compressed(mut self, compress: bool) -> Self {
        self.compress = compress;
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

        let mut vcr_request = vcr_cassette::Request {
            body,
            method,
            uri: req.url().to_owned(),
            headers,
        };

        if let Some(ref modifier) = self.modify_request {
            modifier(&mut vcr_request);
        }

        vcr_request
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

        let mut vcr_response = vcr_cassette::Response {
            body,
            http_version,
            status,
            headers,
        };

        if let Some(ref modifier) = self.modify_response {
            modifier(&mut vcr_response);
        }

        vcr_response
    }

    fn header_values_to_string(&self, header_values: Option<&Vec<String>>) -> String {
        match header_values {
            Some(values) => values.join(", "),
            None => "<MISSING>".to_string(),
        }
    }

    fn find_response_in_vcr(&self, req: vcr_cassette::Request) -> Option<vcr_cassette::Response> {
        let cassette = self.storage.lock().unwrap();
        let iteractions: Vec<&HttpInteraction> = match self.search {
            VCRReplaySearch::SkipFound => {
                let skip = *self.skip.lock().unwrap();
                *self.skip.lock().unwrap() += 1;
                cassette.http_interactions.iter().skip(skip).collect()
            }
            VCRReplaySearch::SearchAll => cassette.http_interactions.iter().collect(),
        };

        // we only want to log match failures if no match is found, so capture
        // everything at the beginning and then output it all at once if none
        // are found
        let mut diff_log = if self.rich_diff {
            Some(String::new())
        } else {
            None
        };
        for interaction in iteractions {
            if interaction.request == req {
                return Some(interaction.response.clone());
            }
            if let Some(diff) = diff_log.as_mut() {
                diff.push_str(&format!(
                    "Did not match {method:?} to {uri}:\n",
                    method = interaction.request.method,
                    uri = interaction.request.uri.as_str()
                ));
                if interaction.request.method != req.method {
                    diff.push_str(&format!(
                        "  Method differs: recorded {expected:?}, got {got:?}\n",
                        expected = interaction.request.method,
                        got = req.method
                    ));
                }
                if interaction.request.uri != req.uri {
                    diff.push_str("  URI differs:\n");
                    diff.push_str(&format!(
                        "    recorded: \"{}\"\n",
                        interaction.request.uri.as_str()
                    ));
                    diff.push_str(&format!("    got:      \"{}\"\n", req.uri.as_str()));
                }
                if interaction.request.headers != req.headers {
                    diff.push_str("  Headers differ:\n");
                    for (recorded_header_name, recorded_header_values) in
                        &interaction.request.headers
                    {
                        let expected = self.header_values_to_string(Some(recorded_header_values));
                        let got =
                            self.header_values_to_string(req.headers.get(recorded_header_name));
                        if expected != got {
                            diff.push_str(&format!("    {}:\n", recorded_header_name));
                            diff.push_str(&format!("      recorded: \"{}\"\n", expected));
                            diff.push_str(&format!("      got:      \"{}\"\n", got));
                        }
                    }
                    for (got_header_name, got_header_values) in &req.headers {
                        if !interaction.request.headers.contains_key(got_header_name) {
                            let got = self.header_values_to_string(Some(got_header_values));
                            diff.push_str(&format!("    {}:\n", got_header_name));
                            diff.push_str("      recorded: <MISSING>\n");
                            diff.push_str(&format!("      got:      \"{}\"\n", got));
                        }
                    }
                }
                if interaction.request.body != req.body {
                    diff.push_str("  Body differs:\n");
                    diff.push_str(&format!(
                        "    recorded: \"{}\"\n",
                        interaction.request.body.string
                    ));
                    diff.push_str(&format!("    got:      \"{}\"\n", req.body.string));
                }
                diff.push('\n');
            }
        }
        if let Some(diff) = diff_log {
            // tracing_test does not appear to capture multiline outputs for test
            // assertion purposes, so we print each line out separately
            for line in diff.split('\n') {
                tracing::info!("{}", line);
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
            VCRMode::Replay => match self.find_response_in_vcr(vcr_request) {
                None => {
                    let message = format!(
                        "Cannot find corresponding request in cassette {:?}",
                        self.path,
                    );
                    Err(reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                        message
                    )))
                }
                Some(response) => {
                    let response = self.vcr_to_response(response);
                    Ok(response)
                }
            },
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
            search: VCRReplaySearch::SkipFound,
            compress: false,
            rich_diff: false,
            modify_request: None,
            modify_response: None,
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

            let contents: String = serde_json::to_string_pretty(&*cassette).unwrap();

            #[cfg(feature = "compress")]
            if self.compress {
                let file = std::fs::File::create(path.clone()).unwrap();

                let mut zip = zip::ZipWriter::new(file);

                let options = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Bzip2)
                    .compression_level(Some(9))
                    .unix_permissions(0o644);
                zip.start_file("test.vcr.json", options).unwrap();
                zip.write_all(contents.as_bytes()).unwrap();
                zip.finish().unwrap();
            }

            if !self.compress {
                fs::write(path.clone(), contents.as_bytes())
                    .unwrap_or_else(|_| panic!("Can not write cassette contents to {path:?}"));
                tracing::info!("Written VCR cassette file at {path:?}");
            }
        }
    }
}

/// Load VCR cassette for filesystem
//
/// For simplicity, support JSON format only for now
impl TryFrom<PathBuf> for VCRMiddleware {
    fn try_from(pb: PathBuf) -> Result<Self, Self::Error> {
        let empty = vcr_cassette::Cassette {
            http_interactions: vec![],
            recorded_with: RECORDER.to_string(),
        };

        let mut mw = Self::from(empty);
        mw.path = Some(pb.clone());
        if !pb.exists() {
            Ok(mw)
        } else {
            let content = fs::read(pb.clone()).map_err(|e| {
                tracing::error!("Failed reading VCR cassette: {e}");
                format!(
                    "Failed to read VCR cassette from path {}",
                    pb.to_str().unwrap()
                )
            })?;

            #[cfg(feature = "compress")]
            let content = {
                let file = fs::File::open(mw.path.clone().unwrap()).unwrap();
                match zip::ZipArchive::new(file) {
                    Ok(mut archive) => {
                        let mut content = content;
                        content.clear();
                        let contents = archive.by_name("test.vcr.json");
                        let mut contents =
                            contents.expect("test.vcr.json file is missing in zip archive");
                        contents
                            .read_to_end(&mut content)
                            .expect("Can not read test.vcr.json from zip archive");
                        content
                    }
                    Err(e) => {
                        tracing::debug!("Failed to detect file as zip: {e:?}");
                        content
                    }
                }
            };

            let cassette: vcr_cassette::Cassette =
                serde_json::from_slice(&content).map_err(|e| {
                    tracing::error!("Failed deserializing VCR cassette: {e}");
                    format!(
                        "Failed to deserialize VCR cassette from path {}",
                        pb.to_str().unwrap()
                    )
                })?;

            let mut mw = Self::from(cassette);
            mw.path = Some(pb);
            Ok(mw)
        }
    }

    type Error = String;
}
