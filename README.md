rvcr
====

[![crates.io](https://img.shields.io/crates/v/rvcr.svg)](https://crates.io/crates/rvcr)

Record-and-replay testing middleware for `reqwest` http client.

Inspired by:
  - [Ruby-VCR](https://github.com/vcr/vcr)
  - [Surf-VCR](https://git.sr.ht/~rjframe/surf-vcr)


Builds on top of:
 - [reqwest-middleware](https://github.com/TrueLayer/reqwest-middleware)
 - [VCR-cassette](https://github.com/http-rs/vcr-cassette/)

 # Examples

To record HTTP requests, initialize client like following

```rust
  use std::path::PathBuf;
  use reqwest::Client;
  use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
  use rvcr::{VCRMiddleware, VCRMode};

  let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  bundle.push("tests/resources/replay.vcr.json");

  let middleware: VCRMiddleware = VCRMiddleware::try_from(bundle.clone())
      .unwrap()
      .with_mode(VCRMode::Record);

  let vcr_client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
      .with(middleware)
      .build();
```

Now `ClientWithMiddleware` instance will be recording requests to a file
located in `tests/resources/replay.vcr.json` inside the project.

To use recorded VCR cassette files, replace `.with_mode(VCRMode::Record)`
with `.with_mode(VCRMode::Replay)`, or omit it, since replay is used by default.

## Search mode

When replaying, rVCR can skip requests already found when searching for
subsequent requests (the default). To disable skipping requests,
which is useful, for example, if requests are done in parallel and responses
may come in random order, use `.with_search(VCRReplaySearch::SearchAll)`.

## Filtering sensitive information

Your requests and responses may contain sensitive information such as authentication details, user
information etc. which you don't want to commit to your source control.

You can modify requests and responses before they are stored and restored using
`with_modify_request` and `with_modify_response`.

You can change anything in the body, URI, headers etc. to hide any information you want. Here's an
example which filters sensitive information in query parameters:

```rust
  let middleware = VCRMiddleware::try_from(bundle.clone())
      .unwrap()
      .with_mode(VCR::Record)
      .with_modify_request(|req| {
          let sensitive_query_params = ["access_token", "appsecret_proof"];

          // Replace sensitive data in query params
          let filtered_query_params = req.uri.clone().query_pairs().map(|(k, v)| {
              if sensitive_query_params.contains(&k.as_ref()) {
                  (k.clone(), Cow::from(k.to_uppercase()))
              } else {
                  (k, v)
              }
          });

          // Overwrite query params with filtered ones
          req.uri
              .query_pairs_mut()
              .clear()
              .extend_pairs(filtered_query_params)
              .finish();
      });
```

## VCR cassette fie compression

Sometimes VCR files can be too large and this harder to maintain in a
version control system.

To save some space and turn on bzip2 compression for artifacts,
use `.compression(true)` method of the builder.
