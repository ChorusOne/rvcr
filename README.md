rvcr
====

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
  bundle.push("tests/resources/test.vcr");

  let middleware: VCRMiddleware = VCRMiddleware::try_from(bundle.clone())
      .unwrap()
      .with_mode(VCRMode::Record);

  let vcr_client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
      .with(middleware)
      .build();
```

Now `ClientWithMiddleware` instance will be recording requests to a file
located in `tests/resources/test.vcr` inside the project.

To use recorded VCR cassette files, replace `.with_mode(VCRMode::Record)`
with `.with_mode(VCRMode::Replay)`, or omit it, since replay is used by default.
