use std::sync::Arc;

use tokio::sync::Mutex;
use tracing_subscriber::{
    filter, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, Layer,
};

mod e2e;
mod modifiers;

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

lazy_static::lazy_static! {
    static ref SCOPE: TestScope = TestScope::default();
    static ref ADDRESS: String = String::from("http://127.0.0.1:38282");
}
