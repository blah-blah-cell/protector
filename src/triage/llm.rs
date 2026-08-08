//! Optional external LLM triage backend (feature: `llm`).
//!
//! Speaks a small OpenAI-compatible chat-completions protocol (works with
//! Ollama, vLLM, LM Studio, OpenAI, ...) and returns a free-form rationale for
//! a suspicious flow. Enforcement decisions always come from the signal engine
//! so the data plane stays deterministic and sub-millisecond.

use anyhow::Result;

#[cfg(feature = "llm")]
use anyhow::Context;

#[cfg(feature = "llm")]
mod backend {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[derive(Clone)]
    pub struct LlmBackend {
        client: reqwest::Client,
        url: String,
        model: String,
        api_key: Option<String>,
    }

    impl LlmBackend {
        pub fn from_env() -> Option<Self> {
            let url = std::env::var("ZQFW_LLM_URL").ok()?;
            let model = std::env::var("ZQFW_LLM_MODEL").unwrap_or_else(|_| "llama3.1".into());
            let api_key = std::env::var("ZQFW_LLM_API_KEY").ok();
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .ok()?;
            Some(LlmBackend { client, url, model, api_key })
        }

        /// Ask the model to produce a short security rationale for a flow.
        pub async fn review(&self, summary: &str) -> Result<String> {
            let system = "You are the triage controller of a zero-trust eBPF \
                firewall. Given a suspicious flow summary, output a terse \
                security rationale (2-3 sentences) naming the observed signals, \
                whether quarantine is warranted, and why. No preamble.";
            let body = json!({
                "model": self.model,
                "messages": [
                    { "role": "system", "content": system },
                    { "role": "user", "content": summary }
                ],
                "temperature": 0.2,
                "max_tokens": 120
            });
            let mut req = self.client.post(&self.url).json(&body);
            if let Some(key) = &self.api_key {
                req = req.bearer_auth(key);
            }
            let resp = req.send().await.context("LLM request failed")?;
            let status = resp.status();
            if !status.is_success() {
                anyhow::bail!("LLM returned HTTP {status}");
            }
            let v: serde_json::Value = resp.json().await.context("LLM response unparseable")?;
            let text = v["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .to_string();
            if text.is_empty() {
                anyhow::bail!("LLM returned empty content");
            }
            Ok(text)
        }
    }
}

#[cfg(feature = "llm")]
pub use backend::LlmBackend;

#[cfg(not(feature = "llm"))]
#[derive(Clone, Debug, Default)]
pub struct LlmBackend;

#[cfg(not(feature = "llm"))]
impl LlmBackend {
    pub fn from_env() -> Option<Self> {
        None
    }
    pub async fn review(&self, _summary: &str) -> Result<String> {
        anyhow::bail!("the `llm` cargo feature is not enabled")
    }
}
