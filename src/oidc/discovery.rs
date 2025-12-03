use serde::Deserialize;

#[derive(Deserialize)]
pub struct OpenIDConnectEndpoints {
    pub token_endpoint: String,
    pub authorization_endpoint: String,
}

impl OpenIDConnectEndpoints {
    // TODO: add cache strategy
    pub async fn from_remote(http: &reqwest::Client, oidc_uri: &str) -> anyhow::Result<Self> {
        let conf = http.get(oidc_uri).send().await?.json::<Self>().await?;
        Ok(conf)
    }
}
