use serde::Deserialize;

#[derive(Deserialize)]
pub struct OpenIDConfiguration {
    pub token_endpoint: String,
    pub authorization_endpoint: String,
}

impl OpenIDConfiguration {
    // TODO: add cache strategy
    pub async fn from_remote(http: &reqwest::Client, oidc_uri: &str) -> anyhow::Result<Self> {
        let conf = http.get(oidc_uri).send().await?.json::<Self>().await?;
        Ok(conf)
    }
}
