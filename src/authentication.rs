//! Authentication
//!
//! OpenID Connect performs authentication to log in the End-User or to determine that the End-User is already logged in.
//! OpenID Connect returns the result of the Authentication performed by the Server to the Client in a secure manner so that
//! the Client can rely on it. For this reason, the Client is called Relying Party (RP) in this case.
//!
//! The Authentication result is returned in an ID Token, as defined in [Section 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken). It has Claims expressing such
//! information as the Issuer, the Subject Identifier, when the authentication was performed, etc.
//!
//! Authentication can follow one of three paths: the Authorization Code Flow (`response_type=code`),
//! the Implicit Flow (`response_type=id_token token` or `response_type=id_token`), or the Hybrid Flow
//! (using other Response Type values defined in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses](https://openid.net/specs/openid-connect-core-1_0.html#OAuth.Responses)).
//! The flows determine how the ID Token and Access Token are returned to the Client.
//!
//! | Property | Authorization Code Flow | Implicit Flow | Hybrid Flow |
//! |----------|-------------------------|---------------|-------------|
//! | All tokens returned from Authorization Endpoint | no | yes | no |
//! | All tokens returned from Token Endpoint | yes | no | no |
//! | Tokens not revealed to User Agent | yes | no | no |
//! | Client can be authenticated | yes | no | yes |
//! | Refresh Token possible | yes | no | yes |
//! | Communication in one round trip | no | yes | no |
//! | Most communication server-to-server | yes | no | varies |
//!
//! The flow used is determined by the response_type value contained in the Authorization Request. These response_type values select these flows:
//!
//! | "response_type" value | Flow |
//! |----------------------|------|
//! | code | Authorization Code Flow |
//! | id_token | Implicit Flow |
//! | id_token token | Implicit Flow |
//! | code id_token | Hybrid Flow |
//! | code token | Hybrid Flow |
//! | code id_token token | Hybrid Flow |
//!
//! All but the code Response Type value, which is defined by OAuth 2.0 [RFC6749](https://openid.net/specs/openid-connect-core-1_0.html#RFC6749), are defined
//! in the OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses](https://openid.net/specs/openid-connect-core-1_0.html#OAuth.Responses) specification.
//!
//! NOTE: While OAuth 2.0 also defines the token Response Type value for the Implicit Flow, OpenID Connect does not
//! use this Response Type, since no ID Token would be returned.
//!
//! [RFC OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

use derive_more::Display;
use serde::Deserialize;
use url::Url;

use crate::{config, id_token};

pub enum Flow {
    AuthorizationCodeFlow,
    ImplicitFlow { token: bool },
    HybridFlow { token: bool, id_token: bool },
}

impl Flow {
    pub fn as_reponse_type(&self) -> &'static str {
        match self {
            Self::AuthorizationCodeFlow => "code",
            Self::ImplicitFlow { token: with_token } => {
                if *with_token {
                    "id_token token"
                } else {
                    "id_token"
                }
            }
            Self::HybridFlow {
                token: with_token,
                id_token: with_id_token,
            } => {
                if *with_token && *with_id_token {
                    "code id_token token"
                } else if *with_token && !*with_id_token {
                    "code token"
                } else if !*with_token && *with_id_token {
                    "code id_token"
                } else {
                    tracing::warn!("Using HybridFlow without tokens fallbacks to 'code id_token'");

                    "code id_token"
                }
            }
        }
    }
}

#[derive(Display)]
pub enum RequestParameters {
    #[display("code")]
    Code,
    #[display("response_type")]
    ResponseType,
}

/// ## The Authorization Code Flow.
///
/// 1. Client prepares an Authentication Request containing the desired request parameters.
/// 2. Client sends the request to the Authorization Server.
/// 3. Authorization Server Authenticates the End-User.
/// 4. Authorization Server obtains End-User Consent/Authorization.
/// 5. Authorization Server sends the End-User back to the Client with an Authorization Code.
/// 6. Client requests a response using the Authorization Code at the Token Endpoint.
/// 7. Client receives a response that contains an ID Token and Access Token in the response body.
/// 8. Client validates the ID token and retrieves the End-User's Subject Identifier.
///
/// [Open ID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
///
/// ## Examples
///
/// ```
///     let oidc_uri = "https://_/.well-known/openid-configuration";
///
///     let client = AuthorizationCodeFlowClient::new(oidc_uri);
///     let authentication_request = client.prepare_authentication_request().await?;
///
///     // redirect the user to the `authentication_request` the first time
///
///     let authentication_code = client.extract_authentication_code(&returned_url)?;
///     let authentication_tokens = client.do_authentication_token_request(&authentication_code).await?;
///
///     println!("{}", authentication_tokens.id_token);
///     println!("{}", authentication_tokens.access_token);
///
/// ```
#[non_exhaustive]
pub struct AuthorizationCodeFlowClient {
    flow: Flow,
    http: reqwest::Client,
    oidc_uri: String,
}

#[derive(Deserialize)]
pub struct AuthorizationCodeFlowTokenResponse {
    pub id_token: id_token::IDToken,
    pub access_token: String,
}

impl AuthorizationCodeFlowClient {
    pub fn new(oidc_uri: &str) -> Self {
        Self {
            flow: Flow::AuthorizationCodeFlow,
            http: reqwest::Client::new(),
            oidc_uri: oidc_uri.to_owned(),
        }
    }

    pub async fn prepare_authentication_request(&self) -> anyhow::Result<Url> {
        let conf = config::OpenIDConfiguration::from_remote(&self.http, &self.oidc_uri).await?;
        let request_params = [(RequestParameters::ResponseType.to_string(), self.flow.as_reponse_type())];
        let mut authorization_endpoint = Url::parse(&conf.authorization_endpoint)?;

        for (key, value) in request_params.iter() {
            authorization_endpoint.query_pairs_mut().append_pair(key, value);
        }

        Ok(authorization_endpoint)
    }

    pub async fn do_authentication_token_request(&self, code: &str) -> anyhow::Result<AuthorizationCodeFlowTokenResponse> {
        let conf = config::OpenIDConfiguration::from_remote(&self.http, &self.oidc_uri).await?;
        let mut token_endpoint = Url::parse(&conf.token_endpoint)?;
        let request_params = [(RequestParameters::Code.to_string(), code)];

        for (key, value) in request_params.iter() {
            token_endpoint.query_pairs_mut().append_pair(key, value);
        }

        let token_response = self
            .http
            .post(token_endpoint.as_str())
            .form(&request_params)
            .send()
            .await?
            .json::<AuthorizationCodeFlowTokenResponse>()
            .await?;

        token_response.id_token.validate()?;
        Ok(token_response)
    }

    pub fn extract_authentication_code(&self, url: &str) -> anyhow::Result<String> {
        let url = Url::parse(url)?;

        let Some(code) = url.query_pairs().find(|n| n.0 == "code") else {
            anyhow::bail!("Code not found in provided url");
        };

        Ok(code.1.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::Flow;

    use pretty_assertions::assert_eq;

    #[test]
    fn check_response_type_of_authorization_code_flow() {
        assert_eq!(Flow::AuthorizationCodeFlow.as_reponse_type(), "code");
    }
    #[test]
    fn check_response_type_of_implicit_flow() {
        assert_eq!(Flow::ImplicitFlow { token: false }.as_reponse_type(), "id_token");
        assert_eq!(Flow::ImplicitFlow { token: true }.as_reponse_type(), "id_token token");
    }
    #[test]
    fn check_response_type_of_hybrid_flow() {
        assert_eq!(
            Flow::HybridFlow {
                token: false,
                id_token: false
            }
            .as_reponse_type(),
            "code id_token"
        );

        assert_eq!(
            Flow::HybridFlow {
                token: true,
                id_token: false
            }
            .as_reponse_type(),
            "code token"
        );

        assert_eq!(
            Flow::HybridFlow {
                token: false,
                id_token: true
            }
            .as_reponse_type(),
            "code id_token"
        );

        assert_eq!(
            Flow::HybridFlow {
                token: true,
                id_token: true
            }
            .as_reponse_type(),
            "code id_token token"
        );
    }
}
