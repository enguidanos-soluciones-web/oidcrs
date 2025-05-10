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
//! All but the code Response Type value, which is defined by OAuth 2.0 [RFC6749](https://openid.net/specs/openid-connect-core-1_0.html#RFC6749),
//! are defined in the OAuth 2.0 Multiple Response Type Encoding Practices
//! [OAuth.Responses](https://openid.net/specs/openid-connect-core-1_0.html#OAuth.Responses) specification.
//!
//! NOTE: While OAuth 2.0 also defines the token Response Type value for the Implicit Flow, OpenID Connect does not
//! use this Response Type, since no ID Token would be returned.
//!
//! [RFC OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

use derive_more::Display;

pub enum AuthenticationFlow {
    AuthorizationCodeFlow,
    ImplicitFlow { token: bool },
    HybridFlow { token: bool, id_token: bool },
}

impl AuthenticationFlow {
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
pub enum AuthenticationRequestParameters {
    #[display("code")]
    Code,
    #[display("response_type")]
    ResponseType,
    #[display("scope")]
    Scope,
}

#[derive(Display)]
pub enum AuthenticationRequestScope {
    #[display("openid")]
    OpenID,
    #[display("profile")]
    Profile,
    #[display("email")]
    Email,
    #[display("address")]
    Address,
    #[display("phone")]
    Phone,
    #[display("offline_access")]
    OfflineAccess,
    #[display("{}", _0)]
    Unchecked(&'static str),
}

#[cfg(test)]
mod tests {

    use super::AuthenticationFlow;

    use pretty_assertions::assert_eq;

    #[test]
    fn check_response_type_of_authorization_code_flow() {
        assert_eq!(AuthenticationFlow::AuthorizationCodeFlow.as_reponse_type(), "code");
    }
    #[test]
    fn check_response_type_of_implicit_flow() {
        assert_eq!(
            AuthenticationFlow::ImplicitFlow { token: false }.as_reponse_type(),
            "id_token"
        );
        assert_eq!(
            AuthenticationFlow::ImplicitFlow { token: true }.as_reponse_type(),
            "id_token token"
        );
    }
    #[test]
    fn check_response_type_of_hybrid_flow() {
        assert_eq!(
            AuthenticationFlow::HybridFlow {
                token: false,
                id_token: false
            }
            .as_reponse_type(),
            "code id_token"
        );

        assert_eq!(
            AuthenticationFlow::HybridFlow {
                token: true,
                id_token: false
            }
            .as_reponse_type(),
            "code token"
        );

        assert_eq!(
            AuthenticationFlow::HybridFlow {
                token: false,
                id_token: true
            }
            .as_reponse_type(),
            "code id_token"
        );

        assert_eq!(
            AuthenticationFlow::HybridFlow {
                token: true,
                id_token: true
            }
            .as_reponse_type(),
            "code id_token token"
        );
    }
}

pub mod authorization_code_flow {
    use serde::Deserialize;
    use url::Url;

    use crate::{config, id_token};

    use super::{AuthenticationFlow, AuthenticationRequestParameters, AuthenticationRequestScope};

    #[derive(Deserialize)]
    pub struct AuthorizationCodeFlowTokenResponse {
        pub id_token: id_token::IDToken,
        pub access_token: String,
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
    ///     let authorization_endpoint = client.build_authorization_endpoint().await?;
    ///
    ///     // redirect the user to the `authorization_endpoint` the first time
    ///
    ///     let authorization_code = client.extract_authorization_code(&returned_url)?;
    ///     let authorization_tokens = client.fetch_authorization_tokens(&authorization_code).await?;
    ///
    ///     println!("{}", authorization_tokens.id_token);
    ///     println!("{}", authorization_tokens.access_token);
    ///
    /// ```
    #[non_exhaustive]
    pub struct AuthorizationCodeFlowClient {
        flow: AuthenticationFlow,
        http: reqwest::Client,
        oidc_uri: String,
        scopes: Vec<AuthenticationRequestScope>,
    }

    impl AuthorizationCodeFlowClient {
        pub fn new(oidc_uri: &str) -> Self {
            Self {
                flow: AuthenticationFlow::AuthorizationCodeFlow,
                http: reqwest::Client::new(),
                oidc_uri: oidc_uri.to_owned(),
                scopes: vec![AuthenticationRequestScope::OpenID],
            }
        }

        /// OpenID Connect requests MUST contain the openid scope value. If the openid scope value is not present,
        /// the behavior is entirely unspecified. Other scope values MAY be present. Scope values used that are
        /// not understood by an implementation SHOULD be ignored. See Sections
        /// [5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
        /// and [11](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess)
        /// for additional scope values defined by this specification.
        ///
        /// NOTE: This implementation adds scope `openid` as default.
        ///
        /// ## Examples
        ///
        /// ```
        ///     let oidc_uri = "https://_/.well-known/openid-configuration";
        ///
        ///     let client = AuthorizationCodeFlowClient::new(oidc_uri)
        ///         .with_scope(Scope::Profile)
        ///         .with_scope(Scope::Email)
        ///         .with_scope(Scope::Address)
        ///         .with_scope(Scope::Phone);
        ///
        /// ```
        pub fn with_scope(mut self, s: AuthenticationRequestScope) -> Self {
            match s {
                AuthenticationRequestScope::OpenID => self,
                _ => {
                    self.scopes.push(s);
                    self
                }
            }
        }

        /// **Authorization Endpoint**
        ///
        /// The Authorization Endpoint performs Authentication of the End-User.
        /// This is done by sending the User Agent to the Authorization Server's Authorization
        /// Endpoint for Authentication and Authorization, using request parameters defined by OAuth 2.0
        /// and additional parameters and parameter values defined by OpenID Connect.
        ///
        /// Communication with the Authorization Endpoint MUST utilize TLS. See
        /// [Section 16.17](https://openid.net/specs/openid-connect-core-1_0.html#TLSRequirements)
        /// for more information on using TLS.
        pub async fn build_authorization_endpoint(&self) -> anyhow::Result<Url> {
            let conf = config::OpenIDConfiguration::from_remote(&self.http, &self.oidc_uri).await?;

            let mut authorization_endpoint = Url::parse(&conf.authorization_endpoint)?;

            if authorization_endpoint.scheme() != "https" {
                anyhow::bail!("authorization endpoint must be TLS");
            }

            let request_params = [
                (
                    AuthenticationRequestParameters::Scope.to_string(),
                    self.scopes.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" "),
                ),
                (
                    AuthenticationRequestParameters::ResponseType.to_string(),
                    self.flow.as_reponse_type().to_owned(),
                ),
            ];

            for (key, value) in request_params.iter() {
                authorization_endpoint.query_pairs_mut().append_pair(key, value);
            }

            Ok(authorization_endpoint)
        }

        pub async fn fetch_authorization_tokens(&self, code: &str) -> anyhow::Result<AuthorizationCodeFlowTokenResponse> {
            let conf = config::OpenIDConfiguration::from_remote(&self.http, &self.oidc_uri).await?;
            let mut token_endpoint = Url::parse(&conf.token_endpoint)?;
            let request_params = [(AuthenticationRequestParameters::Code.to_string(), code)];

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

        pub fn extract_authorization_code(&self, url: &str) -> anyhow::Result<String> {
            let url = Url::parse(url)?;

            let Some(code) = url
                .query_pairs()
                .find(|n| n.0 == AuthenticationRequestParameters::Code.to_string())
            else {
                anyhow::bail!("Code not found in provided url");
            };

            Ok(code.1.into_owned())
        }
    }

    #[cfg(test)]
    mod tests {
        use axum::{Json, Router, routing::get};
        use serde_json::json;
        use tokio::net::TcpListener;

        use crate::authentication::{AuthenticationRequestParameters, AuthenticationRequestScope};

        use super::AuthorizationCodeFlowClient;

        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn authorization_endpoint_is_tls() {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let oidc_uri_path = "/.well-known/openid-configuration";

            tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route(
                        oidc_uri_path,
                        get(|| async {
                            Json(json!({
                                "token_endpoint": "https://_/token",
                                "authorization_endpoint": "https://_/authorize"
                            }))
                        }),
                    ),
                )
                .await
                .unwrap()
            });

            let oidc_uri = format!(
                "http://{ip}:{port}{path}",
                ip = addr.ip(),
                port = addr.port(),
                path = oidc_uri_path
            );

            let client = AuthorizationCodeFlowClient::new(&oidc_uri);
            let authorization_endpoint = client.build_authorization_endpoint().await;
            assert!(matches!(authorization_endpoint, Ok(_)));
        }

        #[tokio::test]
        async fn authorization_endpoint_must_be_tls() {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let oidc_uri_path = "/.well-known/openid-configuration";

            tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route(
                        oidc_uri_path,
                        get(|| async {
                            Json(json!({
                                "token_endpoint": "http://_/token",
                                "authorization_endpoint": "http://_/authorize"
                            }))
                        }),
                    ),
                )
                .await
                .unwrap()
            });

            let oidc_uri = format!(
                "http://{ip}:{port}{path}",
                ip = addr.ip(),
                port = addr.port(),
                path = oidc_uri_path
            );

            let client = AuthorizationCodeFlowClient::new(&oidc_uri);
            let authorization_endpoint = client.build_authorization_endpoint().await;
            assert!(matches!(authorization_endpoint, Err(_)));
        }

        #[tokio::test]
        async fn authorization_request_param_response_type_must_be_correct() {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let oidc_uri_path = "/.well-known/openid-configuration";

            tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route(
                        oidc_uri_path,
                        get(|| async {
                            Json(json!({
                                "token_endpoint": "https://_/token",
                                "authorization_endpoint": "https://_/authorize"
                            }))
                        }),
                    ),
                )
                .await
                .unwrap()
            });

            let oidc_uri = format!(
                "http://{ip}:{port}{path}",
                ip = addr.ip(),
                port = addr.port(),
                path = oidc_uri_path
            );

            let client = AuthorizationCodeFlowClient::new(&oidc_uri);

            let authorization_endpoint = client.build_authorization_endpoint().await.unwrap();

            assert_eq!(
                authorization_endpoint
                    .query_pairs()
                    .find(|n| n.0 == AuthenticationRequestParameters::ResponseType.to_string())
                    .map(|n| n.1.into_owned()),
                Some(String::from("code"))
            );
        }

        #[tokio::test]
        async fn authorization_request_param_scope_must_be_openid() {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let oidc_uri_path = "/.well-known/openid-configuration";

            tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route(
                        oidc_uri_path,
                        get(|| async {
                            Json(json!({
                                "token_endpoint": "https://_/token",
                                "authorization_endpoint": "https://_/authorize"
                            }))
                        }),
                    ),
                )
                .await
                .unwrap()
            });

            let oidc_uri = format!(
                "http://{ip}:{port}{path}",
                ip = addr.ip(),
                port = addr.port(),
                path = oidc_uri_path
            );

            let client = AuthorizationCodeFlowClient::new(&oidc_uri);

            let authorization_endpoint = client.build_authorization_endpoint().await.unwrap();

            assert_eq!(
                authorization_endpoint
                    .query_pairs()
                    .find(|n| n.0 == AuthenticationRequestParameters::Scope.to_string())
                    .map(|n| n.1.into_owned()),
                Some(AuthenticationRequestScope::OpenID.to_string())
            );
        }

        #[tokio::test]
        async fn authorization_request_param_scope_can_be_added() {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let oidc_uri_path = "/.well-known/openid-configuration";

            tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route(
                        oidc_uri_path,
                        get(|| async {
                            Json(json!({
                                "token_endpoint": "https://_/token",
                                "authorization_endpoint": "https://_/authorize"
                            }))
                        }),
                    ),
                )
                .await
                .unwrap()
            });

            let oidc_uri = format!(
                "http://{ip}:{port}{path}",
                ip = addr.ip(),
                port = addr.port(),
                path = oidc_uri_path
            );

            let client = AuthorizationCodeFlowClient::new(&oidc_uri)
                .with_scope(AuthenticationRequestScope::Email)
                .with_scope(AuthenticationRequestScope::Address)
                .with_scope(AuthenticationRequestScope::Phone)
                .with_scope(AuthenticationRequestScope::Profile)
                .with_scope(AuthenticationRequestScope::OfflineAccess)
                .with_scope(AuthenticationRequestScope::Unchecked("api://_/.default"));

            let authorization_endpoint = client.build_authorization_endpoint().await.unwrap();

            assert_eq!(
                authorization_endpoint
                    .query_pairs()
                    .find(|n| n.0 == AuthenticationRequestParameters::Scope.to_string())
                    .map(|n| n.1.into_owned()),
                Some(String::from(
                    "openid email address phone profile offline_access api://_/.default"
                ))
            );
        }

        #[tokio::test]
        async fn authorization_request_param_scope_type_openid_can_only_be_added_once() {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let oidc_uri_path = "/.well-known/openid-configuration";

            tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route(
                        oidc_uri_path,
                        get(|| async {
                            Json(json!({
                                "token_endpoint": "https://_/token",
                                "authorization_endpoint": "https://_/authorize"
                            }))
                        }),
                    ),
                )
                .await
                .unwrap()
            });

            let oidc_uri = format!(
                "http://{ip}:{port}{path}",
                ip = addr.ip(),
                port = addr.port(),
                path = oidc_uri_path
            );

            let client = AuthorizationCodeFlowClient::new(&oidc_uri)
                .with_scope(AuthenticationRequestScope::OpenID)
                .with_scope(AuthenticationRequestScope::OpenID);

            let authorization_endpoint = client.build_authorization_endpoint().await.unwrap();

            assert_eq!(
                authorization_endpoint
                    .query_pairs()
                    .find(|n| n.0 == AuthenticationRequestParameters::Scope.to_string())
                    .map(|n| n.1.into_owned()),
                Some(AuthenticationRequestScope::OpenID.to_string())
            );
        }
    }
}
