# OIDCRS

Full Spec Compliant OIDC Library.

Work in Progress. Please, don't use it in production.

```rs
cargo add oidcrs
```

## Examples

##### The Authorization Code Flow.

1. Client prepares an Authentication Request containing the desired request parameters.
2. Client sends the request to the Authorization Server.
3. Authorization Server Authenticates the End-User.
4. Authorization Server obtains End-User Consent/Authorization.
5. Authorization Server sends the End-User back to the Client with an Authorization Code.
6. Client requests a response using the Authorization Code at the Token Endpoint.
7. Client receives a response that contains an ID Token and Access Token in the response body.
8. Client validates the ID token and retrieves the End-User's Subject Identifier.

```rs
let oidc_uri = "https://_/.well-known/openid-configuration";

let client = AuthorizationCodeFlowClient::new(oidc_uri)
    .with_scope(AuthenticationRequestScope::Profile)
    .with_scope(AuthenticationRequestScope::Email)
    .with_scope(AuthenticationRequestScope::Unchecked("api://_/.default"));

let authorization_endpoint = client.build_authorization_endpoint().await?;

// redirect the user to the `authorization_endpoint` the first time

let authorization_code = client.extract_authorization_code(&returned_url)?;
let authorization_tokens = client.fetch_authorization_tokens(&authorization_code).await?;

println!("{:?}", authorization_tokens.id_token);
println!("{:?}", authorization_tokens.access_token);
```

## RFCs

- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
