//! ID Token
//!
//! The primary extension that OpenID Connect makes to OAuth 2.0 to enable End-Users to be Authenticated
//! is the ID Token data structure. The ID Token is a security token that contains Claims about the Authentication
//! of an End-User by an Authorization Server when using a Client, and potentially other requested Claims.
//! The ID Token is represented as a [JSON Web Token (JWT)](https://openid.net/specs/openid-connect-core-1_0.html#JWT).
//!
//! [RFC OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::{ops::Deref, str::FromStr};
use url::Url;

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct IDToken {
    /// **REQUIRED**
    ///
    /// Issuer Identifier for the Issuer of the response.
    /// The iss value is a case-sensitive URL using the https scheme that contains scheme, host, and optionally,
    /// port number and path components and no query or fragment components.
    pub iss: IssuerIdentifier,

    /// **REQUIRED**
    ///
    /// Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User,
    /// which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
    /// It MUST NOT exceed 255 ASCII [RFC20](https://openid.net/specs/openid-connect-core-1_0.html#RFC20) characters in length.
    /// The sub value is a case-sensitive string.
    pub sub: SubjectIdentifier,

    /// **REQUIRED**
    ///
    /// Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 `client_id` of the Relying Party
    /// as an audience value. It MAY also contain identifiers for other audiences. In the general case, the `aud` value
    /// is an array of case-sensitive strings. In the common special case when there is one audience, the `aud` value MAY
    /// be a single case-sensitive string.
    pub aud: Audience,

    /// **REQUIRED**
    ///
    /// Expiration time on or after which the ID Token MUST NOT be accepted by the RP when performing authentication with the OP.
    /// The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value is a
    /// JSON [RFC8259](https://openid.net/specs/openid-connect-core-1_0.html#RFC8259) number representing the number of seconds
    /// from 1970-01-01T00:00:00Z as measured in UTC until the date/time. See RFC 3339 [RFC3339](https://openid.net/specs/openid-connect-core-1_0.html#RFC3339)
    /// for details regarding date/times in general and UTC in particular.
    ///
    /// > NOTE: The ID Token expiration time is unrelated the lifetime of the authenticated session between the RP and the OP.
    pub exp: Expiration,

    /// **REQUIRED**
    ///
    /// Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured
    /// in UTC until the date/time.
    pub iat: IssuedAt,

    /// **OPTIONAL**
    ///
    /// String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified
    /// from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the `nonce` Claim Value is equal
    /// to the value of the `nonce` parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers
    /// MUST include a `nonce` Claim in the ID Token with the Claim Value being the `nonce` value sent in the Authentication Request.
    /// Authorization Servers SHOULD perform no other processing on `nonce` values used. The `nonce` value is a case-sensitive string.
    pub nonce: Option<Nonce>,
    //
    // TODO: auth_time, acr, amr, azp
}

impl IDToken {
    /// **ID Token Validation**
    ///
    /// Clients MUST validate the ID Token in the Token Response in the following manner:
    ///
    /// 1. If the ID Token is encrypted, decrypt it using the keys and algorithms that the Client specified during
    ///    Registration that the OP was to use to encrypt the ID Token. If encryption was negotiated with the OP at
    ///    Registration time and the ID Token is not encrypted, the RP SHOULD reject it.
    ///
    /// 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST
    ///    exactly match the value of the `iss` (issuer) Claim.
    ///
    /// 3. The Client MUST validate that the `aud` (audience) Claim contains its `client_id` value registered at
    ///    the Issuer identified by the `iss` (issuer) Claim as an audience. The `aud` (audience) Claim MAY contain
    ///    an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client
    ///    as a valid audience, or if it contains additional audiences not trusted by the Client.
    ///
    /// 4. If the implementation is using extensions (which are beyond the scope of this specification) that result
    ///    in the `azp` (authorized party) Claim being present, it SHOULD validate the `azp` value as specified by those extensions.
    ///
    /// 5. This validation MAY include that when an `azp` (authorized party) Claim is present, the Client SHOULD verify
    ///    that its `client_id` is the Claim Value.
    ///
    /// 6. If the ID Token is received via direct communication between the Client and the Token Endpoint (which it is in this flow),
    ///    the TLS server validation MAY be used to validate the issuer in place of checking the token signature.
    ///    The Client MUST validate the signature of all other ID Tokens according to [JWS](https://openid.net/specs/openid-connect-core-1_0.html#JWS)
    ///    using the algorithm specified in the JWT `alg` Header Parameter. The Client MUST use the keys provided by the Issuer.
    ///
    /// 7. The `alg` value SHOULD be the default of `RS256` or the algorithm sent by the Client in the `id_token_signed_response_alg` parameter during Registration.
    ///
    /// 8. If the JWT `alg` Header Parameter uses a MAC based algorithm such as `HS256`, `HS384`, or `HS512`, the octets of
    ///    the UTF-8 [RFC3629](https://openid.net/specs/openid-connect-core-1_0.html#RFC3629) representation of the `client_secret` corresponding
    ///    to the `client_id` contained in the `aud` (audience) Claim are used as the key to validate the signature.
    ///    For MAC based algorithms, the behavior is unspecified if the `aud` is multi-valued.
    ///
    /// 9. The current time MUST be before the time represented by the `exp` Claim.
    ///
    /// 10. The `iat` Claim can be used to reject tokens that were issued too far away from the current time, limiting the
    ///     amount of time that nonces need to be stored to prevent attacks. The acceptable range is Client specific.
    ///
    /// 11. If a nonce value was sent in the Authentication Request, a `nonce` Claim MUST be present and its value checked to
    ///     verify that it is the same value as the one that was sent in the Authentication Request. The Client SHOULD check the
    ///     `nonce` value for replay attacks. The precise method for detecting replay attacks is Client specific.
    ///
    /// 12. If the `acr` Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate.
    ///     The meaning and processing of `acr` Claim Values is out of scope for this specification.
    ///
    /// 13. If the `auth_time` Claim was requested, either through a specific request for this Claim or by using the `max_age`
    ///     parameter, the Client SHOULD check the `auth_time` Claim value and request re-authentication if it determines too much
    ///     time has elapsed since the last End-User authentication.
    ///
    pub fn validate(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IssuerIdentifier {
    value: String,
}

impl Deref for IssuerIdentifier {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl FromStr for IssuerIdentifier {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed_url = Url::parse(s).map_err(|_| anyhow::Error::msg("Impossible to parse proposed issuer as url"))?;

        if parsed_url.query().is_some() {
            anyhow::bail!("Issuer can't have query component on url");
        }
        if parsed_url.fragment().is_some() {
            anyhow::bail!("Issuer can't have fragment component on url");
        }

        Ok(Self { value: s.into() })
    }
}

impl<'de> Deserialize<'de> for IssuerIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SubjectIdentifier {
    value: String,
}

impl Deref for SubjectIdentifier {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl FromStr for SubjectIdentifier {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 255 {
            anyhow::bail!("Subject identifier can't be longer than 255");
        }
        if !s.is_ascii() {
            anyhow::bail!("Subject identifier can't be non ascii");
        }

        Ok(Self { value: s.into() })
    }
}

impl<'de> Deserialize<'de> for SubjectIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Audience {
    value: Vec<String>,
}

impl Deref for Audience {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl From<&str> for Audience {
    fn from(value: &str) -> Self {
        Self {
            value: vec![value.into()],
        }
    }
}
impl From<&[&str]> for Audience {
    fn from(value: &[&str]) -> Self {
        Self {
            value: value.iter().copied().map(|n| n.to_owned()).collect(),
        }
    }
}

struct AudienceVisitor;

impl<'de> Visitor<'de> for AudienceVisitor {
    type Value = Audience;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("string or string vec")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Audience {
            value: vec![value.to_string()],
        })
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Audience { value: vec![value] })
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut value = Vec::new();

        while let Some(element) = seq.next_element()? {
            value.push(element);
        }

        Ok(Audience { value })
    }
}

// Ahora implementamos Deserialize usando nuestro visitante personalizado
impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(AudienceVisitor)
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Expiration {
    value: i64,
}

impl Deref for Expiration {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl TryFrom<chrono::Duration> for Expiration {
    type Error = anyhow::Error;

    fn try_from(value: chrono::Duration) -> Result<Self, Self::Error> {
        // The spec says that `The processing of this parameter requires that the current date/time MUST
        // be before the expiration date/time listed in the value` but there is no way to exactly match
        // these constraint from e2e user perspective. A minimum seconds delay is assigned.
        if value.num_seconds() < 10 {
            anyhow::bail!("Expiration duration needs to be greater than 10 seconds")
        }

        Ok(Self {
            value: (chrono::Utc::now() + value).timestamp(),
        })
    }
}

impl<'de> Deserialize<'de> for Expiration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IssuedAt {
    value: i64,
}

impl Deref for IssuedAt {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl IssuedAt {
    pub fn now() -> Self {
        Self {
            value: chrono::Utc::now().timestamp(),
        }
    }
}

impl<'de> Deserialize<'de> for IssuedAt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Nonce {
    value: String,
}

impl Deref for Nonce {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Default for Nonce {
    fn default() -> Self {
        let mut buffer = [0u8; 12];
        rand::rng().fill_bytes(&mut buffer);

        Self {
            value: URL_SAFE_NO_PAD.encode(buffer),
        }
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

#[cfg(test)]
mod tests {
    use crate::id_token::{Expiration, IssuedAt, SubjectIdentifier};
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::str::FromStr;

    use super::{IDToken, IssuerIdentifier};

    #[test]
    fn issuer_must_be_complaint() {
        let iss = IssuerIdentifier::from_str("http://myissuer.com:443/v2.0");
        assert!(iss.is_ok());
    }

    #[test]
    fn issuer_cant_have_query_component_on_url() {
        let iss = IssuerIdentifier::from_str("http://myissuer.com:443/v2.0?code=1234");
        assert!(iss.is_err());
    }

    #[test]
    fn issuer_cant_have_fragment_component_on_url() {
        let iss = IssuerIdentifier::from_str("http://myissuer.com:443/v2.0#code=1234");
        assert!(iss.is_err());
    }

    #[test]
    fn subject_must_be_complaint() {
        let sub = SubjectIdentifier::from_str("40ab568a070ba11c1a3ea00f");
        assert!(sub.is_ok());
    }

    #[test]
    fn subject_must_be_shortest_than_256() {
        let sub = SubjectIdentifier::from_str(
            r#"
4670bba18f57e33b50c9e8e5b2d30b99e51ca
0009faad1713f43b9ea8094ca0b75612edf76
7f5244f1471a784a145af0d8a8da0109601f6
ab2e8ca6659350deed6c974080faf47ad17a3
21ed384e0907897abc96112759deeb7748bf2
91b39c06d00635698f7730ed3fc9d5ae4d539
e10d36046bba5d3c9db421040f572a9c48
            "#,
        );

        assert!(sub.is_err());
    }

    #[test]
    fn subject_must_be_ascii() {
        let sub = SubjectIdentifier::from_str(
            r#"
4670bba18f57e33b50c9e8e5b2d30b99e51ca
0009faad1713f43b9ea8094ca0b75612edf76
7f5244f1471a784a145af0d8a8da0109601f6
ab2e8ca6659350deed6c974080faf47ad17a3
21ed384e0907897abc96112759deeb7748bf2
91b39c06d00635698f7730ed3fc9d5ae4d539
e10d36046bba5d3c9db421040f572a9cÉ
            "#,
        );

        assert!(sub.is_err());
    }

    #[test]
    fn expiration_must_be_complaint() {
        let exp = Expiration::try_from(chrono::Duration::days(600));
        assert!(exp.is_ok());
    }

    #[test]
    fn expiration_duration_must_be_greater_than_10_seconds() {
        let exp = Expiration::try_from(chrono::Duration::seconds(8));
        assert!(exp.is_err());
    }

    #[test]
    fn issued_at_must_be_complaint() {
        let iat = IssuedAt::now();
        assert_eq!(*iat, chrono::Utc::now().timestamp());
    }

    #[test]
    fn id_token_must_deserialize_from_json() {
        // aud as vec
        let plain_json = json!({
            "iss": "issuer",
            "sub": "subject",
            "aud": ["myaudience1", "myaudience2"],
            "exp": 9,
            "iat": 9,
            "nonce": null
        })
        .to_string();

        let id_token = serde_json::from_str::<IDToken>(&plain_json).expect("id token deserialization");

        assert_eq!(*id_token.iss, String::from("issuer"));
        assert_eq!(*id_token.sub, String::from("subject"));
        assert_eq!(*id_token.aud, vec![String::from("myaudience1"), String::from("myaudience2")]);
        assert_eq!(*id_token.exp, 9);
        assert_eq!(*id_token.iat, 9);
        assert_eq!(id_token.nonce.as_deref(), None);

        // aud as string
        let plain_json = json!({
            "iss": "issuer",
            "sub": "subject",
            "aud": "myaudience1",
            "exp": 9,
            "iat": 9,
            "nonce": null
        })
        .to_string();

        let id_token = serde_json::from_str::<IDToken>(&plain_json).expect("id token deserialization");

        assert_eq!(*id_token.iss, String::from("issuer"));
        assert_eq!(*id_token.sub, String::from("subject"));
        assert_eq!(*id_token.aud, vec![String::from("myaudience1")]);
        assert_eq!(*id_token.exp, 9);
        assert_eq!(*id_token.iat, 9);
        assert_eq!(id_token.nonce.as_deref(), None);
    }
}
