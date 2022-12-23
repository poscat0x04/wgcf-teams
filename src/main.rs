use std::{fmt, io};
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use pretty::RcDoc;
use reqwest::Client;
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, CONNECTION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Value};
use tokio;
use wireguard_keys::{Privkey, Pubkey};

const API_ENDPOINT: &str = "https://api.cloudflareclient.com/v0i2209280024/reg";
const INSTRUCTION_URL: &str = "<TODO>";
const WG_MTU: u16 = 1420;
const V4_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const V6_DNS: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0x0, 0x0, 0x0, 0x0, 0x1111));

#[tokio::main]
async fn main() -> Result<()> {
    let token =
        get_jwt_token().await
            .context("Failed to get jwt token")?;
    let client =
        build_client().await
            .context("Failed to build reqwest client")?;
    let reg = Registration::new();
    let req =
        client
            .post(API_ENDPOINT)
            .json(&reg)
            .header("Cf-Access-Jwt-Assertion", &token)
            .build()
            .context("Failed to build request to cloudflare API")?;
    let resp =
        client
            .execute(req).await
            .context("Request to cloudflare API failed")?;
    let a: CFResp<RegistrationResult> =
        resp
            .json().await
            .context("Failed to parse the result returned by cloudflare")?;
    println!("{:?}", a);
    Ok(())
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Registration {
    key: Privkey,
    tos: DateTime<Local>,
    model: String,
    fcm_token: String,
    device_token: String,
}

impl Registration {
    pub fn new() -> Self {
        Registration {
            key: Privkey::generate(),
            tos: Local::now(),
            model: String::from("iPad13,8"),
            fcm_token: String::new(),
            device_token: String::new(),
        }
    }
}

// The error type representing a failed request to the cloudflare API
// Result<T, RequestFailure> should be isomorphic to CFResp<T>
#[derive(Eq, PartialEq, Debug)]
struct RequestFailure {
    errors: Vec<CFError>,
    messages: Vec<Value>,
}

impl Display for RequestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Request to Cloudflare API has failed with errors:")?;
        for err in &self.errors {
            writeln!(f, "")?;
            writeln!(f, "{}",
                     to_string_pretty(err)
                         .expect("Impossible, failed to pretty print error")
            )?;
        }
        writeln!(f, "")?;
        writeln!(f, "And messages:")?;
        for msg in &self.messages {
            writeln!(f, "")?;
            writeln!(f, "{}",
                     to_string_pretty(msg)
                         .expect("Impossible, failed to pretty print error")
            )?;
        }
        Ok(())
    }
}

impl Error for RequestFailure {}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct CFError {
    code: u16,
    message: String,
    other: Option<HashMap<String, Value>>,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct CFResp<T> {
    result: Option<T>,
    success: bool,
    errors: Vec<CFError>,
    messages: Vec<Value>,
}

impl<T> CFResp<T> {
    fn get_result(self) -> Result<T, RequestFailure> {
        match self.result {
            Some(t) => Ok(t),
            None => Err(RequestFailure {
                errors: self.errors,
                messages: self.messages,
            })
        }
    }
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct RegistrationResult {
    id: String,
    version: String,
    updated: DateTime<Utc>,
    #[serde(rename = "type")]
    _type: String,
    key: String,
    policy: WarpPolicy,
    token: String,
    locale: String,
    config: WarpConfig,
    created: DateTime<Utc>,
    // TODO: Value
    override_codes: Value,
    // TODO: Value
    account: Value,
    install_id: String,
    name: String,
    model: String,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WarpPolicy {
    app_url: String,
    captive_portal: u32,
    allowed_to_leave: bool,
    switch_locked: bool,
    fallback_domains: Vec<FallbackDomain>,
    service_mode_v2: Value,
    allow_updates: bool,
    support_url: String,
    // TODO: Value
    exclude: Value,
    gateway_unique_id: String,
    allow_mode_switch: bool,
    auto_connect: u8,
    disable_auto_fallback: bool,
    organization: String,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct FallbackDomain {
    suffix: String,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WarpConfig {
    client_id: String,
    peers: Vec<WgPeer>,
    interface: WgIFConfig,
    metrics: Metrics,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WgPeer {
    public_key: Pubkey,
    endpoint: WgEndpoint,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WgEndpoint {
    host: String,
    v4: SocketAddrV4,
    v6: SocketAddrV6,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct WgIFConfig {
    addresses: IFAddrs,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct IFAddrs {
    v4: Ipv4Addr,
    v6: Ipv6Addr,
}

impl IFAddrs {
    pub fn to_inet_vec(self) -> Vec<IpNet> {
        let mut v = Vec::new();
        let v6inet =
            Ipv6Net::new(self.v6, 128)
                .expect("Impossible, 128 is a valid netmask length for ipv6 addresses");
        let v4inet =
            Ipv4Net::new(self.v4, 32)
                .expect("Impossible, 32 is a valid netmask length for ipv4 addresses");
        v.push(IpNet::V6(v6inet));
        v.push(IpNet::V4(v4inet));
        v
    }
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Services {
    http_proxy: SocketAddr,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
struct Metrics {
    report: u16,
    ping: u16,
}

#[derive(Eq, PartialEq, Debug)]
struct WireguardConfig {
    private_key: Privkey,
    if_address: Vec<IpNet>,
    dns: Vec<IpAddr>,
    mtu: u16,
    public_key: Pubkey,
    allowed_ipv4_range: IpRange<Ipv4Net>,
    allowed_ipv6_range: IpRange<Ipv6Net>,
    endpoint: String,
}

fn kvdoc<'a, A, U>(key: &'a str, val: U) -> RcDoc<'a, A>
    where
        U: Into<Cow<'a, str>>
{
    RcDoc::text(key).append(RcDoc::text(" = ")).append(RcDoc::text(val))
}

fn ip_range_to_doc<T>(range: &IpRange<T>) -> RcDoc
    where T: ToString + iprange::IpNet
{
    RcDoc::intersperse(range.iter().map(|x| x.to_string()), RcDoc::text(", "))
}

impl WireguardConfig {
    pub fn to_doc(&self) -> Option<RcDoc> {
        let lines = [
            RcDoc::text("[Interface]"),
            kvdoc("PrivateKey", self.private_key.to_base64()),
            kvdoc("Address", self.if_address.first()?.to_string()),
            //kvdoc("DNS", self.dns.to_string()),
            kvdoc("MTU", self.mtu.to_string()),
            RcDoc::text("[Peer]"),
            kvdoc("PublicKey", self.public_key.to_base64()),
            RcDoc::text("AllowedIPs = ")
                .append(ip_range_to_doc(&self.allowed_ipv4_range))
                .append(RcDoc::text(", "))
                .append(ip_range_to_doc(&self.allowed_ipv6_range)),
            kvdoc("Endpoint", self.endpoint.to_string()),
        ];
        Some(RcDoc::intersperse(lines, RcDoc::line()))
    }

    pub fn fmt_config(self, width: usize) -> String {
        let mut ret = String::new();
        todo!()
    }

    pub fn print_config(self) {}

    pub fn write_config<P>(self, path: P)
        where
            P: AsRef<Path> + Send + 'static
    {}
}

impl WgIFConfig {
    pub fn to_inet_vec(self) -> Vec<IpNet> {
        self.addresses.to_inet_vec()
    }
}

// TODO: add ip range exclusion logic
impl WarpConfig {
    pub fn to_wg_config(mut self, privkey: Privkey) -> Result<WireguardConfig> {
        let peer =
            self.peers.pop()
                .with_context(|| format!(
                    "Warp config contains no peers: {}",
                    to_string_pretty(&self)
                        .expect("Impossible, failed to serialize a WarpConfig to JSON")
                ))?;
        let addrs = self.interface.to_inet_vec();

        let mut v4range: IpRange<Ipv4Net> = IpRange::new();
        v4range.add("0.0.0.0/0".parse().expect("Impossible, failed to parse '0.0.0.0/0'"));

        let mut v6range: IpRange<Ipv6Net> = IpRange::new();
        v6range.add("::/0".parse().expect("Impossible, failed to parse '::/0'"));

        let mut dns = Vec::new();
        dns.push(V4_DNS);
        dns.push(V6_DNS);

        Ok(WireguardConfig {
            private_key: privkey,
            public_key: peer.public_key,
            endpoint: peer.endpoint.host,
            dns,
            mtu: WG_MTU,
            if_address: addrs,
            allowed_ipv4_range: v4range,
            allowed_ipv6_range: v6range,
        })
    }
}

impl RegistrationResult {
    pub fn to_wg_config(self, privkey: Privkey) -> Result<WireguardConfig> {
        self.config.to_wg_config(privkey)
    }
}

pub async fn build_client() -> reqwest::Result<Client> {
    let mut hdr = HeaderMap::new();
    hdr.insert(ACCEPT_ENCODING, HeaderValue::from_str("gzip").unwrap());
    hdr.insert(ACCEPT_LANGUAGE, HeaderValue::from_str("en-US,en;q=0.9").unwrap());
    hdr.insert(ACCEPT, HeaderValue::from_str("*/*").unwrap());
    hdr.insert(CONNECTION, HeaderValue::from_str("keep-alive").unwrap());
    hdr.insert(HeaderName::from_bytes(b"CF-Client-Version").unwrap()
               , HeaderValue::from_str("i-6.16-2209280024.1").unwrap());
    Client::builder()
        .user_agent("1.1.1.1/2209280024.1 CFNetwork/1399 Darwin/22.1.0")
        .default_headers(hdr)
        .cookie_store(true)
        .gzip(true)
        .timeout(Duration::from_secs(10))
        .build()
}

pub async fn get_jwt_token() -> io::Result<String> {
    println!("Please log in to warp, paste the JWT token into the stdin and press enter.");
    println!("For a detailed instruction on where to find the JWT token after login, see {}.", INSTRUCTION_URL);
    tokio::time::sleep(Duration::from_secs(5)).await;
    webbrowser::open("https://poscat.cloudflareaccess.com/warp")?;
    let mut str = String::new();
    io::stdin().read_line(&mut str)?;
    Ok(str)
}

#[cfg(test)]
mod test {
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use iprange::IpRange;
    use serde_json::*;

    use crate::{CFResp, RegistrationResult, V4_DNS, V6_DNS};

    const TEST_FILE: &str = r#"
{
  "result" : {
    "id" : "t.a849f2f4-61dd-11ed-8b7d-3acbb31d7d51",
    "version" : "6.16",
    "updated" : "2022-11-11T16:26:56.002100164Z",
    "type" : "i",
    "key" : "/V3c9pAqcqy6SpZRq9bck69mmfFzsTi7mG8WFXW/NwU=",
    "policy" : {
      "app_url" : "https://poscat.cloudflareaccess.com",
      "captive_portal" : 180,
      "allowed_to_leave" : true,
      "switch_locked" : false,
      "fallback_domains" : [
        {
          "suffix" : "home.arpa"
        },
        {
          "suffix" : "intranet"
        },
        {
          "suffix" : "internal"
        },
        {
          "suffix" : "private"
        },
        {
          "suffix" : "localdomain"
        },
        {
          "suffix" : "domain"
        },
        {
          "suffix" : "lan"
        },
        {
          "suffix" : "home"
        },
        {
          "suffix" : "host"
        },
        {
          "suffix" : "corp"
        },
        {
          "suffix" : "local"
        },
        {
          "suffix" : "localhost"
        },
        {
          "suffix" : "invalid"
        },
        {
          "suffix" : "test"
        }
      ],
      "service_mode_v2" : {
        "mode" : "warp"
      },
      "allow_updates" : false,
      "support_url" : "",
      "exclude" : [
        {
          "address" : "10.0.0.0/8"
        },
        {
          "address" : "100.64.0.0/10"
        },
        {
          "address" : "169.254.0.0/16"
        },
        {
          "address" : "172.16.0.0/12"
        },
        {
          "address" : "192.0.0.0/24"
        },
        {
          "address" : "192.168.0.0/16"
        },
        {
          "address" : "224.0.0.0/24"
        },
        {
          "address" : "240.0.0.0/4"
        },
        {
          "address" : "255.255.255.255/32"
        },
        {
          "address" : "fe80::/10"
        },
        {
          "address" : "fd00::/8"
        },
        {
          "address" : "ff01::/16"
        },
        {
          "address" : "ff02::/16"
        },
        {
          "address" : "ff03::/16"
        },
        {
          "address" : "ff04::/16"
        },
        {
          "address" : "ff05::/16"
        },
        {
          "host" : "bilibili.com"
        },
        {
          "host" : "live.bilibili.com"
        }
      ],
      "gateway_unique_id" : "07248f8927685cace2b3b4eb853a8c57",
      "allow_mode_switch" : true,
      "auto_connect" : 0,
      "disable_auto_fallback" : false,
      "organization" : "poscat"
    },
    "token" : "21b87a20-cd76-4305-a5f0-0bf40b8fdc51",
    "locale" : "en-US",
    "config" : {
      "client_id" : "9agP",
      "peers" : [
        {
          "public_key" : "bmXOC+F1FxEMF9dyjK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "endpoint" : {
            "host" : "engage.cloudflareclient.com:2408",
            "v4" : "162.159.193.6:0",
            "v6" : "[2606:4700:100::a29f:c106]:0"
          }
        }
      ],
      "services" : {
        "http_proxy" : "172.16.0.1:2480"
      },
      "interface" : {
        "addresses" : {
          "v4" : "172.16.0.2",
          "v6" : "2606:4700:110:8d80:5ee:f514:1b65:ecfe"
        }
      },
      "metrics" : {
        "report" : 900,
        "ping" : 900
      }
    },
    "created" : "2022-11-11T16:26:56.002100164Z",
    "override_codes" : {
      "disable_for_time" : {
        "seconds" : 86400,
        "secret" : "dfad7ec220d2e3187781d41229114081"
      }
    },
    "account" : {
      "managed" : "not_api_managed",
      "id" : "07248f8927685cace2b3b4eb853a8c57",
      "organization" : "poscat",
      "account_type" : "team"
    },
    "install_id" : "",
    "name" : "",
    "model" : "iPad13,8"
  },
  "success" : true,
  "errors" : [

  ],
  "messages" : [

  ]
}
"#;

    #[test]
    fn test_response_parsing() {
        let res: Result<CFResp<RegistrationResult>> = from_str(TEST_FILE);
        assert!(res.is_ok());
        println!("Parse succeeded: {:?}", res.unwrap());
    }

    #[test]
    fn test_dns_server_const() {
        assert_eq!(V4_DNS.to_string(), "1.1.1.1");
        assert_eq!(V6_DNS.to_string(), "2606:4700:4700::1111");
    }

    #[test]
    fn test_wg_profile_generation() {}
}
