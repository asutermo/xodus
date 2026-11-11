//! 2026-11-10 license-floor investigation — direct xal minter.
//!
//! Mints an XSTS token for an arbitrary relying party via xal's own auth chain:
//! browser login (OAuth, XboxLive.signin) → device token (CLEP/deviceaddcredential)
//! → user token (user.auth, "d=" prefix) → signed /xsts/authorize.
//! Usage: xal-mint [--rp <url>] [--no-title-token] [--out <file>]
use std::process::ExitCode;

use xal::client_params::CLIENT_WINDOWS;
use xal::oauth2::{RedirectUrl, Scope};
use xal::{Constants, Flows, RequestSigning, TokenStore, XalAppParameters, XalAuthenticator};

const CLIENT_ID: &str = "000000004424da1f";
const TITLE_ID: i64 = 704208617;

fn app_params() -> XalAppParameters {
    XalAppParameters {
        client_id: CLIENT_ID.to_string(),
        title_id: Some(TITLE_ID.to_string()),
        auth_scopes: vec![Scope::new(Constants::SCOPE_SERVICE_USER_AUTH.to_owned())],
        redirect_uri: Some(
            RedirectUrl::new(Constants::OAUTH20_DESKTOP_REDIRECT_URL.into()).unwrap(),
        ),
        client_secret: None,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut rp = "http://licensing.xboxlive.com".to_string();
    let mut out_path = String::new();
    let mut redirect_file = String::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--rp" => rp = args.next().unwrap_or(rp),
            "--out" => out_path = args.next().unwrap_or_default(),
            "--redirect-url" => redirect_file = args.next().unwrap_or_default(),
            other => {
                eprintln!("unknown arg: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    let mut authenticator =
        XalAuthenticator::new(app_params(), CLIENT_WINDOWS(), "RETAIL".to_string());
    let ts: TokenStore = if !redirect_file.is_empty() {
        // Offline mode: access token supplied via a captured redirect URL file.
        // Parse the OAuth token from the URL fragment and build the live token
        // directly (skips ms_authorization_flow / browser).
        let url = std::fs::read_to_string(&redirect_file).expect("redirect file read");
        let frag = url.split('#').nth(1).unwrap_or("");
        let mut access_token = String::new();
        let mut expires_in: Option<u64> = None;
        for pair in frag.split('&') {
            let mut kv = pair.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("access_token"), Some(v)) => access_token = v.to_string(),
                (Some("expires_in"), Some(v)) => expires_in = v.parse().ok(),
                _ => {}
            }
        }
        if access_token.is_empty() {
            eprintln!("no access_token in redirect fragment");
            return ExitCode::FAILURE;
        }
        eprintln!("xal: oauth token from redirect file ({} bytes)", access_token.len());
        let token: xal::oauth2::StandardTokenResponse<
            xal::oauth2::EmptyExtraTokenFields,
            xal::oauth2::basic::BasicTokenType,
        > = xal::oauth2::StandardTokenResponse::new(
            xal::oauth2::AccessToken::new(access_token),
            xal::oauth2::basic::BasicTokenType::Bearer,
            xal::oauth2::EmptyExtraTokenFields {},
        );
        let mut live = token;
        if let Some(secs) = expires_in {
            live.set_expires_in(Some(&std::time::Duration::from_secs(secs)));
        }
        TokenStore {
            app_params: app_params(),
            client_params: CLIENT_WINDOWS(),
            sandbox_id: "RETAIL".to_string(),
            live_token: live,
            user_token: None,
            title_token: None,
            device_token: None,
            authorization_token: None,
            updated: None,
        }
    } else {
        let handler = xal::CliCallbackHandler;
        eprintln!("xal: starting browser auth (sign in with the account owning the license)…");
        match Flows::ms_authorization_flow(&mut authenticator, handler, true).await {
            Ok(ts) => ts,
            Err(e) => {
                eprintln!("xal ms auth failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    };
    let live_token = ts.live_token.clone();
    eprintln!("xal: oauth acquired; running xbox-live chain for rp={rp}");
    let ts = match Flows::xbox_live_authorization_traditional_flow(
        &mut authenticator,
        live_token,
        rp.clone(),
        xal::AccessTokenPrefix::D,
        false,
    )
    .await
    {
        Ok(ts) => ts,
        Err(e) => {
            eprintln!("xal xbox-live chain failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let auth_token = match &ts.authorization_token {
        Some(t) => t,
        None => {
            eprintln!("xal: no XSTS in TokenStore");
            return ExitCode::FAILURE;
        }
    };
    let client = reqwest::Client::new();
    let header = auth_token.authorization_header_value();
    eprintln!("xsts OK: rp={rp} header_len={}", header.len());
    println!("{header}");

    // Optional: hybrid mint — user token + an external device token (JWE, e.g. a
    // console-captured XToken) as Properties.DeviceToken in a custom /xsts/authorize
    // call, signed with the authenticator's proof-key signer.
    if std::env::var("XAL_DEVICE_TOKEN_FILE").is_ok() {
        let dt_path = std::env::var("XAL_DEVICE_TOKEN_FILE").unwrap();
        let device_token = std::fs::read_to_string(&dt_path).unwrap_or_else(|e| {
            eprintln!("device token file read failed: {e}");
            std::process::exit(1);
        });
        let device_token = device_token.trim().to_string();
        let user_token = match ts.user_token.clone() {
            Some(ut) => ut,
            None => {
                eprintln!("no user token in TokenStore for hybrid mint");
                std::process::exit(1);
            }
        };
        // Build a DeviceToken response shell around the externally supplied JWE
        // (From<&str> fills inert timestamps; only .token is sent to xsts).
        let dt: xal::response::DeviceToken = device_token.as_str().into();
        eprintln!(
            "hybrid mint: user token (len {}) + external device token (len {})",
            user_token.token.len(),
            dt.token.len()
        );
        match authenticator
            .get_xsts_token(Some(&dt), None, Some(&user_token), &rp)
            .await
        {
            Ok(xsts) => {
                eprintln!("hybrid xsts OK: len {}", xsts.token.len());
                if !out_path.is_empty() {
                    let _ = std::fs::write(format!("{out_path}.hybrid-xsts"), &xsts.token);
                }
            }
            Err(e) => {
                eprintln!("hybrid xsts failed: {e}");
                // Manual retry with identical construction (contract v1, no
                // Authorization header) to capture the raw error body.
                let body = format!(
                    "{{\"Properties\":{{\"SandboxId\":\"RETAIL\",\"UserTokens\":[\"{}\"],\"DeviceToken\":\"{}\"}},\"RelyingParty\":\"{}\",\"TokenType\":\"JWT\"}}",
                    user_token.token, dt.token, rp
                );
                let cv = xal::cvlib::CorrelationVector::new();
                let mut signer = authenticator.request_signer();
                let req = reqwest011::Client::new()
                    .post("https://xsts.auth.xboxlive.com/xsts/authorize")
                    .header("x-xbl-contract-version", "1")
                    .header("MS-CV", cv.to_string())
                    .header("Accept", "application/json")
                    .body(body)
                    .build()
                    .expect("manual hybrid request build");
                match signer.sign_request(req, None).await {
                    Ok(signed_req) => match reqwest011::Client::new().execute(signed_req).await {
                        Ok(r) => {
                            let status = r.status();
                            let text = r.text().await.unwrap_or_default();
                            eprintln!("hybrid retry: HTTP {status}");
                            eprintln!("hybrid retry body: {}", &text[..text.len().min(600)]);
                        }
                        Err(e) => eprintln!("hybrid retry send failed: {e}"),
                    },
                    Err(e) => eprintln!("hybrid retry sign failed: {e}"),
                }
            }
        }
    }

    // Optional: immediately test the licensing content endpoint with this token,
    // signed with the authenticator's proof-key signer (bound to the user token).
    if std::env::var("XAL_CALL_LICENSE").is_ok() {
        let content_id =
            std::env::var("XAL_LICENSE_CONTENT").unwrap_or_else(|_| "7c7eb620-5f1a-4dff-8375-1446377cb1e8".to_string());
        let signer = authenticator.request_signer();
        let body = format!(
            "{{\"contentId\":\"{content_id}\",\"deviceContext\":{{\"hardwareManufacturer\":\"Public\",\"hardwareType\":\"Public\",\"mobileOperator\":\"Public\"}},\"licenseVersion\":5,\"market\":\"US\",\"needKey\":true,\"roots\":[],\"users\":{{}}}}"
        );
        let cv = xal::cvlib::CorrelationVector::new();
        let mut signer = authenticator.request_signer();
        let req = reqwest011::Client::new()
            .post("https://licensing.mp.microsoft.com/v7.0/licenses/content")
            .header("From", "XboxLicenseManager")
            .header("Authorization", header.clone())
            .header("User-Agent", "XboxLm-Console/25398.4908.amd64fre.xb_flt_2406zn.240606-1530")
            .header("MS-CV", cv.to_string())
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body.clone())
            .build()
            .expect("licensing request build");
        let signed = signer.sign_request(req, None).await;
        match signed {
            Ok(signed_req) => {
                let resp = reqwest011::Client::new().execute(signed_req).await;
                match resp {
                    Ok(r) => {
                        let status = r.status();
                        let text = r.text().await.unwrap_or_default();
                        eprintln!("licensing: HTTP {status}");
                        eprintln!("licensing body: {}", &text[..text.len().min(600)]);
                        if !out_path.is_empty() {
                            let _ = std::fs::write(format!("{out_path}.license-response"), &text);
                        }
                    }
                    Err(e) => eprintln!("licensing send failed: {e}"),
                }
            }
            Err(e) => eprintln!("licensing sign failed: {e}"),
        }
    }
    if !out_path.is_empty() {
        let _ = std::fs::write(&out_path, &header);
        eprintln!("written: {out_path}");
    }
    ExitCode::SUCCESS
}
