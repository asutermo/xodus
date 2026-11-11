use crate::models::xbox::{
    UserAuthProperties, UserAuthRequest, XstsPropertyBag, XstsRequest, XstsResponse,
};

pub async fn authenticate_xbox_user(
    client: &reqwest::Client,
    rps_ticket: String,
) -> std::result::Result<XstsResponse, Box<dyn std::error::Error>> {
    let body = UserAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: UserAuthProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            // RPS ticket prefix: xal supports "d=" (OAuth token), "t=" (MBI_SSL
            // SOAP ticket), or none. The SOAP compact ticket from the login
            // flow is an MBI_SSL ticket → "t=" (selectable via XBL_RPS_PREFIX
            // for experimentation; 2026-11-10: bare and "d=" both 400'd).
            rps_ticket: {
                let p = std::env::var("XBL_RPS_PREFIX").unwrap_or_else(|_| "t=".to_string());
                if rps_ticket.starts_with("d=") || rps_ticket.starts_with("t=") {
                    rps_ticket
                } else if p == "none" {
                    rps_ticket
                } else {
                    format!("{p}{rps_ticket}")
                }
            },
        },
    };

    let resp = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(format!("user.auth {} body: {}", status, &text[..text.len().min(400)]).into());
    }
    serde_json::from_str(&text).map_err(|e| {
        format!("user.auth body parse failed: {e} | body head: {}", &text[..text.len().min(200)]).into()
    })
}

pub async fn request_xsts_token(
    client: &reqwest::Client,
    token: String,
    relying_party: &str,
    device_token: Option<String>,
    sandbox_id: Option<String>,
) -> reqwest::Result<XstsResponse> {
    let body = XstsRequest {
        relying_party: Some(relying_party.to_string()),
        token_type: Some("JWT".to_string()),
        properties: XstsPropertyBag {
            user_tokens: Some(vec![token]),
            sandbox_id: sandbox_id.or(Some("RETAIL".to_string())),
            delegation_token: None,
            service_token: None,
            device_token,
        },
    };

    let resp = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

pub fn get_xsts_auth_header(xsts: XstsResponse) -> String {
    let uhs = xsts.user_hash().expect("XSTS response missing xui claim");
    format!("XBL3.0 x={uhs};{}", xsts.token)
}
