use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(client: &reqwest::Client, tokens: &TokenManager) {
    match tokens.get_device_license() {
        Err(_) => provision_device(client, tokens).await,
        Ok(license) if tokens.get_device_sts_token().is_err() => {
            reauthenticate_device(client, tokens, license).await
        }
        Ok(_) => {}
    }
}

async fn provision_device(client: &reqwest::Client, tokens: &TokenManager) {
    // PATCH: hex-only username — see licensing::utils::generate_hex_string.
    // The DeviceName claim derived from this must be hex (LicensingFD fault 3043).
    let username = format!("02{}", crate::licensing::utils::generate_hex_string(14));
    let password = crate::licensing::utils::generate_hex_string(20);
    if std::env::var("XODUS_DEBUG").is_ok() {
        eprintln!("[provision] creating device credential, username={username}");
    }
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: {
                let mut components = hardware::probe_provision_components();
                // PATCH: with XODUS_FRESH_DEVICE=1, randomize the SMBIOS identity
                // components (4100=version, 4101=serial, 4102=uuid) so MSA registers
                // a brand-new device instead of deduping onto a stale registration
                // that carries a pre-patch non-hex DeviceName claim.
                if std::env::var("XODUS_FRESH_DEVICE").is_ok() {
                    eprintln!("[provision] XODUS_FRESH_DEVICE: randomizing hardware identity");
                    for comp in components.iter_mut() {
                        if comp.name == 4101 || comp.name == 4102 {
                            comp.value = Some(crate::licensing::utils::generate_hex_string(32));
                            comp.error = None;
                        }
                    }
                }
                components
            },
            tpm_info: None,
        }),
    };

    // PATCH: dump raw provisioning request for claim inspection (XODUS_DEBUG=1)
    if std::env::var("XODUS_DEBUG").is_ok() {
        if let Ok(xml) = quick_xml::se::to_string(&provision) {
            let _ = std::fs::create_dir_all("out");
            let _ = std::fs::write("out/provision_request.xml", &xml);
            eprintln!("[provision] request xml written to out/provision_request.xml");
        }
    }

    let dev = crate::api::live::login_device_credential(client, provision)
        .await
        .expect("Failed to get device creds");

    // PATCH: dump SPLicense identity fields (XODUS_DEBUG=1)
    // The DeviceName claim inside device STS tickets is minted from data MSA
    // stores at deviceaddcredential time — the SPLicense identity fields show
    // exactly what device identity MSA bound.
    if std::env::var("XODUS_DEBUG").is_ok() {
        eprintln!("[provision] HWDeviceID={} GlobalDeviceID={} puid={}", dev.hw_device_id, dev.global_device_id, dev.puid);
        if let Ok(sp) = SPLicense::parse_base64(&dev.license.splicense_block) {
            eprintln!("[provision] splicense device_id: {:02x?}", sp.device_id);
            eprintln!("[provision] splicense hardware_id: {:02x?}", sp.hardware_id);
            eprintln!("[provision] splicense package_name: {}", sp.package_name);
        }
    }

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens
        .save_device_license(&device)
        .expect("Failed to save device license");

    reauthenticate_device(client, tokens, device).await;
}

async fn reauthenticate_device(client: &reqwest::Client, tokens: &TokenManager, license: Device) {
    let sp_license =
        SPLicense::parse_base64(&license.splicense).expect("Failed to parse SPLicense");
    let clep_sign_state = sp_license.clep_sign_state.expect("Missing clep sign state");
    let key = clep_sign_state.get_rsa_key();
    let private_key = parse_bcrypt_rsa_private(&key).unwrap();
    if std::env::var("XODUS_DEBUG").is_ok() {
        eprintln!("[reauth] authenticating device username={}", license.username);
    }
    let resp = crate::api::live::authenticate_device(client, license.username, private_key)
        .await
        .expect("Failed to auth device");

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp);
    }
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) {
    let key_name = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .unwrap()
        .key_info
        .key_name
        .as_ref()
        .unwrap()
        .clone();
    let token: crate::models::secrets::Token = (*resp).into();
    // PATCH: save under the response's key_name AND the well-known lookup key.
    // get_device_sts_token() looks up PASSPORT_STS ("http://Passport.NET/STS"),
    // but fresh device registrations may return a different key_name — saving
    // only under that left the lookup empty (NotFound panic in license.rs).
    tokens
        .save_device_token(key_name.clone(), token.clone())
        .expect("Failed to save device token");
    tokens
        .save_device_token("http://Passport.NET/STS".to_string(), token)
        .expect("Failed to save device token (passport sts)");
}
