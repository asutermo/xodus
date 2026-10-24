use std::collections::HashMap;

use base64::prelude::*;

use crate::api::live::utils;
use crate::models::soap;

pub struct RSTRequest<'a> {
    pub signed_xml: String,
    pub signature: Option<super::RSTSignature<'a>>,
}

impl<'a> RSTRequest<'a> {
    /// Makes a POST request with `reqwest::Client` and decrypts the envelope if applicable
    pub async fn request(
        self,
        client: &reqwest::Client,
    ) -> Result<soap::Envelope, super::RSTError> {
        tracing::trace!("Making RST2.srf request");
        let response = client
        .post("https://login.live.com/RST2.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(self.signed_xml)
        .send()
        .await?;

        let response_text = response.text().await?;
        // PATCH: dump raw RST2 response for claim inspection (XODUS_DEBUG=1)
        if std::env::var("XODUS_DEBUG").is_ok() {
            use std::sync::atomic::{AtomicU32, Ordering};
            static RST_SEQ: AtomicU32 = AtomicU32::new(0);
            let n = RST_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = format!("out/rst_response_{}.xml", n);
            let _ = std::fs::create_dir_all("out");
            let _ = std::fs::write(&path, &response_text);
            eprintln!("[rst] response {} ({} bytes) written to {}", n, response_text.len(), path);
        }
        let envelope: soap::Envelope = {
            // PATCH: unsigned responses to exchanges are SOAP faults WITHOUT the
            // wsa:Action header the strict Envelope struct requires (observed:
            // "Invalid STS request" 0x80048820). Faults are terminal for the flow —
            // dump (already done above) and surface a clean error instead of
            // a serde panic.
            match quick_xml::de::from_str::<soap::Envelope>(&response_text) {
                Ok(env) => env,
                Err(de_err) => {
                    if response_text.contains("S:Fault") {
                        let status = response_text
                            .split("<psf:value>")
                            .nth(1)
                            .and_then(|s| s.split("<").next())
                            .unwrap_or("?")
                            .to_string();
                        let text = response_text
                            .split("<psf:text>")
                            .nth(1)
                            .map(|s| {
                                s.split("</psf:text>").next().unwrap_or("").to_string()
                            })
                            .unwrap_or_default();
                        return Err(super::RSTError::InvalidResponseSignature(format!(
                            "server rejected request: fault {status}: {text} (deser err: {de_err}; raw in out/)"
                        )));
                    }
                    return Err(de_err.into());
                }
            }
        };

        verify_and_decrypt_envelope(self.signature, response_text, envelope)
    }
}

fn verify_and_decrypt_envelope<'a>(
    signature: Option<super::RSTSignature<'a>>,
    xml_text: String,
    mut envelope: soap::Envelope,
) -> Result<soap::Envelope, super::RSTError> {
    let Some(signature) = signature else {
        tracing::debug!("No signature, returning raw envelope");
        return Ok(envelope);
    };
    tracing::trace!("Decrypting soap::Envelope");
    let nonces: HashMap<String, String> = envelope
        .header
        .security
        .derived_key_tokens
        .iter()
        .map(|token| (token.id.clone(), token.nonce.clone()))
        .collect();

    if let Some(security_signature) = &envelope.header.security.signature
        && let Some(key_info) = &security_signature.key_info
    {
        let id = &key_info.security_token_reference.reference.uri;
        let nonce = nonces.get(&id[1..]).ok_or(super::RSTError::MissingNonce)?;
        let nonce = BASE64_STANDARD.decode(nonce)?;
        let key = signature.signing_key(&nonce)?;
        let mut kmgr = bergshamra::KeysManager::new();
        kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Verify));
        let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
        let result = bergshamra::verify(&ctx, &xml_text)?;
        match result {
            bergshamra::VerifyResult::Invalid { reason } => {
                return Err(super::RSTError::InvalidResponseSignature(reason));
            }
            bergshamra::VerifyResult::Valid { .. } => tracing::debug!("Verification successful"),
        }
    }

    if envelope.header.pp.is_none()
        && let Some(enc_pp) = envelope.header.encrypted_pp.take()
    {
        tracing::trace!("Decrypting soap::PP");
        let pp = utils::decrypt_soap_encrypted_data(
            Box::new(enc_pp.encrypted_data),
            &signature,
            &nonces,
        )?;
        envelope.header.pp = pp;
    }

    if let soap::BodyContent::EncryptedData(enc_data) = envelope.body.body {
        tracing::trace!("Decrypting soap::Body");
        envelope.body.body = utils::decrypt_soap_encrypted_data(enc_data, &signature, &nonces)?;
    }

    // PATCH: dump the fully decrypted envelope (claims visible, e.g. DeviceName)
    if std::env::var("XODUS_DEBUG").is_ok() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static DEC_SEQ: AtomicU32 = AtomicU32::new(0);
        let n = DEC_SEQ.fetch_add(1, Ordering::Relaxed);
        if let Ok(dec) = quick_xml::se::to_string(&envelope) {
            let path = format!("out/rst_decrypted_{}.xml", n);
            let _ = std::fs::create_dir_all("out");
            let _ = std::fs::write(&path, &dec);
            eprintln!("[rst] decrypted envelope {} ({} bytes) written to {}", n, dec.len(), path);
        }
    }

    Ok(envelope)
}
