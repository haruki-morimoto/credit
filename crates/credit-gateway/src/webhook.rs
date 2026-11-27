//! **3-Line Embeddable `"Pay with Credits (∀)"` Web Checkout Widget** & **HMAC-Signed Merchant Webhooks**.
//!
//! Enables any indie game, SaaS, online store, or creator site to accept `~170 ms` zero-fee `XCR`
//! payments without Stripe's `2.9% + $0.30` cut:
//! ```html
//! <script src="http://127.0.0.1:8080/embed/xcr-checkout.js"></script>
//! <div class="xcr-pay-button" data-amount="4.95" data-memo="Indie Game Key"></div>
//! ```
//! And delivers authenticated HTTP `POST` webhooks signed with `X-XCR-Signature: sha256=<64-hex>`
//! (`domain_hash("XCR.WEBHOOK.HMAC.V1", &[secret, body])`) whenever an incoming stealth payment settles.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_crypto::{ct_eq_slice, domain_hash};
use credit_types::Amount;

use crate::json_escape;

/// Zero-dependency embeddable JavaScript checkout widget served at `GET /embed/xcr-checkout.js`.
pub const EMBED_CHECKOUT_JS: &str = r##"(function(){
  const scriptEl = document.currentScript || document.querySelector('script[src*="xcr-checkout.js"]');
  const origin = scriptEl ? new URL(scriptEl.src, window.location.href).origin : window.location.origin;

  function mountButton(el) {
    if (el.dataset.xcrMounted) return;
    el.dataset.xcrMounted = '1';
    const amt = el.dataset.amount || '1.00';
    const memo = el.dataset.memo || 'Order';
    const btn = document.createElement('button');
    btn.textContent = `\u2200 Pay ${amt} XCR`;
    btn.style.cssText = 'background:#76b82a;color:#0b1105;border:none;border-radius:9px;padding:10px 18px;font:700 14px system-ui,sans-serif;cursor:pointer;box-shadow:0 2px 10px rgba(118,184,42,0.35);';
    btn.onclick = () => openModal(el, amt, memo);
    el.appendChild(btn);
  }

  async function openModal(hostEl, amt, memo) {
    const inv = 'WEB-' + Math.floor(100000 + Math.random() * 900000);
    const info = await fetch(`${origin}/api/invoice-uri?amount=${encodeURIComponent(amt)}&invoice=${inv}&memo=${encodeURIComponent(memo)}`).then(r => r.json());
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.72);display:flex;align-items:center;justify-content:center;z-index:99999;';
    const box = document.createElement('div');
    box.style.cssText = 'background:#181d22;color:#eef2f6;border:1px solid #2a323b;border-radius:16px;padding:22px;width:320px;text-align:center;font-family:system-ui,sans-serif;';
    box.innerHTML = `
      <div style="font-weight:700;font-size:16px;margin-bottom:4px;">Pay with Credits (\u2200)</div>
      <div style="color:#94a3b8;font-size:12.5px;margin-bottom:12px;">\u2200 ${amt} XCR \u00b7 ${memo} (${inv})</div>
      <div style="background:#fff;border-radius:12px;padding:10px;width:190px;height:190px;margin:0 auto 12px;">
        <img src="${origin}/api/qr.svg?data=${encodeURIComponent(info.uri)}" style="width:100%;height:100%;display:block;" alt="XCR QR"/>
      </div>
      <div id="xcrModalState" style="font-size:12.5px;color:#c8a96e;margin-bottom:12px;">Scan QR or tap URI \u2014 settles in ~170 ms</div>
      <input readonly value="${info.uri}" onclick="this.select()" style="width:100%;background:#0f1215;border:1px solid #2a323b;color:#eef2f6;padding:6px 8px;border-radius:6px;font:11px monospace;margin-bottom:10px;"/>
      <button id="xcrCloseBtn" style="background:transparent;color:#94a3b8;border:1px solid #2a323b;border-radius:7px;padding:6px 14px;cursor:pointer;">Cancel</button>
    `;
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    const timer = setInterval(async () => {
      const st = await fetch(`${origin}/api/checkout-status?inv=${encodeURIComponent(inv)}`).then(r => r.json()).catch(() => ({ paid: false }));
      if (st.paid) {
        clearInterval(timer);
        document.getElementById('xcrModalState').innerHTML = `<strong style="color:#76b82a">\u2713 PAID &amp; SETTLED (${st.amount})</strong>`;
        hostEl.dispatchEvent(new CustomEvent('xcr:paid', { detail: st, bubbles: true }));
        setTimeout(() => overlay.remove(), 1800);
      }
    }, 1400);

    box.querySelector('#xcrCloseBtn').onclick = () => { clearInterval(timer); overlay.remove(); };
  }

  function initAll() { document.querySelectorAll('.xcr-pay-button').forEach(mountButton); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initAll);
  else initAll();
})();
"##;

/// Computes the canonical `sha256=<64-hex>` `X-XCR-Signature` header for a webhook JSON payload.
pub fn compute_webhook_signature(secret: &str, json_body: &str) -> String {
    let tag = domain_hash(
        "XCR.WEBHOOK.HMAC.V1",
        &[secret.as_bytes(), json_body.as_bytes()],
    );
    format!("sha256={}", tag.to_hex())
}

/// Constant-time verifier for merchant backends validating `X-XCR-Signature`.
pub fn verify_webhook_signature(secret: &str, json_body: &str, header_value: &str) -> bool {
    let expected = compute_webhook_signature(secret, json_body);
    ct_eq_slice(expected.as_bytes(), header_value.trim().as_bytes())
}

/// Sends an authenticated HTTP/1.1 `POST` webhook notification to `webhook_url` (`http://host[:port]/path`).
pub fn dispatch_signed_webhook(
    webhook_url: &str,
    secret: &str,
    amount: Amount,
    one_time_address: &str,
    memo: &str,
) -> io::Result<u16> {
    let trimmed = webhook_url.trim();
    let rest = trimmed.strip_prefix("http://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "webhook URL must start with http://",
        )
    })?;
    let (host_port, path_part) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, String::from("/")),
    };
    let addr_spec = if host_port.contains(':') {
        host_port.to_owned()
    } else {
        format!("{host_port}:80")
    };
    let host_header = host_port.split(':').next().unwrap_or(host_port);
    let sock_addr: SocketAddr = addr_spec
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "webhook host lookup failed"))?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = format!(
        r#"{{"event":"payment.settled","amount":"{}","bits":{},"one_time_address":"{}","memo":"{}","timestamp":{}}}"#,
        amount.format_symbolic(),
        amount.bits(),
        json_escape(one_time_address),
        json_escape(memo),
        ts
    );
    let sig = compute_webhook_signature(secret, &body);

    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let req = format!(
        "POST {path_part} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nX-XCR-Signature: {sig}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut resp_buf = [0u8; 256];
    let n = stream.read(&mut resp_buf).unwrap_or(0);
    let first = String::from_utf8_lossy(&resp_buf[..n]);
    let code = first
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(200);
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn signed_merchant_webhook_delivers_and_verifies_hmac_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let secret = "whsec_sovereign_test_key";

        let receiver = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            raw
        });

        let url = format!("http://{addr}/hooks/xcr");
        let code = dispatch_signed_webhook(
            &url,
            secret,
            Amount::from_chips(495).unwrap(),
            "xcr1_deadbeef1234",
            "WEB-102938: Indie Game Key",
        )
        .unwrap();
        assert_eq!(code, 200);

        let captured = receiver.join().unwrap();
        let (head, body) = captured.split_once("\r\n\r\n").unwrap();
        let sig_line = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("x-xcr-signature:"))
            .unwrap();
        let sig_val = sig_line.split_once(':').unwrap().1.trim();
        assert!(verify_webhook_signature(secret, body, sig_val));
        assert!(!verify_webhook_signature("wrong_secret", body, sig_val));
        assert!(body.contains("Indie Game Key"));
    }
}
