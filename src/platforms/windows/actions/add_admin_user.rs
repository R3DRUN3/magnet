use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Result};
use chrono::Utc;
use serde::Serialize;
use std::time::Instant;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::Foundation::ERROR_SUCCESS,
    Win32::NetworkManagement::NetManagement::{
        NetUserAdd, NetUserSetInfo, NetLocalGroupAddMembers,
        USER_INFO_1, USER_INFO_1008, USER_PRIV_USER, USER_ACCOUNT_FLAGS,
        UF_SCRIPT, UF_NORMAL_ACCOUNT, UF_DONT_EXPIRE_PASSWD,
        LOCALGROUP_MEMBERS_INFO_3,
    },
};

/// Simple struct implementing Simulation for user creation.
#[derive(Default)]
pub struct AdminUserAddSimulation;

#[derive(Serialize)]
struct UserAddTelemetry {
    test_id: String,
    timestamp: String,
    username: String,
    password: String,
    group: String,
    created: bool,
    activated: bool,
    added_to_group: bool,
    elapsed_ms: u128,
}

/// Convert &str → wide string (Vec<u16>) for Windows API
fn make_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl AdminUserAddSimulation {
    /// Core operation: creates and configures a Windows local user.
    fn perform_user_creation(username: &str, password: &str, group: &str) -> Result<(bool, bool, bool)> {
        unsafe {
            let username_w = make_wide(username);
            let password_w = make_wide(password);
            let groupname_w = make_wide(group);

            let username_pwstr = PWSTR(username_w.as_ptr() as *mut _);
            let password_pwstr = PWSTR(password_w.as_ptr() as *mut _);

            let flags = USER_ACCOUNT_FLAGS(
                UF_SCRIPT.0 | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD.0,
            );

            // --- create user ---
            let user_info = USER_INFO_1 {
                usri1_name: username_pwstr,
                usri1_password: password_pwstr,
                usri1_password_age: 0,
                usri1_priv: USER_PRIV_USER,
                usri1_home_dir: PWSTR(std::ptr::null_mut()),
                usri1_comment: PWSTR(std::ptr::null_mut()),
                usri1_flags: flags,
                usri1_script_path: PWSTR(std::ptr::null_mut()),
            };

            let add_result = NetUserAdd(PCWSTR::null(), 1, &user_info as *const _ as *const u8, None);

            let created = match add_result {
                r if r == ERROR_SUCCESS.0 => true,
                2224 => false, // already exists
                5 => anyhow::bail!("Access denied — run as Administrator"),
                other => anyhow::bail!("Failed to create user (code: {})", other),
            };

            // --- enable account ---
            let user_flags = USER_INFO_1008 { usri1008_flags: flags };
            let set_result = NetUserSetInfo(
                PCWSTR::null(),
                PCWSTR(username_w.as_ptr()),
                1008,
                &user_flags as *const _ as *const u8,
                None,
            );

            let activated = set_result == ERROR_SUCCESS.0;

            // --- add to Administrators group ---
            let member = LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname: PWSTR(username_w.as_ptr() as *mut _),
            };
            let group_result = NetLocalGroupAddMembers(
                PCWSTR::null(),
                PCWSTR(groupname_w.as_ptr()),
                3,
                &member as *const _ as *const u8,
                1,
            );

            let added_to_group = match group_result {
                r if r == ERROR_SUCCESS.0 => true,
                1378 => true, // already member
                other => {
                    eprintln!("Failed to add to group. Error code: {}", other);
                    false
                }
            };

            Ok((created, activated, added_to_group))
        }
    }
}

impl Simulation for AdminUserAddSimulation {
    fn name(&self) -> &'static str {
        "windows::admin_user_add"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();
        let username = "magnetuser";
        let password = "Magnet@1234";
        let group = "Administrators";

        logger::action_running("Creating Windows local user and adding to Administrators");

        // DRY-RUN behavior
        if cfg.dry_run {
            logger::info(&format!("dry-run: would create user '{}'", username));
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: self.name().into(),
                status: "dry-run".into(),
                details: format!("dry-run: would add '{}' to '{}'", username, group),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        let (created, activated, added_to_group) = match Self::perform_user_creation(username, password, group) {
            Ok(r) => r,
            Err(e) => {
                logger::action_fail("User creation failed");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: self.name().into(),
                    status: "failed".into(),
                    details: e.to_string(),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &rec);
                return Err(e);
            }
        };

        let elapsed = start.elapsed();
        let telemetry = UserAddTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            username: username.to_string(),
            password: password.to_string(),
            group: group.to_string(),
            created,
            activated,
            added_to_group,
            elapsed_ms: elapsed.as_millis(),
        };

        // Write telemetry as JSON
        if let Err(e) = write_action_record(cfg, &ActionRecord {
        test_id: cfg.test_id.clone(),
        timestamp: Utc::now().to_rfc3339(),
        action: "user_add".into(),
        status: "telemetry".into(),
        details: serde_json::to_string(&telemetry).unwrap_or_default(),
        artifact_path: None,
    }) {
        logger::warn(&format!("failed to write telemetry record: {}", e));
    }

        let details = format!(
            "User '{}' created={}, activated={}, added_to_group={}",
            username, created, activated, added_to_group
        );

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: self.name().into(),
            status: "ok".into(),
            details,
            artifact_path: None,
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}
