//! Simulation: Create a new process via `NtCreateUserProcess` (low-level).
//!
//! This simulation spawns calc.exe via direct NTAPI calls and close the handle to it after 1 second.
//! Meant to simulate stealthy process creation behavior often used by malware.

use anyhow::Result;
use chrono::Utc;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};

// WinAPI / NTAPI
use winapi::ctypes::c_void;
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::ntdef::{HANDLE, UNICODE_STRING};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::{PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS};

use ntapi::ntrtl::{
    RtlAllocateHeap, RtlCreateProcessParametersEx, RtlDestroyProcessParameters, RtlFreeHeap,
    RtlInitUnicodeString, RtlProcessHeap, PRTL_USER_PROCESS_PARAMETERS, RTL_USER_PROC_PARAMS_NORMALIZED,
};

use ntapi::ntpsapi::{
    NtCreateUserProcess, PsCreateInitialState, PS_ATTRIBUTE_IMAGE_NAME, PS_ATTRIBUTE_LIST,
    PS_CREATE_INFO, PS_ATTRIBUTE, PS_ATTRIBUTE_u,
};

use widestring::U16CString;

/// Output name for tracking simulation artifact.
const ARTIFACT_NAME: &str = "nt_create_proc_sim";

#[derive(Default)]
pub struct CreateProcSim;

impl CreateProcSim {
    fn simulate_nt_proc_spawn() -> Result<()> {
        unsafe {
            let mut nt_image_path: UNICODE_STRING = std::mem::zeroed();
            let path = U16CString::from_str(r"\??\C:\Windows\System32\calc.exe")?;
            RtlInitUnicodeString(&mut nt_image_path, path.as_ptr() as *mut u16);

            let mut process_parameters: PRTL_USER_PROCESS_PARAMETERS = null_mut();
            let status = RtlCreateProcessParametersEx(
                &mut process_parameters,
                &mut nt_image_path,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                RTL_USER_PROC_PARAMS_NORMALIZED,
            );

            if status < 0 {
                return Err(anyhow::anyhow!("RtlCreateProcessParametersEx failed: {}", status));
            }

            let mut create_info: PS_CREATE_INFO = std::mem::zeroed();
            create_info.Size = std::mem::size_of::<PS_CREATE_INFO>();
            create_info.State = PsCreateInitialState;

            let attribute_list = RtlAllocateHeap(
                RtlProcessHeap(),
                0x00000008, // HEAP_ZERO_MEMORY
                std::mem::size_of::<PS_ATTRIBUTE_LIST>(),
            ) as *mut PS_ATTRIBUTE_LIST;

            if attribute_list.is_null() {
                RtlDestroyProcessParameters(process_parameters);
                return Err(anyhow::anyhow!("Failed to allocate attribute list"));
            }

            (*attribute_list).TotalLength = std::mem::size_of::<PS_ATTRIBUTE_LIST>();
            std::ptr::write_bytes(&mut (*attribute_list).Attributes[0], 0, 1);

            (*attribute_list).Attributes[0] = PS_ATTRIBUTE {
                Attribute: PS_ATTRIBUTE_IMAGE_NAME,
                Size: nt_image_path.Length as usize,
                u: PS_ATTRIBUTE_u {
                    Value: nt_image_path.Buffer as ULONG_PTR,
                },
                ReturnLength: null_mut(),
            };

            let mut h_process: HANDLE = null_mut();
            let mut h_thread: HANDLE = null_mut();

            let status = NtCreateUserProcess(
                &mut h_process,
                &mut h_thread,
                PROCESS_ALL_ACCESS,
                THREAD_ALL_ACCESS,
                null_mut(),
                null_mut(),
                0,
                0,
                process_parameters as *mut c_void,
                &mut create_info,
                attribute_list,
            );

            RtlFreeHeap(RtlProcessHeap(), 0, attribute_list as *mut _);
            RtlDestroyProcessParameters(process_parameters);

            if status < 0 {
                return Err(anyhow::anyhow!("NtCreateUserProcess failed: 0x{:x}", status));
            }

            logger::info("Process successfully created via NtCreateUserProcess");
            logger::info("Sleeping for 1 seconds before closing handle…");

            sleep(Duration::from_secs(1));

            if !h_process.is_null() {
                CloseHandle(h_process);
            }
            if !h_thread.is_null() {
                CloseHandle(h_thread);
            }

            Ok(())
        }
    }

    fn output_path() -> Option<PathBuf> {
        crate::core::telemetry::telemetry_dir().map(|mut p| {
            p.push(format!("{}.log", ARTIFACT_NAME));
            p
        })
    }
}

impl Simulation for CreateProcSim {
    fn name(&self) -> &'static str {
        "windows::create_proc"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Spawning process via NtCreateUserProcess");

        let start = Instant::now();
        let out_path = Self::output_path()
            .ok_or_else(|| anyhow::anyhow!("could not resolve MagnetTelemetry path"))?;

        if cfg.dry_run {
            logger::info("dry-run: would spawn process");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "create_proc".into(),
                status: "dry-run".into(),
                details: "dry-run: no process spawned".into(),
                artifact_path: Some(out_path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        match Self::simulate_nt_proc_spawn() {
            Ok(()) => {
                let elapsed = start.elapsed();
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "create_proc".into(),
                    status: "written".into(),
                    details: format!("Process created and handle closed after 1 ({}ms)", elapsed.as_millis()),
                    artifact_path: Some(out_path.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                logger::action_ok();
                Ok(())
            }
            Err(e) => {
                logger::action_fail("NtCreateUserProcess simulation failed");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "create_proc".into(),
                    status: "failed".into(),
                    details: format!("error: {}", e),
                    artifact_path: Some(out_path.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                Err(e)
            }
        }
    }
}
