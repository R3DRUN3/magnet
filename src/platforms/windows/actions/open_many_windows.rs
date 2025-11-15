//! Simulates DoS via rapid creation of multiple top-level overlapped windows (T1499.003).

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::Result;
use chrono::Utc;
use std::time::Instant;

// Import Windows API (via windows-sys)
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::{ValidateRect, GetStockObject, WHITE_BRUSH, HBRUSH},
    System::{LibraryLoader::GetModuleHandleW, Threading::Sleep},
    UI::WindowsAndMessaging::*,
};

/// Simulation that opens and closes 150 windows using the Windows API.
#[derive(Default)]
pub struct OpenManyWindowsSimulation;

impl Simulation for OpenManyWindowsSimulation {
    fn name(&self) -> &'static str {
        "windows::open_many_windows"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Opening 150 GUI windows and closing them (Windows API test)");

        if cfg.dry_run {
            logger::info("dry-run: would create 150 windows via CreateWindowExW and close them");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1499.003 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no actual windows created".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        let start = Instant::now();

        unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
            if instance.is_null() {
                logger::action_fail("failed to get module handle");
                anyhow::bail!("GetModuleHandleW returned null");
            }

            // Manual UTF-16 version of "MagnetWindowClass\0"
            let class_name: Vec<u16> = "MagnetWindowClass\0".encode_utf16().collect();

            // Define window class
            let wc = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: instance,
                hIcon: std::ptr::null_mut(),
                hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
                hbrBackground: GetStockObject(WHITE_BRUSH) as HBRUSH,
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
            };

            let atom = RegisterClassW(&wc);
            if atom == 0 {
                logger::action_fail("RegisterClassW failed");
                anyhow::bail!("RegisterClassW failed");
            }

            let mut windows: Vec<HWND> = Vec::with_capacity(150);

            for i in 1..=150 {
                let title = format!("hello from Magnet - window n. {}", i);
                let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();

                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    wide.as_ptr(),
                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    400,
                    300,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    instance,
                    std::ptr::null(),
                );

                if hwnd.is_null() {
                    logger::warn(&format!("failed to create window {}", i));
                } else {
                    windows.push(hwnd);
                }
            }

            // Wait 2 seconds
            Sleep(2000);

            // Close all windows
            for hwnd in &windows {
                PostMessageW(*hwnd, WM_CLOSE, 0, 0);
            }

            // Standard message loop
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) != 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        let elapsed = start.elapsed().as_millis();
        logger::info(&format!("Created and closed 150 windows in {} ms", elapsed));

        // Write telemetry
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1499.003 - {}", self.name()),
            status: "completed".into(),
            details: format!("Opened and closed 150 windows in {} ms", elapsed),
            artifact_path: None,
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}

extern "system" fn wndproc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match message {
            WM_PAINT => {
                ValidateRect(window, std::ptr::null());
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(window, message, wparam, lparam),
        }
    }
}
