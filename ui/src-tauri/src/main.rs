// AgentSnitch Tauri entrypoint (tray + popup UI)
// Thin wrapper; real logic in lib.rs

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    agentsnitch_ui::run();
}
