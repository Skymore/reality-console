#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("headless")) {
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
            std::process::exit(64);
        }
        let Some(output) = arguments.next() else {
            std::process::exit(64);
        };
        if arguments.next().is_some() {
            std::process::exit(64);
        }
        match reality_client_lib::HeadlessInvocation::from_stdin(std::path::Path::new(&output)) {
            Ok(invocation) => reality_client_lib::run_headless(invocation),
            Err(_) => std::process::exit(65),
        }
    } else {
        reality_client_lib::run();
    }
}
