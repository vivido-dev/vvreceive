fn main() -> std::process::ExitCode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match vvreceive::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    std::process::ExitCode::FAILURE
}
