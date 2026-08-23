fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    match vvreceive::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
    #[cfg(not(target_os = "linux"))]
    std::process::ExitCode::FAILURE
}
