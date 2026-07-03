fn main() {
    if let Err(error) = m0untain_service::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
