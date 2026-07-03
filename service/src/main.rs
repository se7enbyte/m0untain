fn main() {
    let status = m0untain_service::current_status();
    println!("{}", status.message);
}
