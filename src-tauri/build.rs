fn main() {
    let mut attributes = tauri_build::Attributes::new();
    // Test harnesses must remain runnable without UAC. The distributed release
    // executable, which manages WFP filters, always requests elevation.
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        let windows =
            tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"));
        attributes = attributes.windows_attributes(windows);
    }
    tauri_build::try_build(attributes).expect("failed to build m0untain resources");
}
