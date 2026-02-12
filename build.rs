use winres::WindowsResource;


fn main() {
    // Only run this on Windows
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = WindowsResource::new();
        // This looks for "icon.ico" in your project folder
        res.set_icon("icon.ico");
        res.compile().unwrap();
    }
}