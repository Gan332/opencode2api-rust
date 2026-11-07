fn main() {
    println!("cargo:rerun-if-env-changed=OPENCODE2API_VERSION");
    let version = std::env::var("OPENCODE2API_VERSION")
        .or_else(|_| std::env::var("GITHUB_REF_NAME"))
        .unwrap_or_else(|_| "dev".to_string());
    println!("cargo:rustc-env=OPENCODE2API_VERSION={version}");
}
