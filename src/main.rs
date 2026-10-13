fn main() {
    let config = conductor::config::Config::default();
    println!(
        "conductor: unstable placeholder (http_bind={})",
        config.http_bind
    );
}
