#[tokio::test]
#[ignore = "requires a running local slicer-mac daemon and live API token"]
async fn live_slicer_smoke() {
    let base_url =
        std::env::var("SLICER_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned());
    let _ = base_url;
}
