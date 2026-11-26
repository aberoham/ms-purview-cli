#[tokio::main]
async fn main() {
    std::process::exit(ms_purview_cli::cli::execute().await);
}
