mod config;
mod state;
mod firewall;
mod capture;
mod detection;
mod api;

use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    println!("Starting IDPS Rust Backend...");

    let config = config::Config::load();
    println!("Loaded Configuration: {:?}", config);

    let app_state = Arc::new(RwLock::new(state::AppState::new()));
    let firewall = Arc::new(firewall::FirewallManager::new());
    let shared_config = Arc::new(RwLock::new(config.clone()));

    let handle = tokio::runtime::Handle::current();
    capture::start_capture(app_state.clone(), config.clone(), firewall.clone(), handle);

    // Setup API state
    let api_state = Arc::new(api::ApiState {
        st: app_state.clone(),
        config: shared_config.clone(),
        firewall: firewall.clone(),
    });

    let app = api::create_router(api_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("API and WebSocket listening on 0.0.0.0:8000");

    // Setup Gateway if in GATEWAY mode
    firewall.setup_gateway(&config);

    let firewall_clone = firewall.clone();
    let shared_config_clone = shared_config.clone();

    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        tokio::signal::ctrl_c().await.expect("failed to install CTRL+C signal handler");
        println!("Received shutdown signal...");
    });

    server.await.unwrap();

    // Teardown Gateway before exiting
    let config_at_shutdown = shared_config_clone.read().await;
    firewall_clone.teardown_gateway(&config_at_shutdown);
    println!("IDPS Backend stopped gracefully.");
}
