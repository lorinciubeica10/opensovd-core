use once_cell::sync::Lazy;
use reqwest::Client;
use sovd_handlers::get_process_pid;
use sovd_server::server_config::ServerConfig;
use sovd_server::sovd_server::spawn_test_server;
use std::sync::{Mutex, Once};

use std::time::Duration;
use reqwest::StatusCode;
use anyhow::{Result, anyhow};

// Static configuration for the test server using Lazy initialization
static SERVER_CONFIG: Lazy<ServerConfig> = Lazy::new(|| {
    ServerConfig::create_server_settings(
        "../config/sovd_server_apps.conf", // Path to server config file
        "http".to_string(),                // Protocol
        "127.0.0.1".to_string(),           // Host
        "0".to_string(),                   // Port (0 means auto-assign)
        "standalone".to_string(),          // Mode
        "chassis-hpc".to_string(),         // Component name
    )
    .expect("Failed to create server config")
});

// Static variable to store the server address once started
static SERVER_ADDR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// Static HTTP client used for sending requests
static CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .no_proxy() // Disable proxy
        .build()
        .expect("Failed to build reqwest client")
});

// Starts the test server if not already started
async fn start_server() {

    let mut addr_lock = SERVER_ADDR.lock().unwrap();
    if addr_lock.is_none() {
        let (addr, _handle) = spawn_test_server(&SERVER_CONFIG).await;
        *addr_lock = Some(addr.to_string());
        drop(addr_lock); // Release lock before waiting
        wait_for_server_ready(&addr.to_string()).await;
    }
}

// Retrieves the server address from the static variable
fn get_server_addr() -> String {
    SERVER_ADDR
        .lock()
        .unwrap()
        .clone()
        .expect("Server address not set")
}

// Builds the path for accessing app-specific resources
fn build_app_path_resources(resource: &str) -> String {
    let pid = get_process_pid("sovd-server").expect("Fail to read pid");
    format!(
        "v1/apps/sovd-server-{}/data/sovd-server-{}-{}",
        pid, pid, resource
    )
}

// Sends a GET request to the specified endpoint and asserts success
async fn get_and_assert_endpoint(path: &str) -> Result<String> {
    start_server().await;

    // Normalize and build the URL
    let base = get_server_addr();
    let url = reqwest::Url::parse(&format!("http://{}/", base))
        .and_then(|mut u| { u.set_path(path); Ok(u) })
        .map_err(|e| anyhow!("Invalid URL for path '{}': {}", path, e))?;

    let max_attempts = 3;
    let mut last_err = None;
    for attempt in 1..=max_attempts {
        match CLIENT
            .get(url.clone())
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let bytes = resp.bytes().await;
                match (status, bytes) {
                    (StatusCode::OK, Ok(body)) => {
                        if body.is_empty() {
                            return Err(anyhow!("Response body is empty for {}", url));
                        }
                        match String::from_utf8(body.to_vec()) {
                            Ok(text) => return Ok(text),
                            Err(_) => return Err(anyhow!("Response body is not valid UTF-8 for {}", url)),
                        }
                    }
                    (StatusCode::NOT_FOUND, _) => return Err(anyhow!("Endpoint {} not found (404)", url)),
                    (StatusCode::INTERNAL_SERVER_ERROR, Ok(body)) => {
                        let text = String::from_utf8_lossy(&body);
                        return Err(anyhow!("Internal server error at {} (500): {}", url, text));
                    }
                    (status, Ok(body)) => {
                        let text = String::from_utf8_lossy(&body);
                        return Err(anyhow!("Unexpected status {} for {}: {}", status, url, text));
                    }
                    (_, Err(e)) => {
                        last_err = Some(format!("Failed to read response body: {}", e));
                        if attempt < max_attempts {
                            tokio::time::sleep(Duration::from_millis(150 * attempt as u64)).await;
                            continue;
                        } else {
                            return Err(anyhow!("Failed to read response body after {} attempts: {}", max_attempts, e));
                        }
                    }
                }
            }
            Err(e) => {
                last_err = Some(format!("Request failed for {}: {}", url, e));
                // Only retry for transient errors
                if e.is_timeout() || e.is_connect() {
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_millis(150 * attempt as u64)).await;
                        continue;
                    }
                }
                return Err(anyhow!("Request failed for {}: {}", url, e));
            }
        }
    }
    Err(anyhow!("All attempts failed for {}: {:?}", url, last_err))
}

async fn wait_for_server_ready(addr: &str) {
    let url = format!("http://{}/v1/components", addr);
    let max_attempts = 10;

    for _ in 0..max_attempts {
        if let Ok(resp) = CLIENT.get(&url).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    panic!("Server did not become ready in time");
}

// Integration test: Get general component information
#[tokio::test]
async fn get_component_info() -> Result<()>{
    let res = get_and_assert_endpoint("v1/components").await;
    match res {
        Ok(_) => Ok(()),
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get data for a specific component
#[tokio::test]
async fn get_component_data() -> Result<()>{
    let res = get_and_assert_endpoint("v1/components/chassis-hpc").await;
    match res {
        Ok(_) => Ok(()),
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get detailed data for a specific component
#[tokio::test]
async fn get_component_specific_data() -> Result<()>{
    let res = get_and_assert_endpoint("v1/components/chassis-hpc/data").await;
    match res {
        Ok(_) => Ok(()),
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get CPU usage for a specific component
#[tokio::test]
async fn get_component_specific_cpu_usage() -> Result<()>{
    let res = get_and_assert_endpoint("v1/components/chassis-hpc/data/chassis-hpc-cpu").await;
    match res {
        Ok(body) => {
            assert!(body.contains("cpu"), "Expected 'cpu' in response");
            Ok(())
        },
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get disk usage for a specific component
#[tokio::test]
async fn get_component_specific_disk_usage() -> Result<()> {
    let res = get_and_assert_endpoint("v1/components/chassis-hpc/data/chassis-hpc-disk").await;
    match res {
        Ok(body) => {
            assert!(body.contains("disk"), "Expected 'disk' in response");
            Ok(())
        },
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}


// Integration test: Get memory usage for a specific component
#[tokio::test]
async fn get_component_specific_memory_usage() -> Result<()>{
    let res = get_and_assert_endpoint("v1/components/chassis-hpc/data/chassis-hpc-memory").await;
    match res {
        Ok(body) => {
            assert!(body.contains("memory"), "Expected 'memory' in response");
            Ok(())
        },
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get related applications for a component
#[tokio::test]
async fn get_related_apps() -> Result<()>{
    let res = get_and_assert_endpoint("v1/components/chassis-hpc/related-apps").await;
    match res {
        Ok(_) => Ok(()),
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get information about a specific app using its PID
#[tokio::test]
async fn get_specific_app() -> Result<()>{
    let path = format!(
        "v1/apps/sovd-server-{}",
        get_process_pid("sovd-server").expect("Fail to read pid")
    );
    let res = get_and_assert_endpoint(&path).await;
    match res {
        Ok(_) => Ok(()),
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get data for a specific app
#[tokio::test]
async fn get_specific_app_data() -> Result<()> {
    let path = format!(
        "v1/apps/sovd-server-{}/data",
        get_process_pid("sovd-server").expect("Fail to read pid")
    );
    let res = get_and_assert_endpoint(&path).await;
    match res {
        Ok(body) => {
            assert!(!body.is_empty(), "Expected non-empty response body for app data");
            Ok(())
        },
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get CPU usage data for a specific app
#[tokio::test]
async fn get_specific_app_cpu() -> Result<()> {
    let path = build_app_path_resources("cpu");
    let res = get_and_assert_endpoint(&path).await;
    match res {
        Ok(body) => {
            assert!(body.contains("cpu"), "Expected 'cpu' in response");
            Ok(())
        },
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get memory usage data for a specific app
#[tokio::test]
async fn get_specific_app_memory() -> Result<()> {
    let path = build_app_path_resources("memory");
    let res = get_and_assert_endpoint(&path).await;
    match res {
        Ok(body) => {
            assert!(body.contains("memory"), "Expected 'memory' in response");
            Ok(())
        },
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get disk usage data for a specific app
#[tokio::test]
async fn get_specific_app_disk() -> Result<()> {
    let path = build_app_path_resources("disk");
    let res = get_and_assert_endpoint(&path).await;
    match res {
        Ok(body) => {
            assert!(body.contains("disk"), "Expected 'disk' in response");
            Ok(())
        },
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

// Integration test: Get all resource data for a specific app
#[tokio::test]
async fn get_specific_app_all() -> Result<()> {
    let path = build_app_path_resources("all");
    let res = get_and_assert_endpoint(&path).await;
    match res {
        Ok(_) => Ok(()),
        Err(err) => panic!("Expected Ok, got error: {}", err),
    }
}

#[tokio::test]
async fn get_nonexistent_endpoint() -> anyhow::Result<()> {

    let res = get_and_assert_endpoint("v1/components/nonexistent").await;
    match res {
        Err(err) => {
            let err_msg = err.to_string();
            assert!(err_msg.contains("404") || err_msg.contains("error sending request"), "Expected 404 error, got: {}", err_msg);
        }
        Ok(body) => {
            // If we got here, the endpoint unexpectedly succeeded; fail the test.
            panic!("Expected nonexistent endpoint to fail, but it returned: {}", body);
        }
    }
    Ok(())
}

#[tokio::test]
async fn get_invalid_resource() -> anyhow::Result<()> {
    let res = get_and_assert_endpoint("v1/components/chassis-hpc/data/invalid-resource").await;
    match res {
        Err(err) => {
            let err_msg = err.to_string();
            assert!(err_msg.contains("500") || err_msg.contains("error sending request"), "Expected 500 error, got: {}", err_msg);
        }
        Ok(body) => {
            panic!("Expected 500 error, but got successful response: {}", body);
        }
    }
    Ok(())
}
