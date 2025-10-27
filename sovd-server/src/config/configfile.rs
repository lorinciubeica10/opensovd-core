/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Configuration {
    pub server: ServerConfig,
    pub logging: sovd_tracing::LoggingConfig,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub node_id: String,
    pub node_name: String,
}

pub trait ConfigSanity {
    /// Checks the configuration for common mistakes and returns an error message if found.
    fn validate_sanity(&self) -> Result<(), String>;
}

impl Default for Configuration {
    fn default() -> Self {
        let mut node_name = std::env::consts::OS.to_owned() + " Node";

        Configuration {
            server: ServerConfig {
                address: "0.0.0.0".to_owned(),
                port: 7690,
                node_id: gethostname::gethostname().to_str().unwrap().to_owned(),
                node_name: node_name.remove(0).to_uppercase().to_string() + &node_name,
            },
            logging: sovd_tracing::LoggingConfig::default(),
        }
    }
}

impl ConfigSanity for Configuration {
    fn validate_sanity(&self) -> Result<(), String> {
        // Add checks for Configuration fields here if needed
        Ok(())
    }
}
