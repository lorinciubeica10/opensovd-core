use crate::ServerImpl;

mod bulk_data;
mod capabilities;
mod communication_logs;
mod configurations;
mod data_retrieval;
mod discovery;
mod fault_handling;
mod locking;
mod logging;
mod operations_controls;
mod target_modes;
mod updates;

impl sovd_api::apis::ErrorHandler for ServerImpl {}
