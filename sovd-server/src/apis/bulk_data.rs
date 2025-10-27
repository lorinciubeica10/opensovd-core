use async_trait::async_trait;
use axum::http::Method;
use axum_extra::extract::{CookieJar, Host};
use sovd_api::{
    apis::bulk_data::{
        EntityCollectionEntityIdBulkDataCategoryBulkDataIdDeleteResponse,
        EntityCollectionEntityIdBulkDataCategoryBulkDataIdGetResponse,
        EntityCollectionEntityIdBulkDataCategoryDeleteResponse,
        EntityCollectionEntityIdBulkDataCategoryGetResponse,
        EntityCollectionEntityIdBulkDataCategoryPostResponse,
        EntityCollectionEntityIdBulkDataGetResponse,
    },
    models,
    types::ByteArray,
};

use crate::ServerImpl;

#[allow(unused_variables)]
#[async_trait]
impl sovd_api::apis::bulk_data::BulkData for ServerImpl {
    /// EntityCollectionEntityIdBulkDataCategoryBulkDataIdDelete - DELETE /v1/{entity_collection}/{entity_id}/bulk-data/{category}/{bulk_data_id}
    async fn entity_collection_entity_id_bulk_data_category_bulk_data_id_delete(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::EntityCollectionEntityIdBulkDataCategoryBulkDataIdDeletePathParams,
    ) -> Result<EntityCollectionEntityIdBulkDataCategoryBulkDataIdDeleteResponse, ()> {
        todo!();
    }

    /// EntityCollectionEntityIdBulkDataCategoryBulkDataIdGet - GET /v1/{entity_collection}/{entity_id}/bulk-data/{category}/{bulk_data_id}
    async fn entity_collection_entity_id_bulk_data_category_bulk_data_id_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        header_params: &models::EntityCollectionEntityIdBulkDataCategoryBulkDataIdGetHeaderParams,
        path_params: &models::EntityCollectionEntityIdBulkDataCategoryBulkDataIdGetPathParams,
    ) -> Result<EntityCollectionEntityIdBulkDataCategoryBulkDataIdGetResponse, ()> {
        todo!();
    }

    /// EntityCollectionEntityIdBulkDataCategoryDelete - DELETE /v1/{entity_collection}/{entity_id}/bulk-data/{category}
    async fn entity_collection_entity_id_bulk_data_category_delete(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::EntityCollectionEntityIdBulkDataCategoryDeletePathParams,
    ) -> Result<EntityCollectionEntityIdBulkDataCategoryDeleteResponse, ()> {
        todo!();
    }

    /// EntityCollectionEntityIdBulkDataCategoryGet - GET /v1/{entity_collection}/{entity_id}/bulk-data/{category}
    async fn entity_collection_entity_id_bulk_data_category_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::EntityCollectionEntityIdBulkDataCategoryGetPathParams,
        query_params: &models::EntityCollectionEntityIdBulkDataCategoryGetQueryParams,
    ) -> Result<EntityCollectionEntityIdBulkDataCategoryGetResponse, ()> {
        todo!();
    }

    /// EntityCollectionEntityIdBulkDataCategoryPost - POST /v1/{entity_collection}/{entity_id}/bulk-data/{category}
    async fn entity_collection_entity_id_bulk_data_category_post(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        header_params: &models::EntityCollectionEntityIdBulkDataCategoryPostHeaderParams,
        path_params: &models::EntityCollectionEntityIdBulkDataCategoryPostPathParams,
        body: &ByteArray,
    ) -> Result<EntityCollectionEntityIdBulkDataCategoryPostResponse, ()> {
        todo!();
    }

    /// EntityCollectionEntityIdBulkDataGet - GET /v1/{entity_collection}/{entity_id}/bulk-data
    async fn entity_collection_entity_id_bulk_data_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::EntityCollectionEntityIdBulkDataGetPathParams,
        query_params: &models::EntityCollectionEntityIdBulkDataGetQueryParams,
    ) -> Result<EntityCollectionEntityIdBulkDataGetResponse, ()> {
        todo!();
    }
}
