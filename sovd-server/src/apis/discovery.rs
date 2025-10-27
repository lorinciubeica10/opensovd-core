use async_trait::async_trait;
use axum::http::Method;
use axum_extra::extract::{CookieJar, Host};
use sovd_api::{
    apis::discovery::{
        AreasAreaIdRelatedComponentsGetResponse, AreasAreaIdSubareasGetResponse,
        ComponentsComponentIdRelatedAppsGetResponse, ComponentsComponentIdSubcomponentsGetResponse,
        EntityCollectionEntityIdGetResponse, EntityCollectionGetResponse,
    },
    models::{self, AnyPathDocsGetDefaultResponse},
};

use crate::ServerImpl;

#[allow(unused_variables)]
#[async_trait]
impl sovd_api::apis::discovery::Discovery for ServerImpl {
    /// AreasAreaIdRelatedComponentsGet - GET /v1/areas/{area_id}/related-components
    async fn areas_area_id_related_components_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::AreasAreaIdRelatedComponentsGetPathParams,
    ) -> Result<AreasAreaIdRelatedComponentsGetResponse, ()> {
        todo!();
    }

    /// AreasAreaIdSubareasGet - GET /v1/areas/{area_id}/subareas
    async fn areas_area_id_subareas_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::AreasAreaIdSubareasGetPathParams,
        query_params: &models::AreasAreaIdSubareasGetQueryParams,
    ) -> Result<AreasAreaIdSubareasGetResponse, ()> {
        todo!();
    }

    /// ComponentsComponentIdRelatedAppsGet - GET /v1/components/{component_id}/related-apps
    async fn components_component_id_related_apps_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::ComponentsComponentIdRelatedAppsGetPathParams,
    ) -> Result<ComponentsComponentIdRelatedAppsGetResponse, ()> {
        todo!();
    }

    /// ComponentsComponentIdSubcomponentsGet - GET /v1/components/{component_id}/subcomponents
    async fn components_component_id_subcomponents_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::ComponentsComponentIdSubcomponentsGetPathParams,
        query_params: &models::ComponentsComponentIdSubcomponentsGetQueryParams,
    ) -> Result<ComponentsComponentIdSubcomponentsGetResponse, ()> {
        todo!();
    }

    /// EntityCollectionEntityIdGet - GET /v1/{entity_collection}/{entity_id}
    async fn entity_collection_entity_id_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::EntityCollectionEntityIdGetPathParams,
    ) -> Result<EntityCollectionEntityIdGetResponse, ()> {
        // Check, if requested entity_id is supported. TODO: include registered
        // sub SOVD Servers. Currently, we support only the component which hosts the SOVD server
        if path_params.entity_id != self.id {
            return Ok(
                EntityCollectionEntityIdGetResponse::Status0_AnUnexpectedRequestOccurred(
                    AnyPathDocsGetDefaultResponse::new(
                        "not-responding".to_owned(),
                        format!("Component {} did not respond.", path_params.entity_id),
                    ),
                ),
            );
        }

        let mut response = models::EntityCollectionEntityIdGet200Response::new(
            self.id.to_owned(),
            self.name.to_owned(),
        );

        let _ = response.data.insert(format!(
            "http://{}{}/components/{}/data",
            host.0,
            sovd_api::BASE_PATH,
            self.id
        ));

        Ok(EntityCollectionEntityIdGetResponse::Status200_TheResponseBodyContainsAPropertyForEachSupportedResourceAndRelatedCollection(
        response
      ))
    }

    /// EntityCollectionGet - GET /v1/{entity_collection}
    async fn entity_collection_get(
        &self,

        method: &Method,
        host: &Host,
        cookies: &CookieJar,
        path_params: &models::EntityCollectionGetPathParams,
        query_params: &models::EntityCollectionGetQueryParams,
    ) -> Result<EntityCollectionGetResponse, ()> {
        let mut items = Vec::<models::EntityCollectionGet200ResponseItemsInner>::new();

        // TODO: Besides self, sub SOVD Servers registering via mDNS must be
        // supported here.
        items.push(models::EntityCollectionGet200ResponseItemsInner::new(
            self.id.to_owned(),
            self.name.to_owned(),
            String::from(format!(
                "http://{}{}/components/{}",
                host.0,
                sovd_api::BASE_PATH,
                self.id
            )),
        ));

        Ok(EntityCollectionGetResponse::Status200_ResponseBody(
            models::EntityCollectionGet200Response::new(items),
        ))
    }
}
