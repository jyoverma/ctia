(ns ctia.http.routes.relationship
  (:require
    [compojure.api.sweet :refer :all]
    [ctia.domain.entities :as ent]
    [ctia.domain.entities.relationship :refer [with-long-id page-with-long-id]]
    [ctia.flows.crud :as flows]
    [ctia.http.routes.common
     :refer [created paginated-ok PagingParams RelationshipSearchParams]]
    [ctia.store :refer :all]
    [ctia.schemas.core :refer [NewRelationship Relationship]]
    [ring.util.http-response :refer [no-content not-found ok]]
    [schema-tools.core :as st]
    [schema.core :as s]))

(s/defschema RelationshipByExternalIdQueryParams
  PagingParams)

(defroutes relationship-routes
  (context "/relationship" []
           :tags ["Relationship"]
           (POST "/" []
                 :return Relationship
                 :body [relationship NewRelationship
                        {:description "a new Relationship"}]
                 :header-params [api_key :- (s/maybe s/Str)]
                 :summary "Adds a new Relationship"
                 :capabilities :create-relationship
                 :identity identity
                 (-> (flows/create-flow
                      :entity-type :relationship
                      :realize-fn ent/realize-relationship
                      :store-fn #(write-store :relationship create-relationships %)
                      :long-id-fn with-long-id
                      :entity-type :relationship
                      :identity identity
                      :entities [relationship]
                      :spec :new-relationship/map)
                     first
                     ent/un-store
                     created))

           (GET "/external_id/:external_id" []
                :return [(s/maybe Relationship)]
                :query [q RelationshipByExternalIdQueryParams]
                :path-params [external_id :- s/Str]
                :header-params [api_key :- (s/maybe s/Str)]
                :summary "List relationships by external id"
                :capabilities #{:read-relationship :external-id}
                (-> (read-store :relationship list-relationships
                                {:external_ids external_id} q)
                    page-with-long-id
                    ent/un-store-page
                    paginated-ok))

           (GET "/search" []
                :return (s/maybe [Relationship])
                :summary "Search for a Relationship using a Lucene/ES query string"
                :query [params RelationshipSearchParams]
                :capabilities #{:read-relationship :search-relationship}
                :header-params [api_key :- (s/maybe s/Str)]
                (-> (query-string-search-store
                     :relationship
                     query-string-search
                     (:query params)
                     (dissoc params :query :sort_by :sort_order :offset :limit)
                     (select-keys params [:sort_by :sort_order :offset :limit]))
                    page-with-long-id
                    ent/un-store-page
                    paginated-ok))

           (GET "/:id" []
                :return (s/maybe Relationship)
                :summary "Gets an Relationship by ID"
                :path-params [id :- s/Str]
                :header-params [api_key :- (s/maybe s/Str)]
                :capabilities :read-relationship
                (if-let [relationship (read-store :relationship read-relationship id)]
                  (-> relationship
                      with-long-id
                      ent/un-store
                      ok)
                  (not-found)))

           (DELETE "/:id" []
                   :no-doc true
                   :path-params [id :- s/Str]
                   :summary "Deletes an Relationship"
                   :header-params [api_key :- (s/maybe s/Str)]
                   :capabilities :delete-relationship
                   :identity identity
                   (if (flows/delete-flow
                        :get-fn #(read-store :relationship read-relationship %)
                        :delete-fn #(write-store :relationship delete-relationship %)
                        :entity-type :relationship
                        :entity-id id
                        :identity identity)
                     (no-content)
                     (not-found)))))
