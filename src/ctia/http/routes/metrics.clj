(ns ctia.http.routes.metrics
  (:import (com.codahale.metrics Gauge Timer
                                 Counter Histogram Meter))
  (:require [compojure.api.sweet :refer :all]
            [ring.util.http-response :refer :all]
            [schema.core :as s]
            [metrics.gauges :as gauges]
            [metrics.meters :as meters]
            [metrics.histograms :as histograms]
            [metrics.counters :as counters]
            [metrics.timers :as timers]
            [metrics.core :refer [default-registry]]
            [metrics.utils :refer [all-metrics]]))

(defprotocol RenderableMetric
  (render-to-basic [metric]
    "Turn a metric into a basic Clojure datastructure."))

(extend-type Gauge
  RenderableMetric
  (render-to-basic [g]
    {:type :gauge
     :value (gauges/value g)}))

(extend-type Timer
  RenderableMetric
  (render-to-basic [t]
    {:type :timer
     :rates (timers/rates t)
     :percentiles (timers/percentiles t)
     :max (timers/largest t)
     :min (timers/smallest t)
     :mean (timers/mean t)
     :standard-deviation (timers/std-dev t)}))

(extend-type Meter
  RenderableMetric
  (render-to-basic [m]
    {:type :meter
     :rates (meters/rates m)}))

(extend-type Histogram
  RenderableMetric
  (render-to-basic [h]
    {:type :histogram
     :max (histograms/largest h)
     :min (histograms/smallest h)
     :mean (histograms/mean h)
     :standard-deviation (histograms/std-dev h)
     :percentiles (histograms/percentiles h)}))

(extend-type Counter
  RenderableMetric
  (render-to-basic [c]
    {:type :counter
     :value (counters/value c)}))

(defn- render-metric [[metric-name metric]]
  [metric-name (render-to-basic metric)])

(defn render-metrics []
  (into {} (map render-metric (all-metrics default-registry))))

(defroutes metrics-routes
  (context "/metrics" []
    :tags ["Metrics"]
    (GET "/" []
      :summary "Display Metrics"
      :header-params [api_key :- (s/maybe s/Str)]
      :capabilities :developer
      (ok (render-metrics)))))
