(ns lb.cluster-test
  "Unit tests for the cluster module."
  (:require [clojure.test :refer :all]
            [lb.cluster.protocol :as proto]
            [lb.cluster.sync :as sync]))

;;; =============================================================================
;;; Protocol Tests
;;; =============================================================================

(deftest test-generate-node-id
  (testing "Generate unique node IDs"
    (let [id1 (proto/generate-node-id)
          id2 (proto/generate-node-id)]
      (is (string? id1))
      (is (string? id2))
      (is (not= id1 id2))
      (is (clojure.string/starts-with? id1 "lb-")))))

(deftest test-lamport-clock
  (testing "Lamport clock versioning"
    ;; Test that versions increment
    (let [v1 (proto/next-version)
          v2 (proto/next-version)
          v3 (proto/next-version)]
      (is (< v1 v2))
      (is (< v2 v3))
      (is (= (proto/current-version) v3))

      ;; Test update-clock! with much higher value
      (let [high-version (+ v3 1000)]
        (proto/update-clock! high-version)
        (let [v4 (proto/next-version)]
          (is (> v4 high-version)))))))

(deftest test-make-node-info
  (testing "Create NodeInfo"
    (let [node (proto/make-node-info "node-1" "10.0.0.1:7946")]
      (is (= "node-1" (:node-id node)))
      (is (= "10.0.0.1:7946" (:address node)))
      (is (= 0 (:incarnation node)))  ; Starts at 0
      (is (number? (:last-seen node)))
      (is (number? (:join-time node))))))

(deftest test-make-syncable-state
  (testing "Create SyncableState"
    (let [version (proto/next-version)
          state (proto/make-syncable-state
                  :health
                  "target-1"
                  {:status :healthy}
                  version
                  "node-1")]
      (is (= :health (:state-type state)))
      (is (= "target-1" (:key state)))
      (is (= {:status :healthy} (:value state)))
      (is (= version (:version state)))
      (is (= "node-1" (:source-node state)))
      (is (number? (:timestamp state))))))

(deftest test-gossip-message-creation
  (testing "Create push message"
    (let [states [(proto/make-syncable-state :health "t1" {:status :healthy} 1 "n1")]
          msg (proto/push-message "node-1" states)]
      (is (= :push (:msg-type msg)))
      (is (= "node-1" (:sender msg)))
      (is (= states (:states msg)))))

  (testing "Create pull message"
    (let [digest {:k1 1 :k2 2}
          msg (proto/pull-message "node-1" digest)]
      (is (= :pull (:msg-type msg)))
      (is (= "node-1" (:sender msg)))
      (is (= digest (:digest msg)))))

  (testing "Create push-pull message"
    (let [states [(proto/make-syncable-state :health "t1" {:status :healthy} 1 "n1")]
          digest {:k1 1}
          msg (proto/push-pull-message "node-1" states digest)]
      (is (= :push-pull (:msg-type msg)))
      (is (= "node-1" (:sender msg)))
      (is (= states (:states msg)))
      (is (= digest (:digest msg))))))

(deftest test-state-key
  (testing "Extract state key"
    (let [state (proto/make-syncable-state :health "target-1" {:status :healthy} 1 "node-1")]
      (is (= [:health "target-1"] (proto/state-key state))))))

;;; =============================================================================
;;; Sync Provider Tests
;;; =============================================================================

(deftest test-health-provider-creation
  (testing "Health state provider can be created"
    (let [health-states (atom {"target-1" {:status :healthy
                                           :last-check-time 1000
                                           :consecutive-successes 3
                                           :consecutive-failures 0}})
          applied (atom [])
          provider (sync/create-health-provider
                     (fn [] @health-states)
                     (fn [tid state] (swap! applied conj [tid state])))]

      ;; Test provider type
      (is (= :health (proto/provider-type provider)))

      ;; Test get-sync-state - returns nil without membership init,
      ;; or valid states if membership is initialized (from other tests)
      (let [states (proto/get-sync-state provider)]
        (is (or (nil? states)
                (and (seq states)
                     (every? #(= :health (:state-type %)) states))))))))

(deftest test-circuit-breaker-provider-creation
  (testing "Circuit breaker state provider can be created"
    (let [cb-states (atom {"target-1" {:state :closed
                                        :error-rate 0.0
                                        :last-transition 1000}})
          applied (atom [])
          provider (sync/create-circuit-breaker-provider
                     (fn [] @cb-states)
                     (fn [tid state] (swap! applied conj [tid state])))]

      ;; Test provider type
      (is (= :circuit-breaker (proto/provider-type provider))))))

(deftest test-drain-provider-creation
  (testing "Drain state provider can be created"
    (let [drain-states (atom {"target-1" {:status :draining
                                           :start-time 1000
                                           :proxy-name "web"}})
          applied (atom [])
          provider (sync/create-drain-provider
                     (fn [] @drain-states)
                     (fn [tid state] (swap! applied conj [tid state])))]

      ;; Test provider type
      (is (= :drain (proto/provider-type provider))))))

;;; =============================================================================
;;; Conflict Resolution Tests
;;; =============================================================================

(deftest test-circuit-breaker-conflict-resolution
  (testing "OPEN always wins over CLOSED"
    (let [cb-states (atom {"target-1" {:state :closed :error-rate 0.0 :last-transition 1000}})
          applied (atom [])
          provider (sync/create-circuit-breaker-provider
                     (fn [] @cb-states)
                     (fn [tid state]
                       (swap! cb-states assoc tid state)
                       (swap! applied conj [tid state])))]

      ;; Apply remote OPEN state
      (let [remote-states [{:state-type :circuit-breaker
                            :key "target-1"
                            :value {:state :open :error-rate 0.5 :last-transition 2000}
                            :version 100
                            :source-node "node-2"
                            :timestamp (System/currentTimeMillis)}]
            result (proto/apply-remote-state provider remote-states)]

        ;; OPEN should be applied
        (is (= 1 (:applied result)))
        (is (= 0 (:rejected result)))
        (is (= :open (get-in @cb-states ["target-1" :state]))))))

  (testing "HALF-OPEN beats CLOSED"
    (let [cb-states (atom {"target-1" {:state :closed :error-rate 0.0 :last-transition 1000}})
          provider (sync/create-circuit-breaker-provider
                     (fn [] @cb-states)
                     (fn [tid state]
                       (swap! cb-states assoc tid state)))]

      ;; Apply remote HALF-OPEN state
      (let [remote-states [{:state-type :circuit-breaker
                            :key "target-1"
                            :value {:state :half-open :error-rate 0.0 :last-transition 2000}
                            :version 100
                            :source-node "node-2"
                            :timestamp (System/currentTimeMillis)}]
            result (proto/apply-remote-state provider remote-states)]

        ;; HALF-OPEN should be applied
        (is (= 1 (:applied result)))
        (is (= :half-open (get-in @cb-states ["target-1" :state])))))))

(deftest test-drain-conflict-resolution
  (testing "Draining beats active/nil"
    (let [drain-states (atom {})  ; No local drain
          applied (atom [])
          provider (sync/create-drain-provider
                     (fn [] @drain-states)
                     (fn [tid state]
                       (swap! drain-states assoc tid state)
                       (swap! applied conj [tid state])))]

      ;; Apply remote draining state
      (let [remote-states [{:state-type :drain
                            :key "target-1"
                            :value {:status :draining :start-time 1000 :proxy-name "web"}
                            :version 100
                            :source-node "node-2"
                            :timestamp (System/currentTimeMillis)}]
            result (proto/apply-remote-state provider remote-states)]

        ;; Draining should be applied
        (is (= 1 (:applied result)))
        (is (= 0 (:rejected result)))))))

;;; =============================================================================
;;; Event Tests
;;; =============================================================================

(deftest test-cluster-events
  (testing "Create cluster events"
    (let [event (proto/make-event :node-join "node-1" {:address "10.0.0.1:7946"})]
      (is (= :node-join (:event-type event)))
      (is (= "node-1" (:node-id event)))
      (is (= {:address "10.0.0.1:7946"} (:data event)))
      (is (number? (:timestamp event))))))

;;; =============================================================================
;;; Message Serialization Tests
;;; =============================================================================

(deftest test-message-serialization
  (testing "Gossip message to/from map"
    (let [states [(proto/make-syncable-state :health "t1" {:status :healthy} 1 "n1")]
          msg (proto/push-message "node-1" states)
          m (proto/gossip-message->map msg)
          back (proto/map->gossip-message m)]
      (is (= :push (:msg-type back)))
      (is (= "node-1" (:sender back)))
      (is (= 1 (count (:states back))))))

  (testing "Ping message serialization"
    (let [msg (proto/make-message :ping "node-1" "node-2" [] {} {:incarnation 5})
          m (proto/gossip-message->map msg)
          back (proto/map->gossip-message m)]
      (is (= :ping (:msg-type back)))
      (is (= "node-1" (:sender back)))
      (is (= "node-2" (:target back)))
      (is (= 5 (get-in back [:payload :incarnation]))))))
