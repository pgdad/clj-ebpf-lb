(ns lb.access-log-test
  "Unit tests for access logging module."
  (:require [clojure.test :refer [deftest testing is use-fixtures]]
            [clojure.java.io :as io]
            [lb.access-log.logger :as logger]
            [lb.access-log.file-writer :as file-writer])
  (:import [java.io File]))

;;; =============================================================================
;;; Test Data
;;; =============================================================================

(def test-entry
  (logger/->AccessLogEntry
    "2025-01-15T10:30:45.123Z"
    :conn-closed
    "192.168.1.100"
    54321
    "10.0.0.1"
    80
    "10.0.0.5"
    8080
    1523
    1024
    4096
    "tcp"))

(def test-entry-new-conn
  (logger/->AccessLogEntry
    "2025-01-15T10:30:44.000Z"
    :new-conn
    "192.168.1.100"
    54321
    "10.0.0.1"
    80
    "10.0.0.5"
    8080
    nil
    0
    0
    "tcp"))

;;; =============================================================================
;;; JSON Format Tests
;;; =============================================================================

(deftest format-json-test
  (testing "Formats complete entry as JSON"
    (let [json (logger/format-json test-entry)]
      (is (string? json))
      (is (clojure.string/includes? json "\"timestamp\""))
      (is (clojure.string/includes? json "\"conn-closed\""))
      (is (clojure.string/includes? json "\"192.168.1.100\""))
      (is (clojure.string/includes? json "\"10.0.0.5\""))
      (is (clojure.string/includes? json "1523"))
      (is (clojure.string/includes? json "1024"))
      (is (clojure.string/includes? json "4096"))))

  (testing "Formats new-conn entry without duration"
    (let [json (logger/format-json test-entry-new-conn)]
      (is (string? json))
      (is (clojure.string/includes? json "\"new-conn\""))
      (is (clojure.string/includes? json "\"duration_ms\":null")))))

;;; =============================================================================
;;; CLF Format Tests
;;; =============================================================================

(deftest format-clf-test
  (testing "Formats complete entry in CLF style"
    (let [clf (logger/format-clf test-entry)]
      (is (string? clf))
      (is (clojure.string/starts-with? clf "192.168.1.100"))
      (is (clojure.string/includes? clf "CONN-CLOSED"))
      (is (clojure.string/includes? clf "10.0.0.1:80 -> 10.0.0.5:8080"))
      (is (clojure.string/includes? clf "1024/4096"))
      (is (clojure.string/includes? clf "1523ms"))))

  (testing "Formats new-conn without duration shows dash"
    (let [clf (logger/format-clf test-entry-new-conn)]
      (is (clojure.string/includes? clf "NEW-CONN"))
      (is (clojure.string/ends-with? clf "-")))))

;;; =============================================================================
;;; Format Entry Tests
;;; =============================================================================

(deftest format-entry-test
  (testing "Formats as JSON when specified"
    (let [result (logger/format-entry :json test-entry)]
      (is (clojure.string/starts-with? result "{"))))

  (testing "Formats as CLF when specified"
    (let [result (logger/format-entry :clf test-entry)]
      (is (clojure.string/starts-with? result "192.168.1.100"))))

  (testing "Defaults to JSON for unknown format"
    (let [result (logger/format-entry :unknown test-entry)]
      (is (clojure.string/starts-with? result "{")))))

;;; =============================================================================
;;; File Writer Tests
;;; =============================================================================

(deftest file-writer-create-test
  (testing "Creates writer with default options"
    (let [temp-dir (System/getProperty "java.io.tmpdir")
          temp-path (str temp-dir "/test-access-create.log")
          writer (file-writer/create-writer :path temp-path)]
      (try
        (is (some? writer))
        (is (= temp-path (:base-path writer)))
        (is (= (* 100 1024 1024) (:max-size-bytes writer)))
        (is (= 10 (:max-files writer)))
        (finally
          (file-writer/close! writer)
          (.delete (io/file temp-path)))))))

(deftest file-writer-write-test
  (testing "Writes lines to file"
    (let [temp-dir (System/getProperty "java.io.tmpdir")
          temp-path (str temp-dir "/test-access-write.log")
          writer (file-writer/create-writer :path temp-path :max-size-mb 1)]
      (try
        (let [writer1 (file-writer/write-line! writer "line 1")
              writer2 (file-writer/write-line! writer1 "line 2")]
          (file-writer/close! writer2)
          (let [content (slurp temp-path)]
            (is (clojure.string/includes? content "line 1"))
            (is (clojure.string/includes? content "line 2"))))
        (finally
          (.delete (io/file temp-path)))))))

(deftest file-writer-rotation-test
  (testing "Rotates files when max size exceeded"
    (let [temp-dir (System/getProperty "java.io.tmpdir")
          temp-path (str temp-dir "/test-access-rotate.log")
          ;; Very small max size to trigger rotation
          writer (file-writer/create-writer :path temp-path
                                            :max-size-mb 0.0001  ; ~100 bytes
                                            :max-files 3)]
      (try
        ;; Write enough to trigger rotation
        (let [long-line (apply str (repeat 200 "x"))
              w1 (file-writer/write-line! writer long-line)
              w2 (file-writer/write-line! w1 long-line)]
          (file-writer/close! w2)
          ;; Check that rotation occurred
          (is (.exists (io/file temp-path)))
          (is (.exists (io/file (str temp-path ".1")))))
        (finally
          (.delete (io/file temp-path))
          (.delete (io/file (str temp-path ".1")))
          (.delete (io/file (str temp-path ".2"))))))))

(deftest file-writer-status-test
  (testing "Returns correct status"
    (let [temp-dir (System/getProperty "java.io.tmpdir")
          temp-path (str temp-dir "/test-access-status.log")
          writer (file-writer/create-writer :path temp-path
                                            :max-size-mb 10
                                            :max-files 5)]
      (try
        (let [writer2 (file-writer/write-line! writer "test line")
              status (file-writer/get-status writer2)]
          (is (= temp-path (:path status)))
          (is (= (* 10 1024 1024) (:max-size-bytes status)))
          (is (= 5 (:max-files status)))
          (is (pos? (:current-size-bytes status)))
          (file-writer/close! writer2))
        (finally
          (.delete (io/file temp-path)))))))

;;; =============================================================================
;;; Async Logger Tests
;;; =============================================================================

(deftest async-logger-test
  (testing "Logger processes entries asynchronously"
    (let [output (atom [])
          output-fn (fn [line] (swap! output conj line))
          logger (logger/create-async-logger :json [output-fn] :buffer-size 100)]
      (try
        (logger/log-entry! logger test-entry)
        (logger/log-entry! logger test-entry-new-conn)
        ;; Give time for async processing
        (Thread/sleep 100)
        (is (= 2 (count @output)))
        (is (every? #(clojure.string/starts-with? % "{") @output))
        (finally
          (logger/stop-logger! logger)))))

  (testing "Logger uses specified format"
    (let [output (atom [])
          output-fn (fn [line] (swap! output conj line))
          logger (logger/create-async-logger :clf [output-fn] :buffer-size 100)]
      (try
        (logger/log-entry! logger test-entry)
        (Thread/sleep 100)
        (is (= 1 (count @output)))
        (is (clojure.string/starts-with? (first @output) "192.168.1.100"))
        (finally
          (logger/stop-logger! logger)))))

  (testing "Logger calls multiple output functions"
    (let [output1 (atom [])
          output2 (atom [])
          fn1 (fn [line] (swap! output1 conj line))
          fn2 (fn [line] (swap! output2 conj line))
          logger (logger/create-async-logger :json [fn1 fn2] :buffer-size 100)]
      (try
        (logger/log-entry! logger test-entry)
        (Thread/sleep 100)
        (is (= 1 (count @output1)))
        (is (= 1 (count @output2)))
        (finally
          (logger/stop-logger! logger))))))

(deftest logger-running-test
  (testing "Reports running state correctly"
    (let [logger (logger/create-async-logger :json [(fn [_])] :buffer-size 100)]
      (is (logger/logger-running? logger))
      (logger/stop-logger! logger)
      (Thread/sleep 50)
      (is (not (logger/logger-running? logger))))))
