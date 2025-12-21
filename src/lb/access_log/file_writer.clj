(ns lb.access-log.file-writer
  "Rotating file writer for access logs.
   Handles log file rotation based on size with configurable max files."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.logging :as log])
  (:import [java.io File BufferedWriter FileWriter]
           [java.nio.file Files Paths StandardCopyOption]
           [java.time Instant]))

;;; =============================================================================
;;; State
;;; =============================================================================

(defrecord FileWriterState
  [^BufferedWriter writer
   ^File file
   ^long current-size
   ^long max-size-bytes
   ^int max-files
   ^String base-path])

;;; =============================================================================
;;; File Rotation
;;; =============================================================================

(defn- rotate-files!
  "Rotate log files: .log -> .log.1 -> .log.2 -> ... -> .log.N
   Removes the oldest file if max-files is exceeded."
  [base-path max-files]
  (let [base (io/file base-path)
        parent (.getParentFile base)
        name (.getName base)]
    ;; Create parent directory if needed
    (when parent
      (.mkdirs parent))

    ;; Delete the oldest file if it exists
    (let [oldest (io/file parent (str name "." max-files))]
      (when (.exists oldest)
        (.delete oldest)))

    ;; Shift files: .N -> .N+1, .N-1 -> .N, etc.
    (doseq [i (range (dec max-files) 0 -1)]
      (let [from-file (io/file parent (str name "." i))
            to-file (io/file parent (str name "." (inc i)))]
        (when (.exists from-file)
          (.renameTo from-file to-file))))

    ;; Rotate current log: .log -> .log.1
    (when (.exists base)
      (let [target (io/file parent (str name ".1"))]
        (.renameTo base target)))))

(defn- open-writer
  "Open a buffered writer for the log file."
  [path]
  (let [file (io/file path)
        parent (.getParentFile file)]
    (when parent
      (.mkdirs parent))
    (BufferedWriter. (FileWriter. file true))))

(defn- get-file-size
  "Get current file size in bytes."
  [path]
  (let [file (io/file path)]
    (if (.exists file)
      (.length file)
      0)))

;;; =============================================================================
;;; Public API
;;; =============================================================================

(defn create-writer
  "Create a rotating file writer.

   Options:
     :path - Log file path (default: \"logs/access.log\")
     :max-size-mb - Max file size in MB before rotation (default: 100)
     :max-files - Max number of rotated files to keep (default: 10)

   Returns a FileWriterState record."
  [& {:keys [path max-size-mb max-files]
      :or {path "logs/access.log"
           max-size-mb 100
           max-files 10}}]
  (let [max-size-bytes (* max-size-mb 1024 1024)]
    (->FileWriterState
      (open-writer path)
      (io/file path)
      (get-file-size path)
      max-size-bytes
      max-files
      path)))

(defn write-line!
  "Write a line to the log file with automatic rotation.

   Returns updated FileWriterState."
  [^FileWriterState state ^String line]
  (try
    (let [line-bytes (.getBytes (str line "\n") "UTF-8")
          line-size (count line-bytes)
          new-size (+ (:current-size state) line-size)]

      ;; Check if rotation is needed
      (if (and (pos? (:current-size state))
               (> new-size (:max-size-bytes state)))
        ;; Need to rotate
        (do
          ;; Close current writer
          (.close (:writer state))

          ;; Rotate files
          (rotate-files! (:base-path state) (:max-files state))

          ;; Open new writer and write
          (let [new-writer (open-writer (:base-path state))]
            (.write new-writer line)
            (.newLine new-writer)
            (.flush new-writer)
            (assoc state
                   :writer new-writer
                   :current-size line-size)))

        ;; No rotation needed, just write
        (do
          (.write (:writer state) line)
          (.newLine (:writer state))
          (.flush (:writer state))
          (assoc state :current-size new-size))))

    (catch Exception e
      (log/warn e "Error writing to access log")
      state)))

(defn close!
  "Close the file writer."
  [^FileWriterState state]
  (when-let [writer (:writer state)]
    (try
      (.flush writer)
      (.close writer)
      (catch Exception e
        (log/warn e "Error closing access log writer")))))

(defn flush!
  "Flush the file writer buffer."
  [^FileWriterState state]
  (when-let [writer (:writer state)]
    (try
      (.flush writer)
      (catch Exception e
        (log/warn e "Error flushing access log writer")))))

(defn get-status
  "Get file writer status."
  [^FileWriterState state]
  {:path (:base-path state)
   :current-size-bytes (:current-size state)
   :max-size-bytes (:max-size-bytes state)
   :max-files (:max-files state)
   :percent-full (if (pos? (:max-size-bytes state))
                   (* 100.0 (/ (:current-size state) (:max-size-bytes state)))
                   0.0)})
