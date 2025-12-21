(ns build
  (:require [clojure.tools.build.api :as b]
            [clojure.string :as str]))

(def lib 'org.clojars.pgdad/clj-ebpf-lb)
(def class-dir "target/classes")
(def basis (delay (b/create-basis {:project "deps.edn"})))

(defn- get-version
  "Get version from environment variable or git tag."
  []
  (or (System/getenv "VERSION")
      (let [tag (b/git-process {:git-args ["describe" "--tags" "--exact-match"]})]
        (when (and tag (not (str/blank? tag)))
          (str/replace (str/trim tag) #"^v" "")))
      "0.1.0-SNAPSHOT"))

(defn jar-file [version]
  (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (let [version (get-version)]
    (clean nil)
    (b/write-pom {:class-dir class-dir
                  :lib lib
                  :version version
                  :basis @basis
                  :src-dirs ["src"]
                  :scm {:url "https://github.com/pgdad/clj-ebpf-lb"
                        :connection "scm:git:git://github.com/pgdad/clj-ebpf-lb.git"
                        :developerConnection "scm:git:ssh://git@github.com/pgdad/clj-ebpf-lb.git"
                        :tag (str "v" version)}
                  :pom-data [[:description "High-performance eBPF-based Layer 4 load balancer written in Clojure"]
                             [:url "https://github.com/pgdad/clj-ebpf-lb"]
                             [:licenses
                              [:license
                               [:name "MIT License"]
                               [:url "https://opensource.org/licenses/MIT"]]]]})
    (b/copy-dir {:src-dirs ["src" "resources"]
                 :target-dir class-dir})
    (b/jar {:class-dir class-dir
            :jar-file (jar-file version)})
    (println "Built:" (jar-file version))))

(defn deploy [_]
  (let [version (get-version)]
    (jar nil)
    ((requiring-resolve 'deps-deploy.deps-deploy/deploy)
     {:installer :remote
      :artifact (b/resolve-path (jar-file version))
      :pom-file (b/pom-path {:lib lib :class-dir class-dir})})))
