(ns build
  (:require [babashka.process :refer [shell]]
            [clojure.tools.build.api :as b]
            [clojure.string]
            [clojure.edn]))

(defn basis [deps-edn aliases]
  (b/create-basis {:project deps-edn
                   :aliases aliases}))

(defn uber-file [lib version]
  (format "target/%s-%s-run.jar" (name lib) version))

(defn jar-file [lib version]
  (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

(defn extract-build [build-key]
  (let [{:keys [username version]
         :as build-config} (-> (clojure.edn/read-string (slurp "deps.edn"))
                               :build-with)
        lib (keyword "baby.pat" (name build-key))]
    (assoc build-config
           :lib lib
           :pom-file (str "target/classes/META-INF/maven/baby.pat/" (name build-key) "/pom.xml")
           :jar-file (jar-file lib version))))

(defn add-scm-when-needed [pom-config pred? scm-url username repo]
  (if pred?
    (let [url (str "git@" scm-url ":" username ":" repo ".git")
          scm-url (str "scm:git:" url)
          rev (-> (apply (partial babashka.process/sh {}) ["git" "rev-parse" "HEAD"]) :out clojure.string/trim)]
      (assoc pom-config
             :scm {:tag  rev
                   :connection scm-url
                   :developerConnection scm-url
                   :url url}
             :pom-data [[:licenses
                         [:license
                          [:name "Eclipse Public License 1.0"]
                          [:url "https://opensource.org/license/epl-1-0/"]
                          [:distribution "repo"]]]
                        ]))
    pom-config))

(defn jar [{:keys [build]}]
  (let [{:keys [project aliases src-dirs jar-file pom-file clojars? class-dir lib version scm-url username repo] :as the-build} (extract-build build)
        base-pom {:class-dir class-dir
                  :lib lib
                  :version version
                  :basis (basis project aliases)
                  :src-dirs src-dirs}
        target-pom (add-scm-when-needed base-pom clojars? scm-url username repo)
        ready-pom (merge target-pom
                        {})
        #_#_deploy-pom (assoc target-pom :class-dir ???)]
    (println (str "WRITING: " target-pom))
    (b/write-pom ready-pom)
    (println "POM WRITTEN")
    #_(when clojars? (b/write-pom deploy-pom))
    (println (str "COPYING: " {:target class-dir :source src-dirs}))
    (b/copy-dir {:src-dirs src-dirs
                 :target-dir class-dir})
    (println "CLASSES COPIED")
    (println "JARRING: " {:lib lib :version version})
    (b/jar {:class-dir class-dir
            :jar-file jar-file})
    (println "JAR CREATED")
    (println "MOVING ASSETS")
    (babashka.fs/delete-if-exists "target/deploy.jar")
    (babashka.fs/copy jar-file "target/deploy.jar")
    (babashka.fs/delete-if-exists "target/pom.xml")
    (babashka.fs/copy pom-file "target/pom.xml")
    (println "ASSETS READY")))

(defn uber [{:keys [build] :as hug}]
  (let [{:keys [project aliases src-dirs class-dir entry-point lib version]} (extract-build build)
        _ (println (str "THESE ARE THE PATHS: " src-dirs))]
    (clean nil)
    (println "cleaned")
    (b/copy-dir {:src-dirs src-dirs
                 :target-dir class-dir})
    (println "copied")
    (b/compile-clj {:basis (basis project aliases)
                    :src-dirs src-dirs
                    :class-dir class-dir
                    :ns-compile (into '[] [(symbol entry-point)])})
    (println "compiled")
    (b/uber {:class-dir class-dir
             :uber-file (uber-file lib version)
             :basis (basis project aliases)})
    (println "Uberjar written to" (uber-file lib version))))
