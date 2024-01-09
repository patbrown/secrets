(ns net.drilling.plugins.secrets
  (:require [clojure.java.io])
  (:import [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec]
           [java.security MessageDigest]
           [java.util Base64 Base64$Encoder Base64$Decoder]))

(def salt (get  (into {} (System/getenv)) "SALT"))
(def secrets-file (or (get (into {} (System/getenv)) "SECRET_DB") ".config/secrets"))

(def ^Base64$Encoder b64-encoder (.withoutPadding (Base64/getUrlEncoder)))
(def ^Base64$Decoder b64-decoder (Base64/getUrlDecoder))

(defn create-key [s]
  (let [sha (MessageDigest/getInstance "SHA-1")
        ba (->> (.digest sha (.getBytes s "UTF-8"))
                (take 16)
                byte-array)]
    (SecretKeySpec. ba "AES")))

(defn is-key? [thing] (instance? javax.crypto.spec.SecretKeySpec thing))

(defn encrypt!
  ([{:keys [value KEY]}] (encrypt! value KEY))
  ([x y]
   (cond (map? x) (encrypt! y (:KEY x) nil)
         (is-key? x) (encrypt! y x nil)
         :else (encrypt! x y nil)))
  ([value KEY _]
   (->> (.doFinal (doto (Cipher/getInstance "AES")
                    (.init Cipher/ENCRYPT_MODE KEY))
                  (.getBytes value "UTF-8"))
        (.encodeToString b64-encoder))))

(defn decrypt!
  ([{:keys [value KEY]}] (decrypt! value KEY nil))
  ([x y]
   (cond (map? x) (decrypt! y (:KEY x) nil)
         (is-key? x) (decrypt! y x nil)
         :else (decrypt! x y nil)))
  ([value KEY _]
   (try
     (String.
      (->> (.decode b64-decoder value)
           (.doFinal (doto (Cipher/getInstance "AES")
                       (.init Cipher/DECRYPT_MODE KEY))))
      "UTF-8")
     (catch Exception e
       nil))))

(defn new-secret
  ([] (new-secret (apply str (take 64 (repeatedly #(char (+ (rand 26) 65)))))))
  ([salt]
   (let [KEY (create-key salt)
         decrypt! (fn [s] (decrypt! s KEY nil))
         encrypt! (fn [s] (encrypt! s KEY nil))]
     {:KEY KEY
      :salt salt
      :encrypt! encrypt!
      :decrypt! decrypt!})))


(def ^:dynamic *default-secret* (new-secret salt))
(def ^:dynamic *secrets-file-location* (->> secrets-file clojure.java.io/resource))

(defn encrypt-secrets!
  ([secrets] (encrypt-secrets! *default-secret* secrets))
  ([secret secrets]
   (spit *secrets-file-location* (encrypt! secret (if-not (string? secrets) (str secrets) secrets)))))

(defn decrypt-secrets!
  ([] (decrypt-secrets! *default-secret*))
  ([secret]
   (let [raw-secrets (slurp *secrets-file-location*)]
     (clojure.edn/read-string (decrypt! secret raw-secrets)))))

(defn add-secret!
  ([k v] (add-secret! *default-secret* k v))
  ([secret k v]
   (let [secrets (decrypt-secrets! secret)
         new-secrets (assoc secrets k v)]
     (encrypt-secrets! secret new-secrets))))

(defn rm-secret!
  ([k] (rm-secret! *default-secret* k))
  ([secret k]
   (let [secrets (decrypt-secrets! secret)
         new-secrets (dissoc secrets k)]
     (encrypt-secrets! secret new-secrets))))

(defn get-secret
  ([] (decrypt-secrets! *default-secret*))
  ([k] (if (keyword? k)
         (get-secret *default-secret* k)
         (decrypt-secrets! k)))
  ([secret k]
   (get-in (decrypt-secrets! secret) (if-not (vector? k) [k] k))))
