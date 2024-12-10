(ns baby.pat.secrets
  (:require #?@(:bb [[babashka.pods :as pods]]
                :clj [[buddy.core.codecs :as codecs]
                      [buddy.core.nonce :as nonce]
                      [buddy.core.crypto :as crypto]
                      [buddy.core.kdf :as kdf]])
            [baby.pat.jes.vt :as vt]
            [clojure.edn]
            [clojure.java.io :as io]
            [orchestra.core :refer [defn-spec]])
  (:import (java.util Base64)))

(def ^:dynamic *default-secret* (get  (into {} (System/getenv)) "SALT"))
(def ^:dynamic *secrets-file-location* (or (get (into {} (System/getenv)) "SECRET_DB") "bin/resources/assets/secret.db"))

#?(:bb (pods/load-pod 'org.babashka/buddy "0.3.4"))
#?(:bb (require '[pod.babashka.buddy.core.codecs :as codecs]
                '[pod.babashka.buddy.core.nonce :as nonce]
                '[pod.babashka.buddy.core.crypto :as crypto]
                '[pod.babashka.buddy.core.kdf :as kdf]))

(defn-spec ^:private bytes->b64 ::vt/str
  "Converts bytes into base 64"
  [^bytes b ::vt/bytes]
  (String. (.encode (Base64/getEncoder) b)))
(defn-spec  ^:private b64->bytes ::vt/bytes
  "Converts base 64 into bytes"
  [^String s ::vt/str]
  (.decode (Base64/getDecoder) (.getBytes s)))

(defn-spec ^:private slow-key-stretch-with-pbkdf2 ::vt/bytes
  "Takes a weak text key and a number of bytes and stretches it."
  [weak-text-key ::vt/str n-bytes ::vt/long]
  #?(:bb (kdf/get-engine-bytes
          {:key weak-text-key
           :salt (codecs/str->bytes *default-secret*)
           :alg :pbkdf2
           :digest :sha512
           :iterations 1e5
           :length n-bytes})
     :clj (kdf/get-bytes
           (kdf/engine {:key weak-text-key
                        :salt (codecs/str->bytes *default-secret*)
                        :alg :pbkdf2
                        :digest :sha512
                        :iterations 1e5}) ;; target O(100ms) on commodity hardware
           n-bytes)))

(def  ^:private encrypt-fn #?(:bb crypto/block-cipher-encrypt :clj crypto/encrypt))

(defn-spec encrypt ::vt/encrypted
  "Encrypt and return a {:data <b64>, :iv <b64>} that can be decrypted with the
  same `password`.
  Performs pbkdf2 key stretching with quite a few iterations on `password`."
  [clear-text ::vt/any password ::vt/str]
  (let [initialization-vector (nonce/random-bytes 16)]
     {:data (bytes->b64
             (encrypt-fn
              (codecs/to-bytes clear-text)
              (slow-key-stretch-with-pbkdf2 password 64)
              initialization-vector
              {:algorithm :aes256-cbc-hmac-sha512}))
      :iv (bytes->b64 initialization-vector)}))

(def  ^:private decrypt-fn #?(:bb crypto/block-cipher-decrypt :clj crypto/decrypt))

(defn-spec decrypt ::vt/any
  "Decrypt and return the clear text for some output of `encrypt` given the
  same `password` used during encryption."
  [{:keys [data iv]} ::vt/encrypted password ::vt/str]
  (codecs/bytes->str
     (decrypt-fn
      (b64->bytes data)
      (slow-key-stretch-with-pbkdf2 password 64)
      (b64->bytes iv)
      {:algorithm :aes256-cbc-hmac-sha512})))

(defn-spec encrypt-secrets! ::vt/discard
  "Encrypts secrets at the entire `file` level."
  ([data ::vt/any] (encrypt-secrets! *default-secret* data))
  ([pass ::vt/str data ::vt/any]
   (spit *secrets-file-location* (encrypt (str data) pass))))

(defn-spec decrypt-secrets! ::vt/map
  "Decrypts secrets at the entire `file` level."
  ([] (decrypt-secrets! *default-secret*))
  ([pass ::vt/str]
   (let [raw-secrets (read-string (slurp *secrets-file-location*))]
     (clojure.edn/read-string (decrypt raw-secrets pass)))))

(defn-spec add-secret! ::vt/discard
  "Adds secret at the `kw` level."
  ([k ::vt/kw v ::vt/any] (add-secret! *default-secret* k v))
  ([pass ::vt/str k ::vt/kw v ::vt/any]
   (let [secrets (decrypt-secrets! pass)
         new-secrets (assoc secrets k v)]
     (encrypt-secrets! pass new-secrets))))

(defn-spec rm-secret! ::vt/any
  "Removes a secret at the `kw` level."
  ([k ::vt/kw] (rm-secret! *default-secret* k))
  ([pass ::vt/str k ::vt/kw]
   (let [secrets (decrypt-secrets! pass)
         new-secrets (dissoc secrets k)]
     (encrypt-secrets! pass new-secrets))))

(defn-spec get-secret ::vt/any
  "Gets a secret at the `kw` level. Only allows for one at a time."
  ([] (decrypt-secrets! *default-secret*))
  ([k ::vt/kw] (if (keyword? k)
         (get-secret *default-secret* k)
         (decrypt-secrets! k)))
  ([pass ::vt/str k ::vt/kw]
   (get-in (decrypt-secrets! pass) (if-not (vector? k) [k] k))))

(defmacro got-secret [k]
  "Use instead of get-secret for secrets in compile time cljs."
  (do `(get-secret ~k)))

(comment
(encrypt-secrets! {:a 0})
(decrypt-secrets!)
(rm-secret! :b)
(add-secret! :b 10)
(get-secret :a)
  )
