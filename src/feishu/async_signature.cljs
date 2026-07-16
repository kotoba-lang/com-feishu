(ns feishu.async-signature
  "Cloudflare Workers / browser counterpart to `feishu.signature` -- see
  that ns's docstring for the shared scheme this verifies, and
  `meta-webhook.async-signature` for why this is a plain `.cljs`
  namespace (Web Crypto's `SubtleCrypto.digest` is Promise-based).

  `raw-body` MUST be the exact bytes Feishu sent (pre-JSON-parse) -- on a
  Cloudflare Worker that means reading `request.text()` BEFORE any
  `request.json()` call (a Request body stream can only be consumed
  once).")

(defn- bytes->hex [^js buf]
  (let [arr (js/Uint8Array. buf)]
    (apply str (map (fn [b] (let [h (.toString b 16)]
                              (if (= 1 (.-length h)) (str "0" h) h)))
                     (array-seq arr)))))

(defn sha256-hex
  "hex(SHA-256(s)) -- returns a `js/Promise<string>`."
  [s]
  (-> (.digest js/crypto.subtle "SHA-256" (.encode (js/TextEncoder.) s))
      (.then bytes->hex)))

(defn valid-signature?
  "Same contract as `feishu.signature/valid-signature?`, async: returns a
  `js/Promise<boolean>`."
  [{:keys [timestamp nonce encrypt-key body]} signature]
  (-> (sha256-hex (str timestamp nonce encrypt-key body))
      (.then (fn [hex] (= (str signature) hex)))))
