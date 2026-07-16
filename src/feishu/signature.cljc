(ns feishu.signature
  "JVM-only (see `feishu.async-signature` for the Cloudflare Workers/
  browser counterpart -- same sync-vs-async platform split
  `meta-webhook.signature`/`async-signature` documents, Web Crypto's
  `subtle.digest` is inherently async).

  Feishu/Lark Event Subscription verification -- two INDEPENDENT checks;
  which one applies depends on whether the space's callback config has an
  Encrypt Key set:

  1. `token-valid?` -- plain string compare of the decoded body's
     `header.token` (v2 schema) against your configured Verification
     Token. No crypto. Always present regardless of Encrypt Key config.
  2. `valid-signature?` -- `sha256(timestamp + nonce + encrypt-key + body)`
     hex digest compared against the `X-Lark-Signature` request header,
     only present when an Encrypt Key IS configured (Feishu then also
     encrypts the body itself with that key -- decrypting the body is
     NOT implemented here, out of scope; `token-valid?` above works
     without needing an Encrypt Key at all, so it's the simpler path if
     you don't need payload encryption).

  Implemented per Feishu's published Event Subscription docs but -- same
  caveat as this workspace's `teams.jwt-verify` -- never exercised
  against live Feishu infrastructure (no deployed Feishu app exists yet).
  `token-valid?` is the more trustworthy of the two since it's a plain
  string compare with no crypto to get subtly wrong.

  Reference: https://open.feishu.cn/document/server-docs/event-subscription-guide/event-security-verification"
  #?(:clj (:import [java.security MessageDigest])))

(defn token-valid?
  [expected-token actual-token]
  (boolean (and expected-token actual-token (= expected-token actual-token))))

#?(:clj
   (defn- bytes->hex [bs]
     (apply str (map (fn [b]
                        (let [h (Integer/toHexString (bit-and (int b) 0xff))]
                          (if (= 1 (count h)) (str "0" h) h)))
                      bs))))

#?(:clj
   (defn sha256-hex
     "hex(SHA-256(s)) -- the value compared against `X-Lark-Signature`."
     [s]
     (bytes->hex (.digest (MessageDigest/getInstance "SHA-256")
                           (.getBytes (str s) "UTF-8")))))

#?(:clj
   (defn valid-signature?
     "`timestamp`/`nonce` come from the `X-Lark-Request-Timestamp`/
     `X-Lark-Request-Nonce` headers, `encrypt-key` is the space's
     configured Encrypt Key, `body` is the RAW request body string
     (pre-JSON-parse -- same requirement as every other raw-body HMAC
     check in this workspace). `signature` is the `X-Lark-Signature`
     header value."
     [{:keys [timestamp nonce encrypt-key body]} signature]
     (boolean (and signature (= (str signature) (sha256-hex (str timestamp nonce encrypt-key body)))))))
