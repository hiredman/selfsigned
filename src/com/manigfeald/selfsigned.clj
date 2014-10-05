(ns com.manigfeald.selfsigned
  (:import (java.util UUID)
           (java.security KeyPairGenerator
                          KeyStore)
           (org.bouncycastle.x509 X509V3CertificateGenerator)
           (org.bouncycastle.jce X509Principal)
           (org.bouncycastle.jce.provider BouncyCastleProvider)))

(java.security.Security/addProvider (BouncyCastleProvider.))

(defn key-pair []
  (.generateKeyPair
   (doto (KeyPairGenerator/getInstance "RSA")
     (.initialize 1024))))

(defn certificate-generator [n]
  (doto (X509V3CertificateGenerator.)
    (.setSerialNumber
     (BigInteger/valueOf (System/currentTimeMillis)))
    (.setIssuerDN
     (X509Principal.
      (format "CN=%s, OU=None, O=None, L=None, C=None" n)))
    (.setNotBefore (java.util.Date.
                    (- (System/currentTimeMillis)
                       (* 1000 60 60 24))))
    (.setNotAfter (java.util.Date.
                   (+ (System/currentTimeMillis)
                      (* 1000 60 60 24 365))))
    (.setSubjectDN
     (X509Principal.
      (format "CN=%s, OU=None, O=None, L=None, C=None" n)))))

(defn get-cert [pair cert-gen]
  (.generateX509Certificate
   (doto cert-gen
     (.setPublicKey (.getPublic pair))
     (.setSignatureAlgorithm "MD5WithRSAEncryption"))
   (.getPrivate pair)))

(defn keystore-from-cert [pair cert pass]
  (doto (KeyStore/getInstance "JKS")
    (.load nil nil)
    (.setKeyEntry (str (UUID/randomUUID))
                  (.getPrivate pair)
                  pass
                  (doto (make-array java.security.cert.Certificate 1)
                    (aset 0 cert)))))

(defn self-signed-keystore [pass]
  (let [kp (key-pair)
        cg (certificate-generator pass)
        c (get-cert kp cg)]
    (keystore-from-cert kp c (.toCharArray pass))))
