# kafka-fips-chainguard

Requirements Satsified with this Architecture: 

* FIPS-Validated Chainguard images (Cilium and Kafka-Proxy)
* mTLS on Kafka proxy
* Cilium IPsec enabled
* AES-GCM (rfc4106(gcm(aes))) in use
* Default-deny CiliumNetworkPolicies
* EKS (which uses FIPS-capable kernel crypto modules)

**DOCUMENTATION AREAS:**

Client → mTLS (FIPS TLS1.3) → Proxy
Proxy → Cilium IPsec (AES-GCM) → Broker
Node-to-node → IPsec ESP

Additional Reccomendation:
* OS in FIPS mode (proc/sys/crypto/fips_enabled = 1)

# IAMGUARDED Kafka Deployment Setup

## Create cluster UID

```
docker run --rm cgr.dev/chainguard-private/kafka:latest \
  kafka-storage.sh random-uuid
```

## Geberate local TLS certs and create a secret (Skip to generating secret if you already have keys)

```
openssl genrsa -out ca.key 4096

openssl req -x509 -new -nodes \
  -key ca.key \
  -sha256 \
  -days 3650 \
  -out ca.crt \
  -subj "/CN=kafka-mtls-ca"

# PROXY leaf (uses SANs+EKUs from kafka-openssl.cnf)
openssl genrsa -out proxy.key 4096

openssl req -new \
  -key proxy.key \
  -out proxy.csr \
  -config kafka-openssl.cnf

openssl x509 -req \
  -in proxy.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out proxy.crt \
  -days 365 \
  -sha256 \
  -extfile kafka-openssl.cnf \
  -extensions v3_req

# CLIENT leaf (simple client cert; optional to also give SANs/EKU via cnf)
openssl genrsa -out client.key 4096

openssl req -new \
  -key client.key \
  -out client.csr \
  -subj "/CN=kafka-client"

openssl x509 -req \
  -in client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 365 \
  -sha256
```

### Generate TLS Secret
```
kubectl -n kafka create secret generic kafka-tls \
  --from-file=tls.crt=proxy.crt \
  --from-file=tls.key=proxy.key \
  --from-file=ca.crt=ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n kafka create secret generic kafka-client-mtls \
  --from-file=ca.crt=ca.crt \
  --from-file=client.crt=client.crt \
  --from-file=client.key=client.key \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n kafka create secret generic kafka-proxy-mtls \
  --from-file=ca.crt=ca.crt \
  --from-file=tls.crt=proxy.crt \
  --from-file=tls.key=proxy.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Generate keystores and Truststores for JKS

```
KEYPASS="$(openssl rand -hex 24)"
TRUSTPASS="$(openssl rand -hex 24)"

echo "KEYPASS=$KEYPASS"
echo "TRUSTPASS=$TRUSTPASS"

kubectl -n kafka create secret generic kafka-tls-passwords \
  --from-literal=keystore-password="$KEYPASS" \
  --from-literal=truststore-password="$TRUSTPASS" \
  --dry-run=client -o yaml | kubectl apply -f -
  ```

### Generate JKS Secrets for Iamguarded Chainguard Configuration

```
openssl pkcs8 -topk8 -nocrypt -in proxy.key -out proxy.pkcs8.key

openssl pkcs12 -export \
  -in proxy.crt \
  -inkey proxy.pkcs8.key \
  -certfile ca.crt \
  -name kafka \
  -passout pass:"$KEYPASS" \
  -out kafka.keystore.p12

keytool -importkeystore \
  -srckeystore kafka.keystore.p12 \
  -srcstoretype PKCS12 \
  -srcstorepass "$KEYPASS" \
  -destkeystore kafka.keystore.jks \
  -deststoretype JKS \
  -deststorepass "$KEYPASS" \
  -noprompt

keytool -importcert \
  -alias CARoot \
  -file ca.crt \
  -keystore kafka.truststore.jks \
  -storepass "$TRUSTPASS" \
  -noprompt

kubectl -n kafka create secret generic kafka-jks \
  --from-file=kafka.keystore.jks=./kafka.keystore.jks \
  --from-file=kafka.truststore.jks=./kafka.truststore.jks \
  --dry-run=client -o yaml | kubectl apply -f -
```


## Deploy Kafka Brokers (Chainguard Iamguarded Chart)

```
helm upgrade --install kafka oci://cgr.dev/chainguard-private/iamguarded-charts/kafka \
  -n kafka --create-namespace \
  -f kafka-helm/values.yaml
```

## Tests & Confirmation

```
kubectl -n kafka exec kafka-broker-0 -c kafka -- sh -lc '
cat >/tmp/client-ssl.properties <<EOF
security.protocol=SSL
ssl.endpoint.identification.algorithm=https

ssl.truststore.location=/opt/iamguarded/kafka/config/certs/kafka.truststore.jks
ssl.truststore.password=$(grep -m1 "^ssl.truststore.password=" /opt/iamguarded/kafka/config/server.properties | cut -d= -f2)

ssl.keystore.location=/opt/iamguarded/kafka/config/certs/kafka.keystore.jks
ssl.keystore.password=$(grep -m1 "^ssl.keystore.password=" /opt/iamguarded/kafka/config/server.properties | cut -d= -f2)
ssl.key.password=$(grep -m1 "^ssl.keystore.password=" /opt/iamguarded/kafka/config/server.properties | cut -d= -f2)
EOF

echo "Wrote /tmp/client-ssl.properties"
ls -l /tmp/client-ssl.properties
'
```
#### Smoke Test

```
kubectl -n kafka exec kafka-broker-0 -c kafka -- sh -lc '
/opt/iamguarded/kafka/bin/kafka-topics.sh \
  --bootstrap-server kafka-broker-headless.kafka.svc:9094 \
  --command-config /tmp/client-ssl.properties \
  --create --if-not-exists \
  --topic smoke-test --partitions 3 --replication-factor 3
'

kubectl -n kafka exec -i kafka-broker-0 -c kafka -- sh -lc '
echo "hello-$(date +%s)" | /opt/iamguarded/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server kafka-broker-headless.kafka.svc:9094 \
  --producer.config /tmp/client-ssl.properties \
  --topic smoke-test \
  --request-required-acks all \
  --producer-property linger.ms=0 \
  --producer-property retries=3 \
  --producer-property delivery.timeout.ms=15000
echo "producer-exit-code=$?"
'

kubectl -n kafka exec kafka-broker-0 -c kafka -- sh -lc '
/opt/iamguarded/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka-broker-headless.kafka.svc:9094 \
  --consumer.config /tmp/client-ssl.properties \
  --topic smoke-test \
  --group smoke-test-g1 \
  --from-beginning \
  --timeout-ms 20000 \
  --max-messages 5
echo "consumer-exit-code=$?"
'

```

# Cilium FIPS

## Configure CIPHER Suite Secret for Encryption

```
kubectl -n kube-system create secret generic cilium-ipsec-keys \
  --from-literal=keys="1 rfc4106(gcm(aes)) $(openssl rand -hex 20) 128" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Note: the algorithm used and enforced is reccomended for encryption in this use case

## Installation 

```
helm repo add cilium https://helm.cilium.io/
helm repo update
```

```
helm upgrade --install cilium cilium/cilium \
  -n kube-system --create-namespace \
  --version 1.16.6 \
  -f values.yaml
```

## Apply FIPS restrictive network policies for Cilium

```
kubectl apply -f fips-network-policies/kafka-cilium-netpol.yaml
```

**Verify Encryption** 

```
kubectl -n kube-system exec ds/cilium -- cilium status | grep Encryption

kubectl -n kube-system exec ds/cilium -- ip -s xfrm state

kubectl -n kube-system exec ds/cilium -- cilium encrypt status

kubectl -n kube-system exec ds/cilium -- sh -lc "ip -s xfrm state | egrep -n 'aead|auth|enc|rfc4106|gcm|cbc|sha' | head -n 50"
```

**Confirm Network Policy Enforcement:**

```
kubectl -n kafka get ciliumnetworkpolicies

kubectl -n kube-system exec ds/cilium -- cilium status | grep Policy

kubectl create ns test-ns

kubectl -n test-ns run testpod \
  --image=curlimages/curl \
  --restart=Never \
  -- sleep 3600

kubectl -n test-ns exec testpod -- \
  nc -zv <broker-pod-ip> 9092
```

...this last command should time out 


# Test FIPS Configurations

## FIPS Ciphers using OpenSSL (local port-forward)

```
kubectl -n kafka port-forward svc/kafka-proxy-0 9094:9094

openssl s_client -connect localhost:9094 -tls1

openssl s_client -connect localhost:9094

openssl s_client \
  -connect localhost:9094 \
  -CAfile ca.crt \
  -cert client.crt \
  -key client.key \
  -tls1_3 </dev/null 2>/dev/null | egrep 'Protocol|Cipher|Verify return code'
```
