# kafka-fips-chainguard

Requirements Satsified with this Architecture: 

* Cilium IPsec enabled
* AES-GCM (rfc4106(gcm(aes))) in use
* Default-deny CiliumNetworkPolicies
* mTLS on Kafka proxy
* FIPS-Validated Chainguard images (Cilium and Kafka-Proxy)
* EKS (which uses FIPS-capable kernel crypto modules)

Additional Reccomendation:
* OS in FIPS mode (proc/sys/crypto/fips_enabled = 1)

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

openssl genrsa -out proxy.key 4096

openssl req -new \
  -key proxy.key \
  -out proxy.csr \
  -config proxy-openssl.cnf

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

### Generate Proxy Secret
```
kubectl -n kafka create secret generic kafka-proxy-mtls \
  --from-file=tls.crt=proxy.crt \
  --from-file=tls.key=proxy.key \
  --from-file=ca.crt=ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Generate Client Secret

```
kubectl -n kafka create secret generic kafka-client-mtls \
  --from-file=ca.crt=ca.crt \
  --from-file=client.crt=client.crt \
  --from-file=client.key=client.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

## kcat mTLS test

```
kubectl -n kafka run kcat --rm -i --restart=Never \
  --image=edenhill/kcat:1.7.1 \
  --overrides='
{
  "spec": {
    "containers": [{
      "name": "kcat",
      "image": "edenhill/kcat:1.7.1",
      "command": ["sh","-lc"],
      "args": ["kcat -b kafka-proxy-0.kafka.svc:9094 -X security.protocol=SSL -X ssl.ca.location=/certs/ca.crt -X ssl.certificate.location=/certs/client.crt -X ssl.key.location=/certs/client.key -L"],
      "volumeMounts": [{"name":"certs","mountPath":"/certs","readOnly":true}]
    }],
    "volumes": [{"name":"certs","secret":{"secretName":"kafka-client-mtls"}}]
  }
}'
```

## Test create a topic

```
kubectl -n kafka exec -it deploy/broker-0 -- \
  kafka-topics.sh --bootstrap-server broker-0.kafka.svc:9092 \
  --create --topic test --partitions 3 --replication-factor 3
```

## mTLS FIPS Compliance tests should return the following:

* TLS 1.2 negotiated
* TLS 1.1 rejected
* Cipher ECDHE-RSA-AES128-GCM-SHA256 (FIPS)
* Hash SHA-256 
* Key exchange P-256 
* Mutual auth happened (server requested client cert, client sent it) 

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
