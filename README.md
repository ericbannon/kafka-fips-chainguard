# kafka-fips-chainguard


## Create cluster UID

```
docker run --rm cgr.dev/chainguard-private/kafka:latest \
  kafka-storage.sh random-uuid
```

## Geberate local TLS certs and create a secret


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

## Initial Installation 

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

##