#!/bin/bash
set -xe

apt-get update -y
apt-get install -y docker.io curl

# Elasticsearch requires this kernel setting or it will refuse to start
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf

systemctl enable docker
systemctl start docker

# Shared network so ES and Kibana can talk by container name
docker network create elk

# ── Elasticsearch ──────────────────────────────────────────────────────────
docker run -d \
  --name elasticsearch \
  --network elk \
  --restart unless-stopped \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0

# Wait until ES responds before starting Kibana
echo "Waiting for Elasticsearch..."
until curl -s http://localhost:9200/_cluster/health | grep -qE '"status":"(green|yellow)"'; do
  sleep 5
done
echo "Elasticsearch ready."

# ── Kibana ─────────────────────────────────────────────────────────────────
docker run -d \
  --name kibana \
  --network elk \
  --restart unless-stopped \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200" \
  -e "XPACK_SECURITY_ENABLED=false" \
  docker.elastic.co/kibana/kibana:8.12.0

# Give Kibana time to register itself with ES before creating templates
sleep 60

# ── Index template — defines field types for all siem-* indices ────────────
curl -s -X PUT "http://localhost:9200/_index_template/siem" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["siem-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "@timestamp":                  { "type": "date" },
          "source_type":                 { "type": "keyword" },
          "event.dataset":               { "type": "keyword" },
          "event.severity":              { "type": "integer" },
          "event.outcome":               { "type": "keyword" },
          "event.action":                { "type": "keyword" },
          "event.category":              { "type": "keyword" },
          "event.kind":                  { "type": "keyword" },
          "source.ip":                   { "type": "ip" },
          "source.port":                 { "type": "integer" },
          "source.geo.location":         { "type": "geo_point" },
          "source.geo.country_iso_code": { "type": "keyword" },
          "source.geo.country_name":     { "type": "keyword" },
          "source.geo.city_name":        { "type": "keyword" },
          "destination.ip":              { "type": "ip" },
          "destination.port":            { "type": "integer" },
          "http.request.method":         { "type": "keyword" },
          "http.response.status_code":   { "type": "integer" },
          "http.response.bytes":         { "type": "long" },
          "url.path":                    { "type": "keyword" },
          "rule.name":                   { "type": "keyword" },
          "rule.category":               { "type": "keyword" },
          "rule.id":                     { "type": "keyword" },
          "network.transport":           { "type": "keyword" },
          "winlog.event_id":             { "type": "integer" },
          "user.name":                   { "type": "keyword" },
          "host.hostname":               { "type": "keyword" },
          "tags":                        { "type": "keyword" }
        }
      }
    }
  }'

echo "ELK stack fully configured."