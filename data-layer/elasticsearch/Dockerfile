FROM docker.elastic.co/elasticsearch/elasticsearch:8.11.1

USER root
COPY elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/config
USER elasticsearch

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
