FROM jhapy/base-image-slim:1.16

ENV JAVA_OPTS=""
ENV APP_OPTS=""

ADD target/utils-spring-boot-admin-server.jar /app/

ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Xverify:none -Djava.security.egd=file:/dev/./urandom -Dpinpoint.agentId=$(date | md5sum | head -c 24) -jar /app/utils-spring-boot-admin-server.jar $APP_OPTS"]

HEALTHCHECK --interval=30s --timeout=30s --retries=10 CMD curl -f http://localhost:9998/management/health || exit 1

EXPOSE 9998