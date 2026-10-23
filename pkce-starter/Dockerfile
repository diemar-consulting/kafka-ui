# Keep Kafbat's backend executable JAR unchanged and load PKCE at runtime.
FROM azul/zulu-openjdk-alpine:25.0.4.1-jre-headless
RUN apk upgrade --no-cache && apk add --no-cache gcompat tzdata
RUN addgroup -S kafkaui && adduser -S kafkaui -G kafkaui
RUN mkdir /etc/kafkaui /opt/kafbat/extensions && chown -R kafkaui:kafkaui /etc/kafkaui /opt/kafbat
COPY api/build/libs/api-*.jar /api.jar
COPY pkce-starter/build/libs/pkce-starter-*.jar /opt/kafbat/extensions/
USER kafkaui
ENV JAVA_OPTS=""
EXPOSE 8080
CMD java --add-opens java.rmi/javax.rmi.ssl=ALL-UNNAMED $JAVA_OPTS -Dloader.path=/opt/kafbat/extensions -cp /api.jar org.springframework.boot.loader.launch.PropertiesLauncher
