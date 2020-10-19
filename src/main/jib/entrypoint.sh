#!/bin/sh

echo "The application will start in ${JHAPY_SLEEP}s.......with JAVA_OPTS = ${JAVA_OPTS} , JAVA_TOOL_OPTIONS = ${JAVA_TOOL_OPTIONS}, APP_OPTS = ${APP_OPTS}" && sleep ${JHAPY_SLEEP}
exec java ${JAVA_OPTS} -noverify -XX:+AlwaysPreTouch -Djava.security.egd=file:/dev/./urandom -cp /app/resources/:/app/classes/:/app/libs/* "org.jhapy.admin.Application" "${APP_OPTS}"
