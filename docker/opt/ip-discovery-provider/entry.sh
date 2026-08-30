#!/bin/sh

appHome="/opt/ip-discovery-provider"
source ${appHome}/static-functions

log "INFO" "Launching the Network Discovery Provider"
java $JAVA_OPTS -jar ./app.jar

#exec "$@"
