#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

CLASSPATH="$DIR/java:$DIR/weka.jar:$DIR/idb.jar"

java --enable-native-access=ALL-UNNAMED --enable-native-access=javafx.graphics --add-opens=java.base/java.lang=ALL-UNNAMED -classpath "$CLASSPATH" weka.gui.GUIChooser
