# Get the directory of the current script
$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Build the classpath string
$CLASSPATH = "$DIR\java;$DIR\weka.jar;$DIR\idb.jar"

# Run WEKA using a Java 17 or newer JDK
java --enable-native-access=ALL-UNNAMED --enable-native-access=javafx.graphics --add-opens=java.base/java.lang=ALL-UNNAMED -classpath $CLASSPATH weka.gui.GUIChooser