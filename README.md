# CRV


First, setup up jsnark prerequires in reference to https://github.com/akosba/jsnark

$ cd CRV/JsnarkCircuitBuilder

$ javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar $(find ./src/* | grep ".java$")

$ java -cp bin examples.generators.Vote

shparkk95@kookmin.ac.kr
