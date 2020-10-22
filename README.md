# CRV


First, setup up jsnark prerequires in reference to https://github.com/akosba/jsnark

$ cd CRV/JsnarkCircuitBuilder

$ javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar $(find ./src/* | grep ".java$")

$ java -cp bin examples.generators.Vote

for vote circuit

$ java -cp bin examples.generators.Register

for register circuit

$ java -cp bin examples.generators.Tally

for tally circuit

shparkk95@kookmin.ac.kr
