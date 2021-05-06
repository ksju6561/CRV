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

Once, the libsnark library was built and you copied circuit_CRS_pk.dat, circuit_CRS_vk.dat, circuit_proof.dat files to ./CRV/JsnarkCircuitBuilder/datafiles/

you can use library as command

$ ../libsnark/build/libsnark/jsnark_interface/run_ppzksnark Vote.arith Vote.in {mode}

mode is defined as 3 parts

setup, run, verify

making circuit's CRS and proofs are described at CRV/libsnark/libsnark/zk_proof_systems/ppzksnark/voting/run_r1cs_gg_ppzksnark.tcc

using libsnark as library is described at CRV/libsnark/libsnark/jsnark_interface/run_ppzksnark.cpp
 and CRV/JsnarkCircuitBuilder/src/circuit/structure/CircuitGenerator.java

shparkk95@kookmin.ac.kr
