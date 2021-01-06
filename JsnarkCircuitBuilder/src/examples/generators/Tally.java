/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
// import java.math.*;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.ConstantWire;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SHA256Gadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupGeneratorGadget;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupOperationGadget;


public class Tally extends CircuitGenerator {
    /* INPUT */
    private Wire G;
    private Wire U;
    private Wire V;
    private Wire W;
    private Wire msgsum; //MAX = (15) * 2 ^ 16
    /* WITNESS */
    private Wire SK;

    private int leafNumofWords = 8;
    private int leafWordBitWidth = 32;
    private int numofelector;
    private int msgsize;
    private int treeHeight;
    public static final int EXPONENT_BITWIDTH = 254; // in bits


    public Tally(String circuitName, int treeHeight, int numofelector) {
        super(circuitName);
        this.treeHeight = treeHeight;
        this.numofelector = numofelector;
    }

    public Wire[] expwire(Wire input){
        Wire[] output = input.getBitWires(EXPONENT_BITWIDTH).asArray();
		return output;
	}

    
    @Override
    protected void buildCircuit(){
        G = createInputWire("G");
        U = createInputWire("U");
        V = createInputWire("V"); //vsum
        W = createInputWire("W"); //wsum
      
        msgsum = createInputWire("msgsum");
        Wire[] msumbits = msgsum.getBitWires(EXPONENT_BITWIDTH).asArray();

        SK = createProverWitnessWire("sk");
        Wire[] skbits = expwire(SK);
        ECGroupGeneratorGadget dec2 = new ECGroupGeneratorGadget(G, skbits);
        Wire check1 = dec2.getOutputPublicValue();
        makeOutput(check1, "dec2");
        addEqualityAssertion(check1, U, "check1");

        ECGroupOperationGadget dec = new ECGroupOperationGadget(G, msumbits, V, skbits);
        Wire check2 = dec.getOutputPublicValue();
         
        addEqualityAssertion(check2, W, "check2");
        
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        circuitEvaluator.setWireValue(G, new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));
        circuitEvaluator.setWireValue(U, new BigInteger("8242025496843787907786648063961487221225108903776185277615402935691149335791"));
        circuitEvaluator.setWireValue(V, new BigInteger("6716520531993944033977721086270401368654711195597428675989524982305607452325"));
        circuitEvaluator.setWireValue(W, new BigInteger("8113092186587487098704135767833663470937458770672298017328502239202175637389"));

        circuitEvaluator.setWireValue(msgsum, new BigInteger("140737488355328"));
        
        
        circuitEvaluator.setWireValue(SK, new BigInteger("20444478212271350495463602922274610020133286575545030088692111896801588915112"));
        
             
    }

    public static void main(String[] args) throws Exception{
        Tally tally = new Tally("tally", 16, 15);
        tally.generateCircuit();
        tally.evalCircuit();
        tally.prepFiles();
        tally.runLibsnark();
    }

}