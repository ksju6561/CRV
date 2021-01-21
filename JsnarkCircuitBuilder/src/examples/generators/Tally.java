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
import examples.gadgets.math.ModConstantGadget;


public class Tally extends CircuitGenerator {
    /* INPUT */
    private Wire G;
    private Wire U;
    private Wire V;
    private Wire W;
    private Wire msgsum; //MAX = (15) * 2 ^ 16
    /* WITNESS */
    private Wire SK;

    private int numofelector;
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
    
    private Wire mulexp(Wire a, Wire b){
		ModConstantGadget mod = new ModConstantGadget(a, b, Config.CURVE_ORDER);
		return mod.getOutputWires()[0]; 
	}

    
    @Override
    protected void buildCircuit(){
        G = createInputWire("G");
        U = createInputWire("U");
        V = createInputWire("V"); //vsum
        W = createInputWire("W"); //wsum
      
        msgsum = createInputWire("msgsum");
		Wire rand = createConstantWire(new BigInteger("123141251243"));

        SK = createProverWitnessWire("sk");
        ECGroupGeneratorGadget dec1 = new ECGroupGeneratorGadget(G, SK);
        Wire check1 = dec1.getOutputPublicValue();
        // makeOutput(check1, "dec1");
        addEqualityAssertion(check1, U, "check1");

        ECGroupOperationGadget dec = new ECGroupOperationGadget(V, SK, G, mulexp(rand, msgsum));
        Wire check2 = dec.getOutputPublicValue();
         
        addEqualityAssertion(check2, W, "check2");
        
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        circuitEvaluator.setWireValue(G, new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));
        circuitEvaluator.setWireValue(U, new BigInteger("8770841330403347030926649719068993689202161186696114159318225920256745879147"));
        circuitEvaluator.setWireValue(V, new BigInteger("18437695250178433367117794068340095227102603266608906145263062046682943112561"));
        circuitEvaluator.setWireValue(W, new BigInteger("18846636015165217144662772718052395666868227456945327617274249870237629825709"));

        circuitEvaluator.setWireValue(msgsum, new BigInteger("2147483648"));
        
        
        circuitEvaluator.setWireValue(SK, new BigInteger("204444782122713504954636029222746100201332865755450300886921118968015889151"));
        
             
    }

    public static void main(String[] args) throws Exception{
        Tally tally = new Tally("tally", 16, 15);
        tally.generateCircuit();
        tally.evalCircuit();
        tally.prepFiles();
        tally.runLibsnark();
    }

}