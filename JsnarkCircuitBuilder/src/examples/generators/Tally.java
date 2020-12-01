/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

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
    private Wire[] msgsum; //MAX = 2^6 * 2 ^ 16
    /* WITNESS */
    private Wire[] SK;

    private int leafNumofWords = 8;
    private int leafWordBitWidth = 32;
    private int numofvoter = 64;

    private int treeHeight;
    public static final int EXPONENT_BITWIDTH = 253; // in bits


    public Tally(String circuitName, int treeHeight) {
        super(circuitName);
        this.treeHeight = treeHeight;
    }

    public Wire[] expwire(Wire input){
		Wire zerobitWire = createConstantWire(new BigInteger("0")).getBitWires(1).get(0);
		Wire onebitWire = oneWire.getBitWires(1).get(0);
		Wire[] temp = input.getBitWires(EXPONENT_BITWIDTH-3).asArray();
		Wire[] output = new Wire[EXPONENT_BITWIDTH];
		output[0] = zeroWire;
		output[1] = zeroWire;
		output[2] = zeroWire;
		for(int i = 3 ; i < EXPONENT_BITWIDTH  ; i++)
			output[i] = temp[i-3];
		output[EXPONENT_BITWIDTH - 1] = oneWire;
		for(int i = 0 ; i < output.length ; i++){
			addBinaryAssertion(output[i], Integer.toString(i));
		}
		return output;
	}

    @Override
    protected void buildCircuit(){
        Wire oneWire = createConstantWire(new BigInteger("1"));
        G = createInputWire("G");
        U = createInputWire("U");
        V = createInputWire("V");
        W = createInputWire("W");

        msgsum = createInputWireArray(numofvoter, "candidate");
        SK = createProverWitnessWireArray(leafNumofWords, "sk");
        Wire rho = new WireArray(SK).getBits(leafWordBitWidth).packAsBits(256, "rho");
        Wire[] skbits = expwire(rho);
        for(int i = 0 ; i < numofvoter ; i++){
            Wire msg = createConstantWire(new BigInteger(Integer.toString(i)));
            
            Wire[] msgbits = expwire(msg);
            
            ECGroupOperationGadget dec = new ECGroupOperationGadget(V, skbits, G, msgbits);
            Wire m = dec.getOutputPublicValue();
            ECGroupGeneratorGadget dec2 = new ECGroupGeneratorGadget(G, skbits);
            Wire n = dec2.getOutputPublicValue();

            if(m.isEqualTo(W) == oneWire && n.isEqualTo(U) == oneWire)
                msgsum[i].add(1);
        }
    
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        circuitEvaluator.setWireValue(G, new BigInteger("16377448892084713529161739182205318095580119111576802375181616547062197291263"));
        circuitEvaluator.setWireValue(U, new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));
        circuitEvaluator.setWireValue(V, new BigInteger("16377448892084713529161739182205318095580119111576802375181616547062197291263"));
        circuitEvaluator.setWireValue(W, new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));

        for(int i = 0 ; i < numofvoter ; i++){
            circuitEvaluator.setWireValue(msgsum[i], 0);
        }

        for(int i = 0 ; i < leafNumofWords ; i++){
            circuitEvaluator.setWireValue(SK[i], Integer.MAX_VALUE);
        }
             
    }

    public static void main(String[] args) throws Exception{
        Tally tally = new Tally("tally", 16);
        tally.generateCircuit();
        tally.evalCircuit();
        tally.prepFiles();
        tally.runLibsnark();
    }

}