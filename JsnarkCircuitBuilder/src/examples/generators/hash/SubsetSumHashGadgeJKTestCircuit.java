/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators.hash;

import util.Util;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SHA2;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.myMath;

public class SubsetSumHashGadgeJKTestCircuit extends CircuitGenerator {

	private Wire[] input;
	private Wire[] input2;
	
	public SubsetSumHashGadgeJKTestCircuit(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
        input = createInputWireArray(6);
        input2 = createInputWireArray(6*Config.LOG2_FIELD_PRIME);

        
        Wire[] nextInputBits = new WireArray(input).getBits(Config.LOG2_FIELD_PRIME).asArray();
		SubsetSumHashGadget subsetSumGadget = new SubsetSumHashGadget(nextInputBits, false);
        Wire[] currentHash = subsetSumGadget.getOutputWires();
        makeOutputArray(currentHash,"test");
        subsetSumGadget = new SubsetSumHashGadget(input2, false);
        currentHash = subsetSumGadget.getOutputWires();
        makeOutputArray(currentHash);
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        for(int i = 0; i < 3; i++){
            circuitEvaluator.setWireValue(input[i],1);
        }
        for(int i = 3; i < 6; i++){
            circuitEvaluator.setWireValue(input[i],2);
        }
        BigInteger[] hash = new BigInteger[6];
        for(int i = 0; i < 3; i++){
            hash[i] = new BigInteger("1");
        }
        for(int i = 3; i < 6; i++){
            hash[i] = new BigInteger("2");
        }
        BigInteger[] gadget = myMath.getBitArray(hash, Config.LOG2_FIELD_PRIME);
        
        for(int i = 0; i < 6*Config.LOG2_FIELD_PRIME; i++){
            circuitEvaluator.setWireValue(input2[i],gadget[i]);
        }
	}
	
	
	public static void main(String[] args) throws Exception {
		
		SubsetSumHashGadgeJKTestCircuit generator = new SubsetSumHashGadgeJKTestCircuit("test_JK");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}

	
}
