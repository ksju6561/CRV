/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.hash.SHA256Gadget;

public class SimpleCircuitGenerator_vote extends CircuitGenerator {


	/********************* INPUT ***************************/
	// input_s
	// pk_e
	// leafWires
	/********************* OUTPUT ***************************/
	// PK_ID
	// sn
	// rt
	/********************* Witness ***************************/
	// SK_id
	// intermediateHasheWires
	// directionSelector

	/********************* Vote Msg and random ***************************/
	private Wire[] input_s;

	private Wire[] pk_e;
	private Wire[] SK_id;

	/********************* MerkleTree ***************************/
	//private Wire[] publicRootWires;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;

	private int num_of_elector = 8;
	private int leafNumOfWords = 8;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;

	private MerkleTreePathGadget merkleTreeGadget;
	private SHA256Gadget sha2Gadget;

	public SimpleCircuitGenerator_vote(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

	@Override
	protected void buildCircuit() {
		input_s = createInputWireArray(num_of_elector);
		pk_e = createInputWireArray(leafWordBitWidth,"e");

		SK_id = createProverWitnessWireArray(leafWordBitWidth,"sk_id");
		sha2Gadget = new SHA256Gadget(SK_id, 8, 32, false, true);
		Wire[] leafWires = sha2Gadget.getOutputWires();
		
		directionSelector = createProverWitnessWire("Direction selector");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");

		merkleTreeGadget = new MerkleTreePathGadget(directionSelector, leafWires, intermediateHasheWires,
				leafWordBitWidth, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();

		Wire[] sn_input = new Wire[64];
		for (int j = 0; j < 32; j++) {
			sn_input[j] = SK_id[j];
		}
		for (int j = 32; j < 64; j++) {
			sn_input[j] = pk_e[j-32];
		}
		sha2Gadget = new SHA256Gadget(sn_input, 8, 64, false, false);
		Wire out = sha2Gadget.getOutputWiresNoArray();
		makeOutput(out, "sn");

		for(int i = 0; i < actualRoot.length; i++){
			actualRoot[i] = actualRoot[i];
		}

		makeOutputArray(actualRoot, "Computed Root");

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		int i = 0;
		for(i = 0; i < num_of_elector; i ++){
			circuitEvaluator.setWireValue(input_s[i], 0);
		}
		for (i = 0; i < leafWordBitWidth; i++) {
			circuitEvaluator.setWireValue(SK_id[i], 's');
			circuitEvaluator.setWireValue(pk_e[i], 'e');
		}
		circuitEvaluator.setWireValue(directionSelector, 15);
		for (i = 0; i < hashDigestDimension*treeHeight; i++) {
			circuitEvaluator.setWireValue(intermediateHasheWires[i],  i);
		}

		BigInteger PK_id = new BigInteger("3400938187056921201282109642532765669466845577856422331743494419055828710937");
		
	}

	public static void main(String[] args) throws Exception {

		SimpleCircuitGenerator_vote generator = new SimpleCircuitGenerator_vote("voting",16);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		System.out.println("Hello Run Libsnark");
		generator.runLibsnark();
	}

}
