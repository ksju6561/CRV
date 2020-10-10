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
import examples.gadgets.hash.SubsetSumHashGadget;

public class MerkleTreeMembershipCircuitGenerator extends CircuitGenerator {

	private Wire[] publicRootWires;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;
	private Wire[] leafWires;
	private int leafNumOfWords = 8;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION; // 3

	private MerkleTreePathGadget merkleTreeGadget;
	
	public MerkleTreeMembershipCircuitGenerator(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

	@Override
	protected void buildCircuit() {
		
		/** declare inputs **/
		
		publicRootWires = createInputWireArray(hashDigestDimension, "Input Merkle Tree Root");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");
		directionSelector = createProverWitnessWire("Direction selector");
		leafWires = createProverWitnessWireArray(leafNumOfWords, "Secret Leaf");

		/** connect gadget **/
		Wire[] leafBits = new WireArray(leafWires).getBits(leafWordBitWidth).asArray();
		SubsetSumHashGadget subsetSumGadget = new SubsetSumHashGadget(leafBits, false);

		merkleTreeGadget = new MerkleTreePathGadget(
				directionSelector, leafWires, intermediateHasheWires, leafWordBitWidth, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();
		
		/** Now compare the actual root with the public known root **/
		Wire errorAccumulator = getZeroWire();
		for(int i = 0; i < hashDigestDimension; i++){
			Wire diff = actualRoot[i].sub(publicRootWires[i]);
			Wire check = diff.checkNonZero();
			errorAccumulator = errorAccumulator.add(check);
		}
		
		//makeOutputArray(leafBits, "leafBits");
		makeOutputArray(actualRoot, "Computed Root");
		//Wire[] currentHash = subsetSumGadget.getOutputWires();
		//makeOutputArray(currentHash, "Computed currentHash");
		
		/** Expected mismatch here if the sample input below is tried**/
		makeOutput(errorAccumulator.checkNonZero(), "Error if NON-zero");
		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		
		// for (int i = 0; i < hashDigestDimension; i++) {
		// 	circuitEvaluator.setWireValue(publicRootWires[i], Util.nextRandomBigInteger(Config.FIELD_PRIME));
		// }
		circuitEvaluator.setWireValue(publicRootWires[0],
				new BigInteger("12156962947096182454789923497482002572529241157301159238172320534491947938517"));
		circuitEvaluator.setWireValue(publicRootWires[1],
				new BigInteger("20805487431217577854175064082384054357364737375968095549046035423564393655765"));
		circuitEvaluator.setWireValue(publicRootWires[2],
				new BigInteger("8579986702316826360756597853153530881577562890732563292790542280098130013295"));
		// circuitEvaluator.setWireValue(publicRootWires[0],
		// 		new BigInteger("12156962947096182454789923497482002572529241157301159238172320534491947938517"));
		// circuitEvaluator.setWireValue(publicRootWires[1],
		// 		new BigInteger("20805487431217577854175064082384054357364737375968095549046035423564393655765"));
		// circuitEvaluator.setWireValue(publicRootWires[2],
		// 		new BigInteger("8579986702316826360756597853153530881577562890732563292790542280098130013295"));
		
		//circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(treeHeight));
		circuitEvaluator.setWireValue(directionSelector, 3);


		System.out.println("directionSelector :: "+circuitEvaluator.getWireValue(directionSelector));

		for (int i = 0; i < treeHeight; i++) {
			// circuitEvaluator.setWireValue(intermediateHasheWires[i*hashDigestDimension + 0]
			// ,  new BigInteger("8291615950715148130081410724340840491017712756385802150074100103599913038077"));
			// circuitEvaluator.setWireValue(intermediateHasheWires[i*hashDigestDimension + 1]
			// ,  new BigInteger("17257136803525649181800536345422766362159877772771502811077648905405576742167"));
			// circuitEvaluator.setWireValue(intermediateHasheWires[i*hashDigestDimension + 2]
			// ,  new BigInteger("8747563664428558372108288299016749546752962818047029297934391465902565770437"));

			//circuitEvaluator.setWireValue(intermediateHasheWires[i],  Util.nextRandomBigInteger(Config.FIELD_PRIME));
		}
		circuitEvaluator.setWireValue(intermediateHasheWires[0*hashDigestDimension + 0]
		,  new BigInteger("8291615950715148130081410724340840491017712756385802150074100103599913038077"));
		circuitEvaluator.setWireValue(intermediateHasheWires[0*hashDigestDimension + 1]
		,  new BigInteger("17257136803525649181800536345422766362159877772771502811077648905405576742167"));
		circuitEvaluator.setWireValue(intermediateHasheWires[0*hashDigestDimension + 2]
		,  new BigInteger("8747563664428558372108288299016749546752962818047029297934391465902565770437"));
		
		circuitEvaluator.setWireValue(intermediateHasheWires[1*hashDigestDimension + 0]
		,  new BigInteger("6394284389161786975797509383123073898215098799291130303222787132280280295946"));
		circuitEvaluator.setWireValue(intermediateHasheWires[1*hashDigestDimension + 1]
		,  new BigInteger("3136204337377408285378588085428681052560816676522132516217481732801991135168"));
		circuitEvaluator.setWireValue(intermediateHasheWires[1*hashDigestDimension + 2]
		,  new BigInteger("18545657745153670075916532978607579120220741634028878387353118176504478132296"));

		// circuitEvaluator.setWireValue(intermediateHasheWires[2*hashDigestDimension + 0]
		// ,  new BigInteger("11213165461295535814868066358101824938055546008860478530144672181295665454153"));
		// circuitEvaluator.setWireValue(intermediateHasheWires[2*hashDigestDimension + 1]
		// ,  new BigInteger("710973416613642466104394309345275856767586680469837273131454900225443706425"));
		// circuitEvaluator.setWireValue(intermediateHasheWires[2*hashDigestDimension + 2]
		// ,  new BigInteger("12014274187746569005195424171775154286635003369919429242356369376086383583581"));
		
		for(int i = 0; i < leafNumOfWords; i++){
			circuitEvaluator.setWireValue(leafWires[i], 2);
			System.out.println("leafWires :: "+circuitEvaluator.getWireValue(leafWires[i]));
			//System.out.println("Integer.MAX_VALUE :: "+Integer.MAX_VALUE);
		}
		// for (int i = 0; i < hashDigestDimension; i++) {
		// 	circuitEvaluator.setWireValue(publicRootWires[i], Util.nextRandomBigInteger(Config.FIELD_PRIME));
		// }
		// //circuitEvaluator.setWireValue(publicRootWires[hashDigestDimension-1], 0);
		
		// circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(treeHeight));
		// for (int i = 0; i < hashDigestDimension*treeHeight; i++) {
		// 	circuitEvaluator.setWireValue(intermediateHasheWires[i],  Util.nextRandomBigInteger(Config.FIELD_PRIME));
		// }
		
		// //circuitEvaluator.setWireValue(leafWires[0], 1);
		// for(int i = 0; i < leafNumOfWords/2; i++){
		// 	circuitEvaluator.setWireValue(leafWires[i], 1);
		// }
		// for(int i = leafNumOfWords/2; i < leafNumOfWords; i++){
		// 	circuitEvaluator.setWireValue(leafWires[i], Integer.MAX_VALUE);
		// }
		
	}
	
	
	public static void main(String[] args) throws Exception {
		
		MerkleTreeMembershipCircuitGenerator generator = new MerkleTreeMembershipCircuitGenerator("tree_32", 2);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}

	
}
