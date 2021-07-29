/*******************************************************************************
 * Author: Jaekyoung Choi <cjk2889@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupOperationGadget;
import examples.gadgets.hash.MerkleTreePathGadget_MiMC7;
import examples.gadgets.hash.MiMC7Gadget;

public class Vote extends CircuitGenerator {
	/********************* INPUT ***************************/
	private Wire Gx, Gy;
	private Wire Ux, Uy;
	private Wire Vx_in, Wx_in;
	private Wire Vy_in, Wy_in;
	private Wire E_id;
	private Wire root_in;
	private Wire sn_in, pk_in;
	/********************* OUTPUT ***************************/
	Wire root_out;
	/********************* Witness ***************************/
	private Wire Sx, Sy;
	private Wire Tx, Ty;
	private Wire sk_id;

	private Wire msg; 
	
	/********************* Vote Msg and random ***************************/
	private Wire randomizedEnc;
	//private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;

	/********************* MerkleTree ***************************/
	private Wire directionSelector;
	private Wire[] intermediateHasheWires;
	private int treeHeight;
	private int numofelector, msgsize;

	public static final int EXPONENT_BITWIDTH = 254; // in bits
	public Vote(String circuitName, int treeHeight, int numofelector) {
		super(circuitName);
		this.treeHeight = treeHeight;
		this.numofelector = numofelector;
		this.msgsize = (int)( Math.log(numofelector) / Math.log(2) );
	}

	@Override
	protected void buildCircuit() {	
		Gx = createInputWire("Gx");	Gy = createInputWire("Gy");
		Ux = createInputWire("Ux");	Uy = createInputWire("Uy");
		Vx_in = createInputWire("Vx_in");	Vy_in = createInputWire("Vy_in");
		Wx_in = createInputWire("Wx_in");	Wy_in = createInputWire("Wy_in");
		E_id = createInputWire("e");
		pk_in = createInputWire("pk_in");
		sn_in = createInputWire("sn_in");
		root_in = createInputWire("root_in");
		////////////////////////////////////////////////////////////////////////////////////

		sk_id = createProverWitnessWire("sk_id");
		Sx = createProverWitnessWire("Sx");Sy = createProverWitnessWire("Sy");
		Tx = createProverWitnessWire("Tx");Ty = createProverWitnessWire("Ty");
		randomizedEnc = createProverWitnessWire("rand");
		msg = createProverWitnessWire("msg");

		directionSelector = createProverWitnessWire("Direction selector");
		intermediateHasheWires = createProverWitnessWireArray(treeHeight, "Intermediate Hashes");

		MiMC7Gadget sn_hash = new MiMC7Gadget(new Wire[] {Sx, Tx, sk_id, E_id});
		Wire sn_out = sn_hash.getOutputWires()[0];

		ECGroupOperationGadget encV = new ECGroupOperationGadget(Gx, Gy, randomizedEnc, Sx, Sy, msg); //하나에 120ms 정도
		ECGroupOperationGadget encW = new ECGroupOperationGadget(Ux, Uy, randomizedEnc, Tx, Ty, msg);

		MiMC7Gadget pk_hash = new MiMC7Gadget(new Wire[] {sk_id});
		Wire pk_out = pk_hash.getOutputWires()[0];
		
		Wire[] V_out = encV.getOutputWires();
		Wire[] W_out = encW.getOutputWires();
		Wire[] ekpk = {Sx, Tx, pk_out};
		MerkleTreePathGadget_MiMC7 merkleTreeGadget = new MerkleTreePathGadget_MiMC7(directionSelector, ekpk, intermediateHasheWires, treeHeight);
		root_out = merkleTreeGadget.getOutputWires()[0];
		//makeOutputArray(root, "Root");

		addEqualityAssertion(pk_out, pk_in);
		addEqualityAssertion(sn_out, sn_in);
		addEqualityAssertion(V_out[0], Vx_in);
		addEqualityAssertion(V_out[1], Vy_in);
		addEqualityAssertion(W_out[0], Wx_in);
		addEqualityAssertion(W_out[1], Wy_in);
		addEqualityAssertion(root_out, root_in);
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(Gx, new BigInteger("16fd271ae0ad87ddae03044ac6852ee1d2ac024d42cff099c50ea7510d2a70a5",16));
		circuitEvaluator.setWireValue(Gy, new BigInteger("291d2a8217f35195cb3f45acde062e1709c7fdc7b1fe623c0a27021ae5446310",16));
		circuitEvaluator.setWireValue(Ux, new BigInteger("13641eca1827ad0acbee4f0ad1753b2f283b62a5e6f9dc68fb0bbc5af07f366b",16));
		circuitEvaluator.setWireValue(Uy, new BigInteger("deda3e84e9efac8d6b69d3ca21609770da4c62b83526be735a798b4f4668f48",16));
		circuitEvaluator.setWireValue(Vx_in, new BigInteger("9ed22a3cc039218ad431f636cfcf1b0421ca72fd5925b5119b32bdf6f06a0a8",16));
		circuitEvaluator.setWireValue(Vy_in, new BigInteger("2655f79ea87d85712fc303312d504bca37bd60d8a97e19fa3a50592851126713",16));
		circuitEvaluator.setWireValue(Wx_in, new BigInteger("1df45d7aeea36ee42a69385b0298875b339bd1f0a4026437971cd3dcf86275b6",16));
		circuitEvaluator.setWireValue(Wy_in, new BigInteger("6185cd8bd96257dd681d3f9d5c6b6e11cb2aa2e835977399290e1964a325310",16));
		circuitEvaluator.setWireValue(E_id, new BigInteger("1"));
		circuitEvaluator.setWireValue(pk_in, new BigInteger("242e5dac01ff9bc696a866fbe0cebeb2ef3b836de1f9344f3bd8da5ddcfd1899",16));
		circuitEvaluator.setWireValue(sn_in, new BigInteger("2b6b60940830f15107ebdae8664cfe792011abb7848548039ecaaaaf1a590dec",16));	
		circuitEvaluator.setWireValue(root_in, new BigInteger("279d0eb27abfabe7b2ce52d31a7e3ebb9f2a799efb2424667517a56680d3e821",16));
		
		circuitEvaluator.setWireValue(sk_id, new BigInteger("111111"));
		circuitEvaluator.setWireValue(Sx, new BigInteger("1fca64aadf8c72571e0bb07a79cf3f1d97357470e5d7dd51a3bc15f38c7c6e22",16));
		circuitEvaluator.setWireValue(Sy, new BigInteger("239aa42106195d896bcb735b4a3da49acdf6d83b475566995f26879089f844d4",16));
		circuitEvaluator.setWireValue(Tx, new BigInteger("c6b29f54614c69fa95672d61dcacc7aa06d5236df49e25a8c7a1a8e0ba92db2",16));
		circuitEvaluator.setWireValue(Ty, new BigInteger("2ff29f767782f1a68fca486bdb7ed2dd5ef60f78895df259d889c436daf19324",16));
		circuitEvaluator.setWireValue(randomizedEnc, new BigInteger("2b8da27db352ccf66c6068e708b02c1a6ec60088c6050b5bbbf574c95022944",16));
		circuitEvaluator.setWireValue(msg, new BigInteger("800000000000", 16));
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
		circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(treeHeight));		
		for (int i = 0; i < treeHeight; i++) { 
			circuitEvaluator.setWireValue(intermediateHasheWires[i], Integer.MAX_VALUE);
		}
	}

	public static void main(String[] args) throws Exception {
		Vote generator = new Vote("Vote", 16, 15); // 16 : 5 10 15
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}
