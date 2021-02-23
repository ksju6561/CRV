/*******************************************************************************
 * Author: Jaekyoung Choi <cjk2889@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.util.Arrays;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.ConstantWire;
import circuit.structure.BitWire;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import circuit.config.Config;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupGeneratorGadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupOperationGadget;


public class Vote_backup extends CircuitGenerator {
	/********************* INPUT ***************************/
	private Wire G;
	private Wire U;
	private Wire[] E_id;
	/********************* OUTPUT ***************************/
	private Wire[] root;
	private Wire[] sn;
	private Wire[][] VCT;
	/********************* Witness ***************************/
	private Wire[] SK_id;
	private Wire[] EK_id;

	private Wire[] candidate;
	private Wire Rho; 
	


	/********************* Vote Msg and random ***************************/
	private Wire randomizedEnc;
	
	/********************* MerkleTree ***************************/
	private Wire directionSelector;
	private Wire[] intermediateHasheWires;

	private int numofelector; // 2^6
	private int msgsize;
	private int leafNumOfWords = 8;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;
	

	public static final int EXPONENT_BITWIDTH = 254; // in bits

	public Vote_backup(String circuitName, int treeHeight, int numofelector) {
		super(circuitName);
		this.treeHeight = treeHeight;
		this.numofelector = numofelector;
		this.msgsize = (int)( Math.log(numofelector) / Math.log(2) );
	}


	@Override
	protected void buildCircuit() {	

		E_id = createInputWireArray(leafNumOfWords, "E_id");
		EK_id = createProverWitnessWireArray(2, "ek_id");
		G = createInputWire("G");
		U = createInputWire("U");
		
		directionSelector = createProverWitnessWire("Direction selector");
		candidate = createProverWitnessWireArray(EXPONENT_BITWIDTH, "candidate"); // 후보자
		SK_id = createProverWitnessWireArray(leafNumOfWords, "sk_id"); // voter private key
		randomizedEnc = createProverWitnessWire("r");

	
		Wire msg = new WireArray(candidate).packAsBits(EXPONENT_BITWIDTH);
		makeOutput(msg, "msg");

		Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();

		SubsetSumHashGadget hash = new SubsetSumHashGadget(skBits, false);
		Wire[] PK_id = hash.getOutputWires();
		Wire[] S = Util.split(EK_id[0], 256, 8, 32);
		Wire[] T = Util.split(EK_id[1], 256, 8, 32);;
		Wire[] ek = Util.concat(S, T);

		//비트수 맞출것
		Wire[] sn_input = Util.concat(Util.concat(E_id, SK_id), ek); //sn = H(E_ID||SK_ID||EK_ID)
		System.out.println(sn_input.length);
		//32 * 8 + 32 * 8 + 32 * 8 + 32 * 8

		Wire[] snBits = new WireArray(sn_input).getBits(leafWordBitWidth).asArray();
		hash = new SubsetSumHashGadget(snBits, false);
		sn = hash.getOutputWires();
		makeOutputArray(sn, "sn");
		
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");
		
		// 32 * 8 + 32 * 8 +  32 * 3
		Wire[] ekbits = new WireArray(ek).getBits(leafWordBitWidth).asArray();
		hash = new SubsetSumHashGadget(ekbits, false);
		Wire[] hashek = hash.getOutputWires();
		Wire[] ekpk = Util.concat(hashek, PK_id);
		// System.out.println("WW:"+ekpk.length);
		MerkleTreePathGadget merkleTreeGadget = new MerkleTreePathGadget(directionSelector, ekpk, intermediateHasheWires, 254, treeHeight);
		root = merkleTreeGadget.getOutputWires();
		makeOutputArray(root, "Root");
		//  2^8  
		
		ECGroupGeneratorGadget Gr = new ECGroupGeneratorGadget(G, randomizedEnc);
		Wire gr = Gr.getOutputPublicValue();
		makeOutput(gr, "gr");

		long beforeTime = System.currentTimeMillis();
		
		ECGroupOperationGadget encV = new ECGroupOperationGadget(G, randomizedEnc, EK_id[0], msg); //하나에 120ms 정도
		Wire V = encV.getOutputPublicValue();
		ECGroupOperationGadget encW = new ECGroupOperationGadget(U, randomizedEnc, EK_id[1], msg);
		Wire W = encW.getOutputPublicValue();

		long afterTime = System.currentTimeMillis(); 
		long secDiffTime = (afterTime - beforeTime);
		System.out.println("시간차이(m) : "+secDiffTime); //250ms
		
		makeOutput(V, "V");
		makeOutput(W, "W");

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(G, new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));
		circuitEvaluator.setWireValue(U, new BigInteger("16661641749539121848487039119493468627472925312533453925108867068010824302961"));
		
		circuitEvaluator.setWireValue(EK_id[0], new BigInteger("10477647447175823525193414868166901406319183663425347340811680603194551866117"));
		circuitEvaluator.setWireValue(EK_id[1], new BigInteger("12666091344144327122936091045967790976610069455379602669774012682010433991521"));
		
		for(int i = 0 ; i < leafNumOfWords ; i++){
			circuitEvaluator.setWireValue(E_id[i], Integer.MAX_VALUE);
			circuitEvaluator.setWireValue(SK_id[i], Integer.MAX_VALUE);
		}

		circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(treeHeight));
		BigInteger m = Util.nextRandomBigInteger(BigInteger.valueOf(numofelector));
		System.out.println(m);
		m = new BigInteger("1");
		for(int i = 0 ; i < EXPONENT_BITWIDTH  ; i++)
			circuitEvaluator.setWireValue(candidate[i], 0);
		circuitEvaluator.setWireValue(candidate[treeHeight * (m.intValue() + 1) - 1], 1);
		circuitEvaluator.setWireValue(randomizedEnc, new BigInteger("1231231212312542673123124124879879879817259871293845798123754981237549312324"));
		for (int i = 0; i < hashDigestDimension * treeHeight; i++) { 
			circuitEvaluator.setWireValue(intermediateHasheWires[i], Integer.MAX_VALUE);
		}
		
	}

	public static void main(String[] args) throws Exception {

		Vote_backup generator = new Vote_backup("Vote", 16, 15); // 16 : 5 10 15
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
