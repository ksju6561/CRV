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


public class Vote extends CircuitGenerator {
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
	private Wire[][] EK_id;

	private Wire candidate;
	private Wire Rho; 
	


	/********************* Vote Msg and random ***************************/
	private Wire randomizedEnc;
	
	/********************* MerkleTree ***************************/
	private Wire directionSelector;
	private Wire[] intermediateHasheWires;

	private BigInteger numofelector; // 2^6
	private int leafNumOfWords = 8;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;
	

	public static final int EXPONENT_BITWIDTH = 253; // in bits

	public Vote(String circuitName, int treeHeight, BigInteger numofelector) {
		super(circuitName);
		this.treeHeight = treeHeight;
		this.numofelector = numofelector;
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
	protected void buildCircuit() {	
		
		EK_id = new Wire[2][];
		
		E_id = createInputWireArray(leafNumOfWords, "E_id");
		for(int i = 0 ; i < 2 ; i++){
			EK_id[i] = createProverWitnessWireArray(leafNumOfWords, "ek_id" + Integer.toString(i));
		}
		// The secret exponent is a private input by the prover
		// Rho = createProverWitnessWire("Rho");
		// Wire g = createConstantWire(new BigInteger("16377448892084713529161739182205318095580119111576802375181616547062197291263"));;
		// Wire h = createConstantWire(new BigInteger("8252578783913909531884765397785803733246236629821369091076513527284845891757"));
		G = createInputWire("G");
		U = createInputWire("U");
		
		directionSelector = createProverWitnessWire("Direction selector");
		candidate = createProverWitnessWire("candidate"); // 후보자
		SK_id = createProverWitnessWireArray(leafNumOfWords, "sk_id"); // voter private key
		randomizedEnc = createProverWitnessWire("r");

		// Wire[] rhobit = expwire(Rho);
		Wire[] rbit = expwire(randomizedEnc);
		Wire[] msgbit = expwire(candidate);
		// makeOu tputArray(rbit);
		// ECGroupGeneratorGadget exchange = new ECGroupGeneratorGadget(G, rhobit);
		// U = exchange.getOutputPublicValue();
		
		Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();
		// System.out.println("skbits : " + skBits.length);

		//2   *    32 * 8  => 256하나로

		SubsetSumHashGadget hash = new SubsetSumHashGadget(skBits, false);
		Wire[] PK_id = hash.getOutputWires();
	
		//비트수 맞출것
		Wire[] sn_input = Util.concat(Util.concat(Util.concat(E_id, SK_id), EK_id[0]),EK_id[1]); //sn = H(E_ID||SK_ID||EK_ID)
		//32 * 8 + 32 * 8 + 32 * 8 + 32 * 8

		Wire[] snBits = new WireArray(sn_input).getBits(leafWordBitWidth).asArray();
		// System.out.println("WW:"+snBits.length);
		hash = new SubsetSumHashGadget(snBits, false);
		sn = hash.getOutputWires();
		makeOutputArray(sn, "sn");
		
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");
		
		Wire[] ek = Util.concat(EK_id[0],EK_id[1]);
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
		Wire S = new WireArray(EK_id[0]).getBits(32).packAsBits(256, "S");
		Wire T = new WireArray(EK_id[1]).getBits(32).packAsBits(256, "T");
		long beforeTime = System.currentTimeMillis();
		S = createConstantWire(new BigInteger("20972856563602803936618876197870162225522597137883271266424577349524402481974"), "S");
		T = createConstantWire(new BigInteger("14570037276928935487484804278848549726735737539422483972830419685206818024981"), "T");
		
		ECGroupOperationGadget enc = new ECGroupOperationGadget(G, rbit, S, msgbit); //하나에 120ms 정도
		Wire V = enc.getOutputPublicValue();
		enc = new ECGroupOperationGadget(U, rbit, T, msgbit);
		Wire W = enc.getOutputPublicValue();
		long afterTime = System.currentTimeMillis(); 
		long secDiffTime = (afterTime - beforeTime);
		System.out.println("시간차이(m) : "+secDiffTime);
		makeOutput(V, "V");
		makeOutput(W, "W");

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(G, new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));
		circuitEvaluator.setWireValue(U, new BigInteger("9091054082811332808408882460551019864591326367199559281300795799522407870087"));
		// circuitEvaluator.setWireValue(Rho, Util.nextRandomBigInteger(250));
		for(int i = 0 ; i < 2 ; i++){
			for(int j = 0 ; j < leafNumOfWords ; j++){
				circuitEvaluator.setWireValue(EK_id[i][j], Integer.MAX_VALUE);
			}
		}
		for(int i = 0 ; i < leafNumOfWords ; i++){
			circuitEvaluator.setWireValue(E_id[i], Integer.MAX_VALUE);
			circuitEvaluator.setWireValue(SK_id[i], Integer.MAX_VALUE);
		}

		circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(treeHeight));
		BigInteger size = Util.nextRandomBigInteger(numofelector);
		System.out.println(size);
		circuitEvaluator.setWireValue(candidate, size);
		circuitEvaluator.setWireValue(randomizedEnc, 1);
		for (int i = 0; i < hashDigestDimension * treeHeight; i++) { 
			circuitEvaluator.setWireValue(intermediateHasheWires[i], Integer.MAX_VALUE);
		}
		
	}

	public static void main(String[] args) throws Exception {

		Vote generator = new Vote("Vote", 32, BigInteger.valueOf(64));
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
