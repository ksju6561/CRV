/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.util.Random;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;


public class Vote extends CircuitGenerator {

	public static int mode = 0;
	/********************* INPUT ***************************/
	private Wire[][] pp;
	private Wire[] E_id;
	/********************* OUTPUT ***************************/
	private Wire[] root;
	private Wire[] sn;
	private Wire[][] VCT;
	/********************* Witness ***************************/
	private Wire[] SK_id;
	private Wire[][] EK_id;
	private Wire candidate;

	/********************* Vote Msg and random ***************************/
	private Wire randomizedEnc;
	
	/********************* MerkleTree ***************************/
	private Wire directionSelector;
	private Wire[] intermediateHasheWires;

	private int num_of_elector = 64; // 2^6
	private int leafNumOfWords = 8;
	private int list_size = 1024;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;
	private SubsetSumHashGadget subsetSumHashGadget;
	private MerkleTreePathGadget merkleTreeGadget;

	public Vote(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
		this.num_of_elector = 64;
		this.leafNumOfWords = 8;
		this.leafWordBitWidth = 32;

	}

	public Wire power(Wire input, Wire exp) {
		Wire zeroWire = createConstantWire(new BigInteger("0"));
		Wire oneWire = createConstantWire(new BigInteger("1"));
		Wire res = createConstantWire(new BigInteger("1"));
		int index = 0;

		Wire[] getBitExp = exp.getBitWires(256).asArray();
		for (int i = 0; i < 256; i++) {
			Wire tmp = input.sub(1);
			tmp = tmp.mul(getBitExp[i]);
			tmp = tmp.add(1);

			res = res.mul(tmp);

			exp = exp.shiftRight(1, 256);
			input = input.mul(input);
		}
		return res;
	}

	@Override
	protected void buildCircuit() {      
		/* output */
		// root = new Wire[2][];
		// sn = new Wire[3][]; 
		VCT = new Wire[2][8];
		pp = new Wire[2][];
		EK_id = new Wire[2][];

		/* Witness */
		E_id = createInputWireArray(leafNumOfWords, "e_id"); // 투표 번호
		for(int i = 0 ; i < 2 ; i++)
		{
			pp[i] = createInputWireArray(leafNumOfWords, "pp" + Integer.toString(i));
			EK_id[i] = createProverWitnessWireArray(leafNumOfWords, "ek_id" + Integer.toString(i)); // S = G ^ s , T = (S ^ rho) * (G ^ real)		
		}
		directionSelector = createProverWitnessWire("Direction selector");
		candidate = createProverWitnessWire("candidate"); // 후보자
		SK_id = createProverWitnessWireArray(leafNumOfWords, "sk_id"); // voter private key
		randomizedEnc = createProverWitnessWire("r");
		
		Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();
		// System.out.println("ww : " + skBits.length);
        subsetSumHashGadget = new SubsetSumHashGadget(skBits, false);
		Wire[] PK_id = subsetSumHashGadget.getOutputWires();
		// makeOutputArray(PK_id, "PK_id");

		Wire[] sn_input = Util.concat(Util.concat(Util.concat(E_id, SK_id), EK_id[0]),EK_id[1]); //sn = H(E_ID||SK_ID||EK_ID)
		//32 * 8 + 32 * 8 + 32 * 8 + 32 * 8

		Wire[] snBits = new WireArray(sn_input).getBits(leafWordBitWidth).asArray();
		// System.out.println("WW:"+snBits.length);
		subsetSumHashGadget = new SubsetSumHashGadget(snBits, false);
		sn = subsetSumHashGadget.getOutputWires();
		makeOutputArray(sn, "sn");

		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");

		Wire[] ek = Util.concat(EK_id[0],EK_id[1]);
		// 32 * 8 + 32 * 8 +  32 * 3
		Wire[] ekbits = new WireArray(ek).getBits(leafWordBitWidth).asArray();
		subsetSumHashGadget = new SubsetSumHashGadget(ekbits, false);
		Wire[] hashek = subsetSumHashGadget.getOutputWires();
		Wire[] ekpk = Util.concat(hashek, PK_id);
		// System.out.println("WW:"+ekpkBits.length);
		merkleTreeGadget = new MerkleTreePathGadget(directionSelector, ekpk, intermediateHasheWires, 254, treeHeight);
		root = merkleTreeGadget.getOutputWires();
		makeOutputArray(root, "Root");

		// merkleTreeGadget = new MerkleTreePathGadget(directionSelector, PK_id, intermediateHasheWires, leafWordBitWidth, treeHeight);
		// root[1] = merkleTreeGadget.getOutputWires();
		// makeOutputArray(root[1], "Root[1]");

		for(int i = 0 ; i < leafNumOfWords ; i++){
			VCT[0][i] = (power(pp[0][i], randomizedEnc)).mul(power(EK_id[0][i], candidate));
			VCT[1][i] = (power(EK_id[1][i], candidate)).mul(power(pp[1][i], randomizedEnc));
		}

		makeOutputArray(VCT[0], "vct[0]");
		makeOutputArray(VCT[1], "vct[1]");

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		for(int i = 0 ; i < 2 ; i++){
			for(int j = 0 ; j < leafNumOfWords ; j++){
				circuitEvaluator.setWireValue(pp[i][j], Integer.MAX_VALUE);
				circuitEvaluator.setWireValue(EK_id[i][j], Integer.MAX_VALUE);
			}
		}
		for(int i = 0 ; i < leafNumOfWords ; i++){
			circuitEvaluator.setWireValue(E_id[i], Integer.MAX_VALUE);
			circuitEvaluator.setWireValue(SK_id[i], Integer.MAX_VALUE);
		}
		circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(treeHeight));
		circuitEvaluator.setWireValue(candidate, Integer.MAX_VALUE);
		circuitEvaluator.setWireValue(randomizedEnc, 1);
		for (int i = 0; i < hashDigestDimension * treeHeight; i++) { 
			circuitEvaluator.setWireValue(intermediateHasheWires[i], Integer.MAX_VALUE);
		}
	}

	public void setup()
    {
        this.generateCircuit();
        this.evalCircuit();
        this.prepFiles();
        this.runLibsnark();
    }

	public static void main(String[] args) throws Exception {
		Vote generator = new Vote("vote", 16);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();

	}

}
