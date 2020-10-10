/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.io.ByteArrayOutputStream;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import util.Util;
import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;

import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.hash.SHA256Gadget;
import examples.gadgets.rsa.RSASigVerificationV1_5_Gadget;

public class CoercionVote_vote extends CircuitGenerator {

	private Wire[] inputs;
	
	private Wire[] pk_e;
	private Wire[] pp;

	private Wire[] ek_id;
	private Wire[] sk_id;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;

	private LongElement rsaModulus;
	private LongElement signature;

	private Wire randomizedEnc;
	
	private int rsaKeyLength = 2048;
	private int num_of_elector = 4;
	private int leafNumOfWords = 8;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;
	
	private MerkleTreePathGadget merkleTreeGadget;
	private RSASigVerificationV1_5_Gadget rsaSigVerificationV1_5_Gadget;
	private SHA256Gadget sha2Gadget;

	public CoercionVote_vote(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

    public Wire power(Wire input, Wire exp){
		Wire zeroWire = createConstantWire(new BigInteger("0"));
		Wire oneWire = createConstantWire(new BigInteger("1"));
		Wire res = createConstantWire(new BigInteger("1"));
        int index = 0;

		Wire[] getBitExp = exp.getBitWires(256).asArray();
        for(int i = 0; i < 256; i++)
        {
			Wire tmp = input.sub(1);
			tmp = tmp.mul(getBitExp[i]);
			tmp = tmp.add(1);

            res = res.mul(tmp);
			
			exp = exp.shiftRight(1,256);
			input = input.mul(input);
		}
		return res;
	}
	
	@Override
	protected void buildCircuit() {
		pk_e = createInputWireArray(leafNumOfWords,"e");

		inputs = createProverWitnessWireArray(num_of_elector);
		ek_id = createProverWitnessWireArray(num_of_elector*2,"sk_id");
		sk_id = createProverWitnessWireArray(leafNumOfWords,"sk_id");

		directionSelector = createProverWitnessWire("Direction selector");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");

		rsaModulus = createLongElementInput(rsaKeyLength);
		signature = createLongElementProverWitness(rsaKeyLength);


		Wire[] bitwiseSK =  new WireArray(sk_id).getBits(leafWordBitWidth).asArray();
		SubsetSumHashGadget subsetSumHashGadget = new SubsetSumHashGadget(bitwiseSK, false);
		Wire[] leafWires = subsetSumHashGadget.getOutputWires();

		merkleTreeGadget = new MerkleTreePathGadget(directionSelector, leafWires, intermediateHasheWires,
				254, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();

		// Wire[] sn_input = new Wire[16];
		// for (int j = 0; j < 8; j++) {
		// 	sn_input[j] = sk_id[j];
		// }
		// for (int j = 8; j < 16; j++) {
		// 	sn_input[j] = pk_e[j-8];
		// }
		// Wire[] snBits = new WireArray(sn_input).getBits(leafWordBitWidth).asArray();
		// subsetSumHashGadget = new SubsetSumHashGadget(snBits, false);
		// Wire[] SN = subsetSumHashGadget.getOutputWires();

		Wire[] SN_input = Util.concat(sk_id,pk_e);
		Wire[] bitwiseSN = new WireArray(SN_input).getBits(leafWordBitWidth).asArray();

		Wire[] SN = subsetSumHashGadget.getOutputWires();

		pp = createInputWireArray(2 + num_of_elector,"PP");
		randomizedEnc = createProverWitnessWire("r");

		Wire[] CT = new Wire[1 + num_of_elector];
		Wire[] VCT = new Wire[2*num_of_elector];			
		CT[0] = power(pp[0],randomizedEnc);

		for(int i = 0; i < num_of_elector; i++){			
			CT[i + 1] = power(pp[i+2],randomizedEnc).mul(power(pp[1],inputs[i]));
			VCT[i] = power(ek_id[i],randomizedEnc.add(inputs[i]));
			VCT[num_of_elector + i] = power(ek_id[num_of_elector + i],randomizedEnc.add(inputs[i]));
		}

		// Wire R_sig = power(vk_sig[0],sig[1]);
		// R_sig = R_sig.mul(power(vk_sig[1],sig[0]));
		// Wire[] sigMConcat = Util.concat(R_sig,ek_id);
		// makeOutputArray(sigMConcat, "test");
		//sha2Gadget = new SHA256Gadget(sigMConcat,8, 1, false, true);
		
		sha2Gadget = new SHA256Gadget(ek_id, 256, 32*ek_id.length, false, true);
		Wire[] digest = sha2Gadget.getOutputWires();
		makeOutputArray(digest,"hash");

		rsaModulus = createLongElementInput(rsaKeyLength);

		signature = createLongElementProverWitness(rsaKeyLength);
		signature.forceBitwidth();
		signature.assertLessThan(rsaModulus); // not really necessary in that
												// case

		rsaSigVerificationV1_5_Gadget = new RSASigVerificationV1_5_Gadget(rsaModulus, digest, signature, rsaKeyLength);
		makeOutput(rsaSigVerificationV1_5_Gadget.getOutputWires()[0], "Is Signature valid?");

		makeOutputArray(SN,"SN");
		makeOutputArray(actualRoot, "Computed Root");
		makeOutputArray(CT,"CT");
		makeOutputArray(VCT,"VCT");

		//debug
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(inputs[0], 1);
		for(int i = 1; i < num_of_elector; i++){
			circuitEvaluator.setWireValue(inputs[i], 0);
			circuitEvaluator.setWireValue(pp[2+i], Util.nextRandomBigInteger(256));
		}
		
		for (int i = 0; i < leafNumOfWords; i++) {
			circuitEvaluator.setWireValue(pk_e[i], Integer.MAX_VALUE);
			circuitEvaluator.setWireValue(sk_id[i], Integer.MAX_VALUE);
		}
		circuitEvaluator.setWireValue(directionSelector, 15);
		for (int i = 0; i < hashDigestDimension*treeHeight; i++) {
			circuitEvaluator.setWireValue(intermediateHasheWires[i],  i);
		}
		
		circuitEvaluator.setWireValue(pp[0], Util.nextRandomBigInteger(256));
		circuitEvaluator.setWireValue(pp[1], Util.nextRandomBigInteger(256));
		circuitEvaluator.setWireValue(pp[2], Util.nextRandomBigInteger(256));

		BigInteger[] ekBigIntegers = new BigInteger[2 * num_of_elector];
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		try {
			for (int i = 0; i < 2 * num_of_elector; i++) {
				ekBigIntegers[i] = Util.nextRandomBigInteger(256);
				output.write(ekBigIntegers[i].toByteArray());
				circuitEvaluator.setWireValue(ek_id[i], ekBigIntegers[i]);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		circuitEvaluator.setWireValue(randomizedEnc, Util.nextRandomBigInteger(256));

		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(rsaKeyLength, new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();

			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(keyPair.getPrivate());

			byte[] message = output.toByteArray();
			signature.update(message);

			byte[] sigBytes = signature.sign();
			byte[] signaturePadded = new byte[sigBytes.length + 1];
			System.arraycopy(sigBytes, 0, signaturePadded, 1, sigBytes.length);
			signaturePadded[0] = 0;
			BigInteger modulus = ((RSAPublicKey) keyPair.getPublic())
					.getModulus();
			System.out.println(modulus.toString(16));
			BigInteger sig = new BigInteger(signaturePadded);

			circuitEvaluator.setWireValue(rsaModulus, modulus, LongElement.BITWIDTH_PER_CHUNK);
			circuitEvaluator.setWireValue(this.signature, sig, LongElement.BITWIDTH_PER_CHUNK);
		} catch (Exception e) {
			System.err
					.println("Error while generating sample input for circuit");
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws Exception {

		CoercionVote_vote generator = new CoercionVote_vote("CoercionVote_vote",64);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
