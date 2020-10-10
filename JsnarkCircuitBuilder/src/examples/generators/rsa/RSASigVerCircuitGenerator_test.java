/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators.rsa;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;
import examples.gadgets.rsa.RSASigVerificationV1_5_Gadget;


//a demo for RSA Signatures PKCS #1, V1.5
public class RSASigVerCircuitGenerator_test extends CircuitGenerator {

	private int rsaKeyLength;
	private Wire[][] inputMessage = new Wire[3][3];
	private LongElement[] signature = new LongElement[3];
	private LongElement[] rsaModulus = new LongElement[3];

	private SHA256Gadget sha2Gadget;
	private RSASigVerificationV1_5_Gadget rsaSigVerificationV1_5_Gadget;

	public RSASigVerCircuitGenerator_test(String circuitName, int rsaKeyLength) {
		super(circuitName);
		this.rsaKeyLength = rsaKeyLength;
	}

	@Override
	protected void buildCircuit() {
		Wire sig_sum = createConstantWire(new BigInteger("0"));
		Wire data_ch_sum = createConstantWire(new BigInteger("0"));
		// a sample input message of 3 byte
		for(int i = 0; i < 3; i++){

			inputMessage[i] = createInputWireArray(3);
			sha2Gadget = new SHA256Gadget(inputMessage[i], 8, inputMessage[i].length,
					false, true);
			Wire[] digest = sha2Gadget.getOutputWires();

			rsaModulus[i] = createLongElementInput(rsaKeyLength);

			signature[i] = createLongElementProverWitness(rsaKeyLength);

			signature[i].forceBitwidth();
			signature[i].assertLessThan(rsaModulus[i]); 

			rsaSigVerificationV1_5_Gadget = new RSASigVerificationV1_5_Gadget(
					rsaModulus[i], digest, signature[i], rsaKeyLength);
			//makeOutput(rsaSigVerificationV1_5_Gadget.getOutputWires()[0],"Is Signature valid?");
			
			sig_sum = sig_sum.add((rsaSigVerificationV1_5_Gadget.getOutputWires()[0]).isEqualTo(1));
			Wire r0 = inputMessage[i][0].mul(100);
			Wire r1 = inputMessage[i][1].mul(10);
			Wire r2 = inputMessage[i][2].mul(1);
			Wire r3 = r0.add(r1);
			Wire r4 = r2.add(r3);
			
			Wire check = r3.isGreaterThanOrEqual(19,32);
			data_ch_sum = data_ch_sum.add(check);
			
		}
		Wire out = sig_sum.add(data_ch_sum).isEqualTo(6);
		makeOutput(out,"out!");

	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		for(int j = 0; j < inputMessage.length;j++){
			int data = 200 + j;
			String inputStr = Integer.toString(data);
			System.out.println(inputStr);
			for (int i = 0; i < 3; i++) {
				evaluator.setWireValue(inputMessage[j][i], (inputStr.charAt(i)));
			}

			try {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(rsaKeyLength, new SecureRandom());
				KeyPair keyPair = keyGen.generateKeyPair();

				Signature signature = Signature.getInstance("SHA256withRSA");
				signature.initSign(keyPair.getPrivate());

				byte[] message = inputStr.getBytes();
				signature.update(message);

				byte[] sigBytes = signature.sign();
				byte[] signaturePadded = new byte[sigBytes.length + 1];
				System.arraycopy(sigBytes, 0, signaturePadded, 1, sigBytes.length);
				signaturePadded[0] = 0;
				BigInteger modulus = ((RSAPublicKey) keyPair.getPublic())
						.getModulus();
				System.out.println(modulus.toString(16));
				BigInteger sig = new BigInteger(signaturePadded);
				System.out.println("****************** Hello RSA SIG");

				// if (!minimizeVerificationKey) {
				evaluator.setWireValue(this.rsaModulus[j], modulus,
						LongElement.BITWIDTH_PER_CHUNK);
				evaluator.setWireValue(this.signature[j], sig,
						LongElement.BITWIDTH_PER_CHUNK);
				// } else {
				// evaluator.setWireValue(this.rsaModulusWires,
				// Util.split(modulus, Config.LOG2_FIELD_PRIME - 1));
				// evaluator.setWireValue(this.signatureWires,
				// Util.split(sig, Config.LOG2_FIELD_PRIME - 1));
				// }
			} catch (Exception e) {
				System.err
						.println("Error while generating sample input for circuit");
				e.printStackTrace();
			}
		
		}

	}

	public static void main(String[] args) throws Exception {
		int keyLength = 2048;
		RSASigVerCircuitGenerator_test generator = new RSASigVerCircuitGenerator_test(
				"rsa" + keyLength + "_sha256_sig_verify", keyLength);
		System.out.println("Hello RSASigVerCircuitGenerator!");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
