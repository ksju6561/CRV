/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.gadgets.hash;

import java.math.BigInteger;
import java.util.Arrays;

import util.Util;
import circuit.config.Config;

public class SubsetSumHashGadgetJk {

	public static final int DIMENSION = 3; // set to 4 for higher security
	public static final int INPUT_LENGTH = 2 * DIMENSION * Config.LOG2_FIELD_PRIME; // length in bits
	private static final BigInteger[][] COEFFS;

	private BigInteger[] inputWires;
	private BigInteger[] outWires;
	private boolean binaryOutput;

	static {
		COEFFS = new BigInteger[DIMENSION][INPUT_LENGTH];
		for (int i = 0; i < DIMENSION; i++) {
			for (int k = 0; k < INPUT_LENGTH; k++) {
				COEFFS[i][k] = Util.nextRandomBigInteger(Config.FIELD_PRIME);
			}
		}
	}

	/**
	 * @param ins
	 *            The bitwires of the input.
	 * @param binaryOutput
	 *            Whether the output digest should be splitted into bits or not.
	 * @param desc
	 */
	public SubsetSumHashGadgetJk(BigInteger[] ins, boolean binaryOutput, String... desc) {

		int numBlocks = (int) Math.ceil(ins.length * 1.0 / INPUT_LENGTH);
		//System.out.println(numBlocks);

		if (numBlocks > 1) {
			throw new IllegalArgumentException("Only one block is supported at this point");
		}

		int rem = numBlocks * INPUT_LENGTH - ins.length;

		BigInteger[] pad = new BigInteger[rem];
		//System.out.println("test :: "+INPUT_LENGTH);
		for (int i = 0; i < pad.length; i++) {
			pad[i] = BigInteger.ZERO; // TODO: adjust padding
		}
		inputWires = Util.concat(ins, pad);
		this.binaryOutput = binaryOutput;
		buildCircuit();
	}

	private void buildCircuit() {

		BigInteger[] outDigest = new BigInteger[DIMENSION];
		Arrays.fill(outDigest, BigInteger.ZERO);

		for (int i = 0; i < DIMENSION; i++) {
			for (int j = 0; j < INPUT_LENGTH; j++) {
				BigInteger t = inputWires[j].multiply(COEFFS[i][j]);
				outDigest[i] = outDigest[i].add(t).mod(Config.FIELD_PRIME);
			}
		}
		if (!binaryOutput) {
			outWires = outDigest;
		} else {
			// Nothing
		}
	}

	public BigInteger[] getOutput() {
		return outWires;
	}
}
