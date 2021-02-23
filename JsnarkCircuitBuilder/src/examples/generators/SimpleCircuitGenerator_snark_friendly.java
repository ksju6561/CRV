/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

public class SimpleCircuitGenerator_snark_friendly extends CircuitGenerator {

	private Wire[] inputs;
	private Wire[] input_s;

	public SimpleCircuitGenerator_snark_friendly(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		input_s = createInputWireArray(195);
		Wire r1 = createConstantWire(new BigInteger("0"));
		System.out.println("test :: "+r1);
		r1 = input_s[0].isEqualTo(input_s[1]);
		for(int i = 1; i < 195; i += 2){
			r1 = r1.add(input_s[0].isEqualTo(input_s[i]),"r1 :: #" + i);
		}

		//Wire out = r1.isEqualTo(98);
		//makeOutput(out);

		// // declare input array of length 4.
		// inputs = createInputWireArray(4);

		// // r1 = in0 * in1
		// Wire r1 = inputs[0].mul(inputs[1]);

		// // r2 = in2 + in3
		// Wire r2 = inputs[2].add(inputs[3]);

		// // result = (r1+5)*(6*r2)
		// Wire result = r1.add(5).mul(r2.mul(6));

		// // mark the wire as output
		// makeOutput(result);

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(input_s[0], 2);
		for(int i = 1; i < 195; i += 2)
			circuitEvaluator.setWireValue(input_s[i], 2);
		for(int i = 2; i < 195; i += 2){
			circuitEvaluator.setWireValue(input_s[i], 0);
		}
		circuitEvaluator.setWireValue(input_s[193], 2);
		// circuitEvaluator.setWireValue(input_s[98], 17);
		// circuitEvaluator.setWireValue(input_s[99], 17);
		// for (int i = 0; i < 4; i++) {
		// 	circuitEvaluator.setWireValue(inputs[i], i + 1);
		// }
	}

	public static void main(String[] args) throws Exception {

		SimpleCircuitGenerator_snark_friendly generator = new SimpleCircuitGenerator_snark_friendly("snark_friendly");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		System.out.println("Hello Run Libsnark");
		generator.runLibsnark();
	}

}
