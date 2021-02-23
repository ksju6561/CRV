/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

public class SimpleCircuitGenerator_f extends CircuitGenerator {

	private Wire[] inputs;
	private Wire[] input_s;

	public SimpleCircuitGenerator_f(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		input_s = createInputWireArray(100);
		Wire r1 = createConstantWire(new BigInteger("0"));
		System.out.println("test :: "+r1);
		for(int i = 0; i < 100; i++){
			r1 = r1.add(input_s[i].isGreaterThanOrEqual(19,1),"Test Add # " + i);
		}

		Wire out = r1.isEqualTo(100);
		makeOutput(out);

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
		for(int i = 0; i < 100; i++)
			circuitEvaluator.setWireValue(input_s[i], 20);
		// circuitEvaluator.setWireValue(input_s[98], 17);
		// circuitEvaluator.setWireValue(input_s[99], 17);
		// for (int i = 0; i < 4; i++) {
		// 	circuitEvaluator.setWireValue(inputs[i], i + 1);
		// }
	}

	public static void main(String[] args) throws Exception {

		SimpleCircuitGenerator_f generator = new SimpleCircuitGenerator_f("simple_example_f");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
