/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import util.Util;

public class SimpleCircuitGenerator extends CircuitGenerator {

	private Wire[] inputs;
	private Wire[] input_s;

	public SimpleCircuitGenerator(String circuitName) {
		super(circuitName);
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
		for(int i = 0 ; i<8 ; i++)
		input_s = createInputWireArray(8, "pp" + Integer.toString(i));
		makeOutputArray(input_s,"input");
		
		

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		for(int i = 0 ; i < 8 ; i++)
		circuitEvaluator.setWireValue(input_s[0], Util.nextRandomBigInteger(32));
		// for (int i = 0; i < 4; i++) {
		// 	circuitEvaluator.setWireValue(inputs[i], i + 1);
		// }
	}

	public static void main(String[] args) throws Exception {

		SimpleCircuitGenerator generator = new SimpleCircuitGenerator("simple_example");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
