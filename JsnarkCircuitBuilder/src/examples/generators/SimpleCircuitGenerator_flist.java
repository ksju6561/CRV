/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

public class SimpleCircuitGenerator_flist extends CircuitGenerator {

	private final int string_len = 256;

	private Wire[] input_s;
	private Wire[][] input_s_list;
	private String[] str = new String[100];

	public SimpleCircuitGenerator_flist(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		input_s_list = new Wire[100][];
		System.out.println(string_len);
		for(int j = 0; j < 100; j++){
			input_s_list[j] = createInputWireArray(string_len);
		}
		input_s = createInputWireArray(string_len);
		Wire out = createConstantWire(new BigInteger("0"));

		for (int k = 0; k < 100; k++) {
			Wire r1 = createConstantWire(new BigInteger("0"));
			for (int i = 0; i < input_s.length && i < input_s_list[k].length; i++) {
				r1 = r1.add(input_s[i].isEqualTo(input_s_list[k][i]), "Test Add # " + i);
			}
			out = out.add(r1.isEqualTo(string_len));
		}
		makeOutput(out,"out!!");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		String s = String.format("%0256d",2889);
		for (int i = 0; i < s.length(); i++) {
			circuitEvaluator.setWireValue(input_s[i], s.charAt(i));
			circuitEvaluator.setWireValue(input_s_list[0][i], s.charAt(i));
		}
		for(int j = 1; j < 100; j++) {
			s = String.format("%0256d",j);
			for (int i = 0; i < s.length(); i++) {
				circuitEvaluator.setWireValue(input_s_list[j][i], s.charAt(i));
			}
		}
		// circuitEvaluator.setWireValue(input_s[98], 17);
		// circuitEvaluator.setWireValue(input_s[99], 17);
		// for (int i = 0; i < 4; i++) {
		// 	circuitEvaluator.setWireValue(inputs[i], i + 1);
		// }
	}

	public static void main(String[] args) throws Exception {
		
		SimpleCircuitGenerator_flist generator = new SimpleCircuitGenerator_flist("simple_example_flist");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}

