/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.gadgets.math;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;

/**
 * This gadget provides the remainder of a % c, where c is a circuit constant.
 *
 *
 */

public class ModConstantGadget extends Gadget {

	private final Wire a;
	private final Wire b;
	private final BigInteger c;
	private Wire r;
	private Wire q;


	public ModConstantGadget(Wire a, BigInteger c, String...desc) {
		super(desc);
		this.a = a;
		this.b = generator.getOneWire();
		this.c = c;
		if(c.signum() != 1){
			throw new IllegalArgumentException("c must be a positive constant. Signed operations not supported yet.");
		}

		// TODO: add further checks.
		
		buildCircuit();
	}

	public ModConstantGadget(Wire a, Wire b, BigInteger c, String...desc) {
		super(desc);
		this.a = a;
		this.b = b;
		this.c = c;
		if(c.signum() != 1){
			throw new IllegalArgumentException("c must be a positive constant. Signed operations not supported yet.");
		}

		// TODO: add further checks.
		
		buildCircuit();
	}

	private void buildCircuit() {

		r = generator.createProverWitnessWire("mod result");
		q = generator.createProverWitnessWire("division result");

		// notes about how to use this code block can be found in FieldDivisionGadget
		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				BigInteger aValue = evaluator.getWireValue(a);
				BigInteger bValue = evaluator.getWireValue(b);
				BigInteger mulValue = aValue.multiply(bValue);
				BigInteger rValue = mulValue.mod(c);
				evaluator.setWireValue(r, rValue);
				BigInteger qValue = mulValue.divide(c);
				evaluator.setWireValue(q, qValue);
			}

		});

	}

	@Override
	public Wire[] getOutputWires() {
		return new Wire[] { r , q};
	}

}
