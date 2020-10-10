package circuit.operations.primitive;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.structure.Wire;

public class SquareAndMultiplyOp extends BasicOp {
    public SquareAndMultiplyOp(Wire w1, Wire w2, Wire out, String... desc) {
        super(new Wire[] { w1, w2 }, new Wire[] { out }, desc);
    }

    public String getOpcode() {
        return "sm";
    }


    @Override
    protected void compute(BigInteger[] assignment) {
        // 
        //BigInteger result = BigInteger.ONE;
        
        BigInteger result = assignment[inputs[0].getWireId()].modPow(assignment[inputs[1].getWireId()], Config.FIELD_PRIME);

        assignment[outputs[0].getWireId()] = result;
    }
    @Override
	public boolean equals(Object obj) {
        //TODO
        if (this == obj)
            return true;
        if (!(obj instanceof SquareAndMultiplyOp))
            return false;
        SquareAndMultiplyOp op = (SquareAndMultiplyOp) obj;

        boolean check1 = inputs[0].equals(op.inputs[0])
                        && inputs[1].equals(op.inputs[1]);
        boolean check2 = inputs[1].equals(op.inputs[0])
                        && inputs[0].equals(op.inputs[1]);
        return check1 || check2;
    }
    @Override
    public int getNumMulGates() {
        // TODO Auto-generated method stub
        return 1;
    }
}