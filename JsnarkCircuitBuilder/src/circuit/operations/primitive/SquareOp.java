package circuit.operations.primitive;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.structure.Wire;

public class SquareOp extends BasicOp {
    //private Wire w;
    public SquareOp(Wire w1, Wire w2, Wire out, String... desc) {
        super(new Wire[] { w1, w2 }, new Wire[] { out }, desc);
        //w = w2;
    }

    public String getOpcode() {
        return "square";
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
        if (!(obj instanceof SquareOp))
            return false;
            SquareOp op = (SquareOp) obj;

        boolean check1 = inputs[0].equals(op.inputs[0])
                        && inputs[1].equals(op.inputs[1]);
        boolean check2 = inputs[1].equals(op.inputs[0])
                        && inputs[0].equals(op.inputs[1]);
        return check1 || check2;
    }
    @Override
    public int getNumMulGates() {
        // TODO Auto-generated method stub
        //w.getBitWires(32, desc);
        
        return 1;
    }
}