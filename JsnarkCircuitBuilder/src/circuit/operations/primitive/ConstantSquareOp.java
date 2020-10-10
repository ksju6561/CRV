package circuit.operations.primitive;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.structure.Wire;

public class ConstantSquareOp extends BasicOp {
    private BigInteger constInteger;
    private boolean inSign;


    public ConstantSquareOp(Wire w, BigInteger constInteger, Wire out, String... desc) {
        super(new Wire[] { w }, new Wire[] { out }, desc);
        inSign = constInteger.signum() == -1;
		if (!inSign) {
			constInteger = constInteger.mod(Config.FIELD_PRIME);
			this.constInteger =constInteger;
		} else {
			constInteger = constInteger.negate();
			constInteger = constInteger.mod(Config.FIELD_PRIME);
			this.constInteger = Config.FIELD_PRIME.subtract(constInteger);
		}
    }

    public String getOpcode() {
        if (!inSign) {
			return "const-square-" + constInteger.toString(16);
		} else{
			return "const-square-neg-" + Config.FIELD_PRIME.subtract(constInteger).toString(16);
		}
    }


    @Override
    protected void compute(BigInteger[] assignment) {
        // 
        //BigInteger result = BigInteger.ONE;
        
        BigInteger result = assignment[inputs[0].getWireId()].modPow(constInteger, Config.FIELD_PRIME);
        result = result.mod(Config.FIELD_PRIME);
        assignment[outputs[0].getWireId()] = result;
    }
    @Override
	public boolean equals(Object obj) {
        //TODO
        if (this == obj)
            return true;
        if (!(obj instanceof ConstantSquareOp))
            return false;
            ConstantSquareOp op = (ConstantSquareOp) obj;

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