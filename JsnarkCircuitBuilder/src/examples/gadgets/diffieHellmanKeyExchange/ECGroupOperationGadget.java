/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/

package examples.gadgets.diffieHellmanKeyExchange;

import java.math.BigInteger;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

import circuit.structure.AffinePoint;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.ConstantWire;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.math.FieldDivisionGadget;
import examples.gadgets.math.ModConstantGadget;

/**
 * This gadget implements cryptographic key exchange using a customized elliptic
 * curve that is efficient to represent as a SNARK circuit. It follows the
 * high-level guidelines used for the design of Curve25519, while having the
 * cost model of QAP-based SNARKs in mind. Details in section 6:
 * https://eprint.iacr.org/2015/1093.pdf
 * 
 * Detailed comments about the inputs and outputs of the circuit are below.
 * 
 * Note: By default, this gadget validates only the secret values that are
 * provided by the prover, such as the secret key, and any intermediate
 * auxiliary witnesses that the prover uses in the circuit. In the default mode,
 * the gadget does not check the public input keys, e.g. it does not verify that
 * the base point or the other party's input have the appropriate order, as such
 * inputs could be typically public and can be checked outside the circuit if
 * needed. The Curve25519 paper as well claims that validation is not necessary
 * (although there is debate about some cases online). If any validation is
 * desired, there is a separate method called validateInputs() that do
 * validation, but is not called by default.
 * 
 * 
 * 
 */

public class ECGroupOperationGadget extends Gadget {

    // Note: this parameterization assumes that the underlying field has
    // Config.FIELD_PRIME =
    // 21888242871839275222246405745257275088548364400416034343698204186575808495617

    public final static BigInteger COEFF_A = new BigInteger("126932"); // parameterization
                                                                       // in
                                                                       // https://eprint.iacr.org/2015/1093.pdf


    // The Affine point representation is used as it saves one gate per bit
    private AffinePoint basePoint; // The Base point both parties agree to
    private AffinePoint hPoint; // H is the other party's public value
                                // H = (other party's secret)* Base <- scalar EC
                                // multiplication

    // gadget outputs
    private Wire outputPublicValue; // the x-coordinate of the key exchange
                                    // material to be sent to the other party
                                    // outputPublicValue = ((this party's
                                    // secret)*Base).x

    private Wire xout;
    private Wire yout;

    /**
     * This gadget receives two points: Base = (baseX) and H = (hX), and the secret
     * key Bits and outputs the scalar EC multiplications: secret*Base, secret*H
     * 
     * The secret key bits must be of length SECRET_BITWIDTH and are expected to
     * follow a little endian order. The most significant bit should be 1, and the
     * three least significant bits should be zero.
     * 
     * This gadget can work with both static and dynamic inputs If public keys are
     * static, the wires of base and h should be made ConstantWires when creating
     * them (before calling this gadget).
     * 
     * 
     */

    public ECGroupOperationGadget(Wire X, Wire Y, String... desc) {
        super(desc);
        this.basePoint = new AffinePoint(X);
        this.hPoint = new AffinePoint(Y);
        computeYCoordinates();

        buildCircuit();
    }

    public ECGroupOperationGadget(Wire baseX, Wire expX, Wire baseY, Wire expY, String... desc) {
        super(desc);
        ECGroupGeneratorGadget gadget1 = new ECGroupGeneratorGadget(baseX, expX, desc);
        ECGroupGeneratorGadget gadget2 = new ECGroupGeneratorGadget(baseY, expY, desc);
        
        this.basePoint = new AffinePoint(gadget1.getOutputWires()[0]);
        this.hPoint = new AffinePoint(gadget2.getOutputWires()[0]);
        computeYCoordinates();
        
        buildCircuit();
    }

    protected void buildCircuit() {

        /**
         * The reason this operates on affine coordinates is that in our setting, this's
         * slightly cheaper than the formulas in
         * https://cr.yp.to/ecdh/curve25519-20060209.pdf. Concretely, the following
         * equations save 1 multiplication gate per bit. (we consider multiplications by
         * constants cheaper in our setting, so they are not counted)
         */
        Wire samebasepoint = basePoint.x.isEqualTo(hPoint.x);

        AffinePoint out = addAffinePoints(basePoint, hPoint);
        
        outputPublicValue = out.x;
        xout = basePoint.x;
        yout = hPoint.x;
        // Wire a = basePoint.x;
        // Wire b = hPoint.x;
        // outputPublicValue = a.mul(b);
    
        
        // Wire[] a = (basePoint.x).getBitWires(254).asArray();
        // Wire[] b = (hPoint.x).getBitWires(254).asArray();
        // Wire[] out = new WireArray(a).xorWireArray(new WireArray(b), SECRET_BITWIDTH).asArray();
        
        // outputPublicValue = new WireArray(out).packAsBits(SECRET_BITWIDTH);
        
    }


    private void computeYCoordinates() {

        // Easy to handle if baseX is constant, otherwise, let the prover input
        // a witness and verify some properties

        if (basePoint.x instanceof ConstantWire) {

            BigInteger x = ((ConstantWire) basePoint.x).getConstant();
            basePoint.y = generator.createConstantWire(computeYCoordinate(x));
        } else {
            basePoint.y = generator.createProverWitnessWire();
            generator.specifyProverWitnessComputation(new Instruction() {
                public void evaluate(CircuitEvaluator evaluator) {
                    BigInteger x = evaluator.getWireValue(basePoint.x);
                    evaluator.setWireValue(basePoint.y, computeYCoordinate(x));
                }
            });
            assertValidPointOnEC(basePoint.x, basePoint.y);
        }

        if (hPoint.x instanceof ConstantWire) {
            BigInteger x = ((ConstantWire) hPoint.x).getConstant();
            hPoint.y = generator.createConstantWire(computeYCoordinate(x));
        } else {
            hPoint.y = generator.createProverWitnessWire();
            generator.specifyProverWitnessComputation(new Instruction() {
                public void evaluate(CircuitEvaluator evaluator) {
                    BigInteger x = evaluator.getWireValue(hPoint.x);
                    evaluator.setWireValue(hPoint.y, computeYCoordinate(x));
                }
            });
            assertValidPointOnEC(hPoint.x, hPoint.y);

        }
    }

    // this is only called, when Wire y is provided as witness by the prover
    // (not as input to the gadget)
    private void assertValidPointOnEC(Wire x, Wire y) {
        Wire ySqr = y.mul(y);
        Wire xSqr = x.mul(x);
        Wire xCube = xSqr.mul(x);
        generator.addEqualityAssertion(ySqr, xCube.add(xSqr.mul(COEFF_A)).add(x));
    }

    private AffinePoint doubleAffinePoint(AffinePoint p) {
        Wire x_2 = p.x.mul(p.x);
        Wire l1 = new FieldDivisionGadget(x_2.mul(3).add(p.x.mul(COEFF_A).mul(2)).add(1), p.y.mul(2))
                .getOutputWires()[0];
        Wire l2 = l1.mul(l1);
        Wire newX = l2.sub(COEFF_A).sub(p.x).sub(p.x);
        Wire newY = p.x.mul(3).add(COEFF_A).sub(l2).mul(l1).sub(p.y);
        return new AffinePoint(newX, newY);
    }

    private AffinePoint addAffinePoints(AffinePoint p1, AffinePoint p2) {
        Wire diffY = p1.y.sub(p2.y);
        Wire diffX = p1.x.sub(p2.x);
        Wire q = new FieldDivisionGadget(diffY, diffX).getOutputWires()[0];
        Wire q2 = q.mul(q);
        Wire q3 = q2.mul(q);
        Wire newX = q2.sub(COEFF_A).sub(p1.x).sub(p2.x);
        Wire newY = p1.x.mul(2).add(p2.x).add(COEFF_A).mul(q).sub(q3).sub(p1.y);
        return new AffinePoint(newX, newY);
    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[] { outputPublicValue, xout, yout };
    }

    public static BigInteger computeYCoordinate(BigInteger x) {
        BigInteger xSqred = x.multiply(x).mod(Config.FIELD_PRIME);
        BigInteger xCubed = xSqred.multiply(x).mod(Config.FIELD_PRIME);
        BigInteger ySqred = xCubed.add(COEFF_A.multiply(xSqred)).add(x).mod(Config.FIELD_PRIME);
        BigInteger y = IntegerFunctions.ressol(ySqred, Config.FIELD_PRIME);
        return y;
    }

    public Wire getOutputPublicValue() {
        return outputPublicValue;
    }


}
