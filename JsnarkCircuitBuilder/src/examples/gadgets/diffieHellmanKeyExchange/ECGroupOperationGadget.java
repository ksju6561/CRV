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
    private Wire[] outputPubValue;
    /**
     * This gadget receives two points: Base = (pt1_x) and H = (hX), and the secret
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

    public ECGroupOperationGadget(Wire pt1_x, Wire exp1, Wire pt2_x, Wire exp2, String... desc) {
        super(desc);
        ECGroupGeneratorGadget gadget1 = new ECGroupGeneratorGadget(pt1_x, exp1, desc);
        ECGroupGeneratorGadget gadget2 = new ECGroupGeneratorGadget(pt2_x, exp2, desc);
        
        this.basePoint = new AffinePoint(gadget1.getOutputWires()[0]);
        this.hPoint = new AffinePoint(gadget2.getOutputWires()[0]);
        computeYCoordinates();
        
        buildCircuit();
    }

    public ECGroupOperationGadget(Wire pt1_x, Wire pt1_y, Wire exp1, Wire pt2_x, Wire pt2_y, Wire exp2, String... desc) {
        super(desc);
        ECGroupGeneratorGadget gadget1 = new ECGroupGeneratorGadget(pt1_x, pt1_y, exp1, desc);
        ECGroupGeneratorGadget gadget2 = new ECGroupGeneratorGadget(pt2_x, pt2_y, exp2, desc);
        
        Wire[] g1_out = gadget1.getOutputWires();
        Wire[] g2_out = gadget2.getOutputWires();
        this.basePoint = new AffinePoint(g1_out[0],g1_out[1]);//, gadget1.getOutputWires()[1]);
        this.hPoint = new AffinePoint(g2_out[0],g2_out[1]);
        //computeYCoordinates();        
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
        // Wire samebasepoint = basePoint.x.isEqualTo(hPoint.x);

        AffinePoint out = addAffinePoints(basePoint, hPoint);
        
        //outputPublicValue = out.x;
        xout = basePoint.x;
        yout = hPoint.x;
        outputPubValue = new Wire[2];
        outputPubValue[0] = out.x;
        outputPubValue[1] = out.y;
    }


    private void computeYCoordinates() {

        // Easy to handle if pt1_x is constant, otherwise, let the prover input
        // a witness and verify some properties

        if (basePoint.x instanceof ConstantWire) {

            BigInteger x = ((ConstantWire) basePoint.x).getConstant();
            basePoint.y = generator.createConstantWire(computeYCoordinate(x));
        } else {
            basePoint.y = generator.createProverWitnessWire("basepoint.y");
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
            hPoint.y = generator.createProverWitnessWire("hpoint.y");
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
        return new Wire[] { outputPubValue[0], outputPubValue[1] }; //outputPubValue;//
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
