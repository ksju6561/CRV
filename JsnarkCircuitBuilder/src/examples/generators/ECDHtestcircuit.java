/*******************************************************************************
 * Author: Jaekyoung Choi <cjk2889@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.util.Arrays;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupGeneratorGadget;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupOperationGadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.math.ModConstantGadget;

public class ECDHtestcircuit extends CircuitGenerator {
	/* INPUT */
	private Wire G;
	private Wire U;
	private Wire V;
	private Wire W;
	// private Wire msgsum; // MAX = (15) * 2 ^ 16
	/* WITNESS */
	// private Wire SK;

	public ECDHtestcircuit(String circuitName) {
		super(circuitName);

	}

	private Wire mulexp(Wire a, Wire b){
		ModConstantGadget mod = new ModConstantGadget(a, b, Config.CURVE_ORDER);
		return mod.getOutputWires()[0]; 
	}

	@Override
	protected void buildCircuit() {
		G = createInputWire("G");
		// U = createInputWire("U");
		V = createInputWire("V"); // vsum
		W = createInputWire("W"); // wsum

		Wire msgsum = createConstantWire(new BigInteger("2147483648"));
		Wire SK = createConstantWire(new BigInteger("204444782122713504954636029222746100201332865755450300886921118968015889151"));
		Wire eight = createConstantWire(8);
		// 253bit
		Wire s = createConstantWire(
				new BigInteger("234444782122713504954636029222746100201332865755450300886921118968015889151"));
		Wire rand = createConstantWire(new BigInteger("123141251243"));

		ECGroupGeneratorGadget gs = new ECGroupGeneratorGadget(G, s);
		makeOutput(G, "G");

		ECGroupGeneratorGadget test = new ECGroupGeneratorGadget(G, SK);
		Wire U = test.getOutputPublicValue();
		makeOutput(U, "U");
		// makeOutputArray(test.getOutputWires());
		Wire S = gs.getOutputPublicValue();
		makeOutput(S, "g^s"); 
		
		ECGroupGeneratorGadget makeT = new ECGroupGeneratorGadget(G, mulexp(s, SK).add(rand));
		Wire T1 = makeT.getOutputPublicValue();
		makeOutput(T1, "g^(srho+r)");

		// ECGroupGeneratorGadget T = new ECGroupGeneratorGadget(S, SK);
		ECGroupOperationGadget T = new ECGroupOperationGadget(S, SK, G, rand);
		Wire T2 = T.getOutputPublicValue();
		makeOutput(T2, "S^rho + G^r");

		ECGroupGeneratorGadget SR = new ECGroupGeneratorGadget(S, SK);
		makeOutput(SR.getOutputPublicValue(), "S^rho");
		ECGroupGeneratorGadget check = new ECGroupGeneratorGadget(G, mulexp(s, SK));
		makeOutput(check.getOutputPublicValue(), "g^(srho)");

		ECGroupGeneratorGadget tm = new ECGroupGeneratorGadget(T1, msgsum);
		makeOutput(tm.getOutputPublicValue(), "T^m");
		
		ECGroupGeneratorGadget tm2 = new ECGroupGeneratorGadget(G, mulexp(mulexp(s, SK).add(rand), msgsum));
		makeOutput(tm2.getOutputPublicValue(), "G^((s*rho+rand)*m)");
		ECGroupGeneratorGadget ur = new ECGroupGeneratorGadget(U, rand);
		makeOutput(ur.getOutputPublicValue(), "U^r");
		
		ECGroupGeneratorGadget ur2 = new ECGroupGeneratorGadget(G, mulexp(SK, rand));
		makeOutput(ur2.getOutputPublicValue(), "G^(rho*r)");
		
		Wire rand2 = createConstantWire(new BigInteger("1231231212312542673123124124879879879817259871293845798123754981237549312324"));
		
		ECGroupOperationGadget encV = new ECGroupOperationGadget(G, rand2, S, msgsum); //하나에 120ms 정도
		Wire V = encV.getOutputPublicValue();
		ECGroupOperationGadget encW = new ECGroupOperationGadget(U, rand2, T2, msgsum);
		Wire W = encW.getOutputPublicValue();

		ECGroupGeneratorGadget vsk = new ECGroupGeneratorGadget(V, SK);
		makeOutput(vsk.getOutputPublicValue(), "V^rho");
		
		ECGroupGeneratorGadget vsk2 = new ECGroupGeneratorGadget(G, mulexp(mulexp(s, msgsum).add(rand2), SK));
		makeOutput(vsk2.getOutputPublicValue(), "G^((s*m + r)*rho)");

		ECGroupOperationGadget check2 = new ECGroupOperationGadget(V, SK, G, mulexp(rand, msgsum));
		makeOutput(check2.getOutputPublicValue(), "W?");
		
		makeOutput(W, "W");
		makeOutput(V, "V");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(G,
				new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));
		// circuitEvaluator.setWireValue(U,
				// new BigInteger("11887599675588148316772337507702514853876355741811850759752806504104274732396"));
		circuitEvaluator.setWireValue(V,
				new BigInteger("13661002310307559717494111518222658067306869622099376718628839422193784568166"));
		circuitEvaluator.setWireValue(W,
				new BigInteger("14698925788933201984430583328591516055353563534524984870763771430446706204922"));

		// circuitEvaluator.setWireValue(msgsum, new BigInteger("2147483648"));

		// circuitEvaluator.setWireValue(SK,
		// 		new BigInteger("204444782122713504954636029222746100201332865755450300886921118968015889151"));

	}

	public static void main(String[] args) throws Exception {

		ECDHtestcircuit generator = new ECDHtestcircuit("ECDHtestcircuit");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}
