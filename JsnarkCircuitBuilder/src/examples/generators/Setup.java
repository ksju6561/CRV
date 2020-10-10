package examples.generators;

import java.io.ByteArrayOutputStream;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import util.Util;
import circuit.auxiliary.LongElement;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;


public class Setup {

	public BigInteger G, Grho;
	private BigInteger rho;
	private int treeHeight;

    public Setup(int treeHeight) {
		
		this.treeHeight = treeHeight;

    }
    private static BigInteger GCD(BigInteger a,BigInteger b) { if (b.signum() == 0) { return a; } return GCD(b,a.mod(b)); }

	public static BigInteger Generator()
	{
		BigInteger g, b = Config.FIELD_PRIME;
		g = Util.nextRandomBigInteger(256);
		while(GCD(g, b).compareTo(BigInteger.ONE) == 1)
			g = Util.nextRandomBigInteger(256);	
		 
		
		return g;

	}
	
	public BigInteger grho(BigInteger g)
	{
		rho = Util.nextRandomBigInteger(256);
		BigInteger grho = g.modPow(rho, Config.FIELD_PRIME);
		
        return grho;
	}

	public static void main(String[] args) throws Exception{
		BigInteger G = Generator();
		int mode = 0, secparam = 32;
		voter voter = new voter("voter", secparam, G, 0);
		voter.generateCircuit();
		voter.evalCircuit();
        voter.prepFiles();
		System.out.println("Run VOTER SETUP");
		voter.runLibsnarksetup(0);

	}
}