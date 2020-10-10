package examples.generators.hash;

import util.Util;

import java.math.BigInteger;

import examples.gadgets.hash.SubsetSumHashGadgetJk;
import examples.gadgets.myMath;
import examples.gadgets.hash.SHA2;
import circuit.config.Config;

public class SubsetSumHashGadgeJKTest{

    private int hashDigestDimension = SubsetSumHashGadgetJk.DIMENSION; // 3
	
	public SubsetSumHashGadgeJKTest(String circuitName) {
	}
	
	public static void main(String[] args) throws Exception {

        SubsetSumHashGadgeJKTest generator = new SubsetSumHashGadgeJKTest("test_gadget ");	
        BigInteger[] hash = new BigInteger[6];
        for(int i = 0; i < 3; i++){
            hash[i] = new BigInteger("1");
        }
        for(int i = 3; i < 6; i++){
            hash[i] = new BigInteger("2");
        }
        // hash[0] = SHA2.getSHA256(new BigInteger("1"));
        // hash[1] = SHA2.getSHA256(new BigInteger("1"));
        // hash[2] = SHA2.getSHA256(new BigInteger("1"));
        // hash[3] = SHA2.getSHA256(new BigInteger("2"));
        // hash[4] = SHA2.getSHA256(new BigInteger("2"));
        // hash[5] = SHA2.getSHA256(new BigInteger("2"));
        
        BigInteger[] gadget = myMath.getBitArray(hash, Config.LOG2_FIELD_PRIME);
        for(int i = 0; i < gadget.length; i++){
            //System.out.println("(gadget["+i+"]) :: "+gadget[i]);
            System.out.print(gadget[i]);
        }
        System.out.println("");
        System.out.println("hash[0] :: "+hash[0]);
        System.out.println("hash[1] :: "+hash[1]);
        System.out.println("hash[2] :: "+hash[2]);
        System.out.println("hash[3] :: "+hash[3]);
        System.out.println("hash[4] :: "+hash[4]);
        System.out.println("hash[5] :: "+hash[5]);


        SubsetSumHashGadgetJk subsetSumHashGadgetJk = new SubsetSumHashGadgetJk(gadget,false);

        BigInteger[] result = subsetSumHashGadgetJk.getOutput();

        for(int i = 0; i < result.length; i++){
            System.out.println("result["+i+"] :: "+result[i]);
        }

	}

	
}
