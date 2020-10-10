package examples.gadgets;

import java.math.BigInteger;

public class myMath{

    public static BigInteger[] getBitArray(BigInteger[] input, int bitwidth){
        BigInteger[] cpy_input = input.clone();

        BigInteger[] rst = new BigInteger[input.length * bitwidth];
        //System.out.println(input.length * bitwidth);
        for(int i = 0; i < input.length; i++){
            for(int j = 0; j < bitwidth; j++){
                rst[i*bitwidth + j] = cpy_input[i].and(BigInteger.ONE);
                cpy_input[i] = cpy_input[i].shiftRight(1);
            }
        }
        return rst;
    } 
    
    public static BigInteger[] split(BigInteger input, int bitwidth, int blocksize){
        BigInteger cpy_input = input;
        BigInteger bitwidthBigInteger = new BigInteger("2").pow(bitwidth).subtract(BigInteger.ONE);
        BigInteger[] rst = new BigInteger[blocksize];
        //System.out.println(input.length * bitwidth);
        for(int i = 0; i < blocksize; i++){
            rst[i] = cpy_input.and(bitwidthBigInteger);
            cpy_input = cpy_input.shiftRight(bitwidth);
        }
        return rst;
    } 
}