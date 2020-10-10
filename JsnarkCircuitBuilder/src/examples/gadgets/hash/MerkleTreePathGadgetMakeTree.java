/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.gadgets.hash;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import circuit.config.Config;
import examples.gadgets.myMath;


/**
 * A Merkle tree authentication gadget using the subsetsum hash function
 * 
 */

public class MerkleTreePathGadgetMakeTree{

	private static int digestWidth = SubsetSumHashGadget.DIMENSION;

	private BigInteger leafNodeNum;
	private int treeHeight;
	private int leafWordBitWidth;
	private int leafNumOfWords;
	private String path;
	private Map<BigInteger,BigInteger[]> nodeSet;
	private BigInteger nodeMaxIndex;

	public MerkleTreePathGadgetMakeTree(BigInteger leafNodeNum, int leafWordBitWidth, int leafNumOfWords, int treeHeight,String PKid_FileName) {
		this.leafNodeNum = leafNodeNum;
		this.leafWordBitWidth = leafWordBitWidth;
		this.leafNumOfWords = leafNumOfWords;

		this.treeHeight = treeHeight;

		path = PKid_FileName;

		nodeSet = new HashMap<BigInteger,BigInteger[]>();
		nodeMaxIndex = new BigInteger("2").pow(treeHeight).subtract(BigInteger.ONE);

		makeTree();
	}

	private void makeTree() {
		long totalstart = 0,start = 0;
		long end = 0;

		SubsetSumHashGadgetJk subsetSumHashGadgetJk;

		BigInteger nodeIndex = BigInteger.ZERO;
		BigInteger hashIndex = BigInteger.ZERO;
		System.out.println(nodeMaxIndex);

		totalstart = start = System.nanoTime(); 
		try{
			File file = new File(path);
			FileReader fileReader = new FileReader(file);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			String line = "";
			while((line = bufferedReader.readLine()) != null){
				BigInteger leafNodeBigInteger = new BigInteger(line);
				BigInteger[] leafNodeWordsBigInteger = myMath.split(leafNodeBigInteger, leafWordBitWidth, leafNumOfWords);
				BigInteger[] leafNodeBits = myMath.getBitArray(leafNodeWordsBigInteger,leafWordBitWidth);
				subsetSumHashGadgetJk = new SubsetSumHashGadgetJk(leafNodeBits, false);
				nodeSet.put(nodeIndex, subsetSumHashGadgetJk.getOutput()); nodeIndex = nodeIndex.add(BigInteger.ONE);
			}// leaf Node
			bufferedReader.close();
		}catch(FileNotFoundException e){
			System.err.println(e);
		}catch(IOException e){
			System.err.println(e);
		}
		end = System.nanoTime();
		System.out.println("\tMake leaf node time   :: "+((double) (end - start) / 1000000000));

		start = System.nanoTime(); 
		BigInteger[] dummyNodeBigInteger = new BigInteger[1];
		dummyNodeBigInteger[0] = new BigInteger("0");
		//dummyNodeBigInteger[0] = new BigInteger("2147483647");
		//Random rand = new Random();
		System.out.println("\tDummy Node num:: "+ (new BigInteger("2").pow(treeHeight-1).subtract(leafNodeNum)));
		for(BigInteger i = leafNodeNum; i.compareTo(new BigInteger("2").pow(treeHeight-1)) < 0;i = i.add(BigInteger.ONE)){
			//dummyNodeBigInteger[0] = new BigInteger(leafWordBitWidth,rand);
			BigInteger[] dummyNodeBitsArray = myMath.getBitArray(dummyNodeBigInteger, leafWordBitWidth);
			subsetSumHashGadgetJk = new SubsetSumHashGadgetJk(dummyNodeBitsArray, false);
			BigInteger[] dummyNode = subsetSumHashGadgetJk.getOutput();
			nodeSet.put(nodeIndex, dummyNode); nodeIndex = nodeIndex.add(BigInteger.ONE);
		}// dummy

		end = System.nanoTime();
		System.out.println("\tMake dummy node time   :: "+((double) (end - start) / 1000000000));
	
		start = System.nanoTime(); 
		while(nodeIndex.compareTo(nodeMaxIndex) < 0){
			BigInteger[] hash = new BigInteger[2 * digestWidth];
			System.arraycopy(nodeSet.get(hashIndex),0,hash,0,digestWidth); hashIndex = hashIndex.add(BigInteger.ONE);
			System.arraycopy(nodeSet.get(hashIndex),0,hash,digestWidth,digestWidth); hashIndex = hashIndex.add(BigInteger.ONE);
			BigInteger[] hashBits = myMath.getBitArray(hash,Config.LOG2_FIELD_PRIME);
			subsetSumHashGadgetJk = new SubsetSumHashGadgetJk(hashBits, false);
			nodeSet.put(nodeIndex, subsetSumHashGadgetJk.getOutput()); nodeIndex = nodeIndex.add(BigInteger.ONE);
		}
		end = System.nanoTime();

		System.out.println("\tMake merckle hash time :: "+ ((double) (end - start) / 1000000000));
		System.out.println("Total time :: " + ((double) (end - totalstart) / 1000000000));

		System.out.println(nodeSet.size());
	}

	public void writeFile(String path){
		try{
			BufferedWriter writer = new BufferedWriter(new FileWriter(path));
			Set<Map.Entry<BigInteger, BigInteger[]>> entry = nodeSet.entrySet();
			for (Map.Entry<BigInteger, BigInteger[]> nodeData : entry) {
				writer.write(nodeData.getKey().toString());
				for (int j = 0; j < nodeData.getValue().length; j++)
					writer.write(" " + nodeData.getValue()[j]);
				writer.newLine();
			}
			writer.close();
		}catch(FileNotFoundException e){
			System.err.println(e);
		}catch(IOException e){
			System.err.println(e);
		}
	}
	public void printTree(BigInteger nodeIndex,int level){
		if(nodeIndex.compareTo(nodeMaxIndex) > 0)	return;
		for(int k = 0; k < level; k++)
			System.out.print("  ");
		
		System.out.println("node ["+nodeMaxIndex.subtract(nodeIndex) +"]");
		// for(int j = 0; j < digestWidth;j++){
		// 	for(int k = 0; k < level; k++)
		// 		System.out.print("  ");
		// 	System.out.println("["+j+"]:"+nodeSet.get(nodeMaxIndex.subtract(nodeIndex))[j]);
		// }
		printTree(nodeIndex.multiply(new BigInteger("2")).add(BigInteger.ONE),level+1);
		printTree(nodeIndex.multiply(new BigInteger("2")),level+1);
	}

	public static void main(String[] args) throws Exception{
		MerkleTreePathGadgetMakeTree makeTree = new MerkleTreePathGadgetMakeTree(new BigInteger("8"), 32, 8, 4,
				"/home/itsp/jk/HFAL/jsnark/JsnarkCircuitBuilder/PKlist.dat");
		makeTree.printTree(new BigInteger("1"),0);
		makeTree.writeFile("/home/itsp/jk/HFAL/jsnark/JsnarkCircuitBuilder/HashTree.dat");
	}

}
