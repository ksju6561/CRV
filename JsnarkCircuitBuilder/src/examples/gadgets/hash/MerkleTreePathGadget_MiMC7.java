package examples.gadgets.hash;

import circuit.operations.Gadget;
import circuit.structure.Wire;

public class MerkleTreePathGadget_MiMC7 extends Gadget {
	private int treeHeight;
	private Wire directionSelectorWire;
	private Wire[] directionSelectorBits;
	private Wire[] leafWires;
	private Wire[] intermediateHashWires;
	private Wire[] outRoot;

	public MerkleTreePathGadget_MiMC7(Wire directionSelectorWire, Wire[] leafWires, Wire[] intermediateHasheWires,
			 int treeHeight, String... desc) {

		super(desc);
		this.directionSelectorWire = directionSelectorWire;
		this.treeHeight = treeHeight;
		this.leafWires = leafWires;
		this.intermediateHashWires = intermediateHasheWires;

		buildCircuit();
	}

	private void buildCircuit() {
		directionSelectorBits = directionSelectorWire.getBitWires(treeHeight).asArray();


		MiMC7Gadget MiMC7 = new MiMC7Gadget(leafWires);
        Wire currentHash = MiMC7.getOutputWires()[0];

		Wire inHash, temp, temp2;
		for (int i = 0; i < treeHeight; i++) {
			temp = currentHash.sub(intermediateHashWires[i]);
			temp2 = directionSelectorBits[i].mul(temp);
			inHash = intermediateHashWires[i].add(temp2);
	
			temp = currentHash.add(intermediateHashWires[i]);
			inHash = temp.sub(inHash);
			
			MiMC7 = new MiMC7Gadget(currentHash, inHash);
            currentHash = MiMC7.getOutputWires()[0];
		}
		outRoot = new Wire[] {currentHash};
	}

	@Override
	public Wire[] getOutputWires() {
		return outRoot;
	}

}
