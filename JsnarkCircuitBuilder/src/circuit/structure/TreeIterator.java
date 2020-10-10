package circuit.structure;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

public class TreeIterator<T> implements Iterator<TreeNode<T>>{
    private TreeNode<T> next;

    public TreeIterator(TreeNode<T> root){
        next = root;
        if(next == null)
            return;
        while(next.getLeft() != null)
            next = next.getLeft();
    }
    @Override
    public boolean hasNext() {
        return next != null;
    }

    @Override
    public TreeNode<T> next() {
        if (!hasNext())
            throw new NoSuchElementException();
            TreeNode<T> r = next;
        if (next.getRight() != null) {
            next = next.getRight();
            while (next.getLeft() != null)
                next = next.getLeft();
            return r;
        } else
            while (true) {
                if (next.getParent() == null) {
                    next = null;
                    return r;
                }
                if (next.getParent().getLeft() == next) {
                    next = next.getParent();
                    return r;
                }
                next = next.getParent();
            }
    }
}