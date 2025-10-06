package weka.classifiers.trees;

import weka.core.*;
import java.io.Serializable;

/**
 * An abstract class that represents a Splitter object.
 */
abstract class Splitter implements Serializable {

    /**
     * The method to be implemented to find a split based on the given data.
     */
    abstract void findSplit(Instances data);

    /**
     * The method to be implemented that returns true if the given instance
     * should go down the first branch and false otherwise.
     */
    abstract boolean firstSubset(Instance instance);

    /**
     * The method to be implemented that returns the quality of the split.
     */
    abstract double splitQuality();

    /**
     * Returns a string representation of the condition for a branch.
     */
    abstract String toString(boolean leftBranch, int decimalPlaces);
}
