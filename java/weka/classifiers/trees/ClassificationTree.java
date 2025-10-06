package weka.classifiers.trees;

import weka.classifiers.AbstractClassifier;
import weka.core.*;

import java.io.Serializable;
import java.util.*;

/**
 * A generic classification tree learner that grows a tree using the standard top-down approach.
 * Splits are defined by objects of the relevant splitter class.
 */
public class ClassificationTree extends AbstractClassifier implements AdditionalMeasureProducer {

    /**
     * A possible way to represent the tree structure using Java records.
     */
    private interface Node { }
    private record InternalNode(Splitter splitter, Node leftSuccessor, Node rightSuccessor)
            implements Node, Serializable { }
    private record LeafNode(double[] classProbabilities) implements Node, Serializable { }
    
    /** The root node of the decision tree. */
    private Node rootNode = null;

    /** The number of nodes in the tree. */
    private int treeSize = 0;
    
    /** The training instances. */
    private Instances data;

    /** The minimum info gain required for a split (default = 1e-6). */
    private double infoGainThreshold = 1e-6;

    /** Whether to learn a bivariate instead of a univariate split. */
    private boolean bivariateSplit = false;
    
    /**
     * Returns the capabilities of the classifier: numeric predictors
     * and nominal class attribute.
     */
    public Capabilities getCapabilities() {
        Capabilities result = super.getCapabilities();
        result.disableAll();
        result.enable(Capabilities.Capability.NUMERIC_ATTRIBUTES);
        result.enable(Capabilities.Capability.NOMINAL_CLASS);
        return result;
    }       
    
    /**
     * Method to set the cut-off on information gain for pre-pruning. Including metadata annotation
     * to implement command-line option handling for this parameter.
     */
    @OptionMetadata(displayName = "info gain threshold", description = "Minimum info gain required for a split (default = 1e-6).",
		    commandLineParamName = "info-gain-threshold", commandLineParamSynopsis = "-info-gain-threshold <double>", displayOrder = 1)
    public void setInfoGainThreshold(double t) {
       infoGainThreshold = t;
    }
    
    /**
     * Method to get the info gain threshold
     */
    public double getInfoGainThreshold() {
	return infoGainThreshold;
    }
    
    /**
     * Method to set whether bivariate split is to be performed.
     */
    @OptionMetadata(displayName = "bivariate split", description = "Whether to use a bivariate split instead of a univarite one (default = false).",
		    commandLineParamName = "bivariate-split", commandLineParamSynopsis = "-bivariate-split", displayOrder = 2, 	commandLineParamIsFlag = true)
    public void setBivariateSplit(boolean b) {
       bivariateSplit = b;
    }
    
    /**
     * Method to get whether bivariate splitting is performed.
     */
    public boolean getBivariateSplit() {
	return bivariateSplit;
    }
    
    /**
     * Builds the tree classifier by making a shallow copy of the
     * training data and calling the recursive makeTree(Instances) method.
     */
    public void buildClassifier(Instances trainingData) throws Exception {
        // First, use the capabilities to check whether the learning
        // algorithm can handle the data.
        getCapabilities().testWithFail(trainingData);
        data = new Instances(trainingData);
	treeSize = 0;
        rootNode = makeTree(data);
	data = new Instances(data, 0);
    }

    /**
     * Provides an estimated class probability distribution for the
     * current instance by calling the recursive makePrediction(Node,
     * Instance) method.
     */
    public double[] distributionForInstance(Instance instance) {
        return makePrediction(rootNode, instance);
    }

    /**
     * Recursively grows a tree for a given dataset.
     */
    private Node makeTree(Instances data) {
	treeSize++;
	Splitter splitter = getBivariateSplit() ?
	    new BivariateNumericAttributeSplitter() : new UnivariateNumericAttributeSplitter();
	splitter.findSplit(data);
        if (splitter.splitQuality() < getInfoGainThreshold()) {
	    double[] probabilities = new double[data.numClasses()];
	    for (Instance instance : data) {
		probabilities[(int)instance.classValue()]++;
	    }
	    for (int j = 0; j < data.numClasses(); j++) {
		probabilities[j] /= (double)data.numInstances();
	    }
            return new LeafNode(probabilities);
        } else {
            var leftSubset = new Instances(data, data.numInstances());
            var rightSubset = new Instances(data, data.numInstances());
            for (Instance instance : data) {
                if (splitter.firstSubset(instance)) {
		    leftSubset.add(instance);
		} else {
                    rightSubset.add(instance);
                }
            }
	    return new InternalNode(splitter, makeTree(leftSubset), makeTree(rightSubset));
        }
    }

    /**
     * Recursive method for obtaining estimated class probabilities from the tree
     * attached to the node provided.
     */
    private double[] makePrediction(Node node, Instance instance) {
        if (node instanceof LeafNode) {
            return ((LeafNode) node).classProbabilities;
        } else if (node instanceof InternalNode) {
            if (((InternalNode) node).splitter.firstSubset(instance)) {
                return makePrediction(((InternalNode) node).leftSuccessor, instance);
            } else {
                return makePrediction(((InternalNode) node).rightSuccessor, instance);
            }
        }
        return new double[0]; // This should never happen
    }

    /**
     * Returns a string representation of the tree by calling the
     * recursive toString(StringBuffer, int, Node) method.
     */
    public String toString() {
        if (rootNode == null) {
            return "No model has been built yet.";
        }
        StringBuffer sb = new StringBuffer();
        toString(sb, 0, rootNode);
	sb.append("\n\nSize of the tree : " + treeSize);
        return sb.toString();
    }

    /**
     * Recursively produces a string representation of a subtree by
     * calling the branchToString(StringBuffer, int, Node) method for
     * both branches, unless we are at a leaf.
     */
    private void toString(StringBuffer sb, int level, Node node) {
        if (node instanceof LeafNode) {
            sb.append(": ");
	    double[] probabilities = ((LeafNode) node).classProbabilities;
	    for (int i = 0; i < probabilities.length; i++) {
		if (i > 0) {
		    sb.append(",");
		}
		sb.append(String.format("%." + getNumDecimalPlaces() + "f", probabilities[i]));
	    }
        } else {
            branchToString(sb, true, level, (InternalNode) node);
            branchToString(sb, false, level, (InternalNode) node);
        }
    }

    /**
     * Recursively produces the string representation of a branch in the tree.
     */
    private void branchToString(StringBuffer sb, boolean left, int level, InternalNode node) {
        sb.append("\n");
        for (int j = 0; j < level; j++) { sb.append("|   "); }
        sb.append(node.splitter.toString(left, getNumDecimalPlaces()));
        toString(sb, level + 1, left ? node.leftSuccessor : node.rightSuccessor);
    }
    
    /**
     * Returns the size of the tree as a double value.
     */
    public double measureTreeSize() {
	return treeSize;
    }

    /**
     * Returns an enumeration of the "additional measures" recorded in WEKA experiments.
     */
    public Enumeration<String> enumerateMeasures() {
	Vector<String> newVector = new Vector<String>(1);
	newVector.addElement("measureTreeSize");
	return newVector.elements();
    }
    
    /**
     * Returns the value of the named measured.
     */
    public double getMeasure(String additionalMeasureName) {
	if (additionalMeasureName.compareToIgnoreCase("measureTreeSize") == 0) {
	    return measureTreeSize();
	} else {
	    throw new IllegalArgumentException(additionalMeasureName + " not supported");
	}
    }

    /**
     * The main method for running this classifier from a command-line interface.
     */
    public static void main(String[] options) {
        runClassifier(new ClassificationTree(), options);
    }
}
