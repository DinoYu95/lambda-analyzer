package weka.classifiers.trees;

import weka.core.*;
import java.util.Arrays;
import java.util.Collections;

/**
 * A splitter for using the best infogain-based univariate split on numeric attributes.
 */
public class UnivariateNumericAttributeSplitter extends Splitter {
    
    /** The natural logarithm of 2 */
    public static final double log2 = Math.log(2);

    /** The attribute that will be used for splitting */
    private Attribute attribute;

    /** The split point on the attribute */
    private double splitPoint;

    /** The split quality: the information gain */
    private double splitQuality;
    
    /**
     * Finding the best univariate split across attributes using information gain.
     */
    public void findSplit(Instances data) {
	int[] initialCounts = new int[data.numClasses()];
        for (Instance instance : data) {
	    initialCounts[(int)instance.classValue()]++;
	}
        for (Attribute attribute : Collections.list(data.enumerateAttributes())) {
            findBestSplitPoint(data, attribute, initialCounts);
        }
    }

    /**
     * Decides whether the given instance belongs to the first branch or not.
     */
    public boolean firstSubset(Instance instance) {
	return (instance.value(attribute) < splitPoint);
    }

    /**
     * Returns the information gain of the best split found.
     */
    public double splitQuality() {
	return splitQuality;
    }

    /**
     * Returns a string representation of the condition for a branch.
     */
    public String toString(boolean leftBranch, int decimalPlaces) {
        return attribute.name() + (leftBranch ? " < " : " >= ") +
	    String.format("%." + decimalPlaces + "f", splitPoint); 
    }
    
    /**
     * Finds the best split point for the given attribute
     */
    private void findBestSplitPoint(Instances data, Attribute currentAttribute, int[] initialCounts) {
        int[] countsLeft = Arrays.copyOf(initialCounts,data.numClasses());
        int[] countsRight = new int[data.numClasses()];
        double previousValue = Double.NEGATIVE_INFINITY;
	data.sort(currentAttribute);
        for (Instance instance : data) {
            if (instance.value(currentAttribute) > previousValue) {
                double currentSplitQuality = informationGain(countsLeft, countsRight);
                if (currentSplitQuality > splitQuality) {
                    splitQuality = currentSplitQuality;
                    splitPoint = (instance.value(currentAttribute) + previousValue) / 2.0;
		    attribute = currentAttribute;
                }
                previousValue = instance.value(currentAttribute);
            }
	    countsLeft[(int)instance.classValue()]--;
	    countsRight[(int)instance.classValue()]++;
        }
    }
    
    /**
     * Helper method for computing entropy.
     */
    public static double lnFunc(int num){
        return (num <= 0) ? 0 : num * Math.log(num);
    }
    
    /**
     * Computes the base-2 information gain for the given array of counts.
     */
    public static double informationGain(int[] leftCounts, int[] rightCounts) {
	double sumOfNLogNLeft = 0, sumOfNLogNRight = 0, sumOfNLogNTotal = 0;
	int sumLeft = 0, sumRight = 0, sumTotal = 0;
	for (int i = 0; i < leftCounts.length; i++) {
	    sumOfNLogNLeft -= lnFunc(leftCounts[i]);
	    sumLeft += leftCounts[i];
	    sumOfNLogNRight -= lnFunc(rightCounts[i]);
	    sumRight += rightCounts[i];
	    sumOfNLogNTotal -= lnFunc(leftCounts[i] + rightCounts[i]);
	}
	sumTotal = sumLeft + sumRight;
        return (sumTotal <= 0) ? 0 :
	    (sumOfNLogNTotal + lnFunc(sumTotal) -
	     (sumOfNLogNLeft + lnFunc(sumLeft) + sumOfNLogNRight + lnFunc(sumRight))) /
	    (sumTotal * log2);
    }
}
