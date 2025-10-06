package weka.classifiers.trees;

import weka.core.*;
import java.util.Arrays;
import java.util.Collections;

/**
 * A splitter for using the best infogain-based bivariate split on numeric attributes.
 */
public class BivariateNumericAttributeSplitter extends Splitter {
    
    /** The natural logarithm of 2 */
    public static final double log2 = Math.log(2);

    /** The first attribute that will be used for splitting */
    private Attribute attX1;

    /** The second attribute that will be used for splitting */
    private Attribute attX2;
    
    /** The first coordinate for the split */
    private double x1;
    
    /** The second coordinate for the split */
    private double x2;
    
    /** The radius for the split */
    private double r;

    /** The split quality: the information gain */
    private double splitQuality;
    
    /**
     * Finds the best bivariate split across attributes using information gain.
     */
    public void findSplit(Instances data) {

	// TO BE IMPLEMENTED BY YOU
    }

    /**
     * Decides whether the given instance belongs to the first branch or not.
     */
    public boolean firstSubset(Instance instance) {

	// TO BE IMPLEMENTED BY YOU
	return false;
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
        return "Attributes: " + attX1.name() + "," + attX2.name() +
	    (leftBranch ? " inside " : " outside ") + "circle with center (" +
	    String.format("%." + decimalPlaces + "f", x1) + "," +
	    String.format("%." + decimalPlaces + "f", x2) + ") and radius " +
	    String.format("%." + decimalPlaces + "f", r); 
    }
    
    /**
     * Finds the best circular split based on the given data and attributes.
     */
    private void findBestSplit(Instances data, Attribute a1, Attribute a2, int[] initialCounts) {

	// TO BE COMPLETED BY YOU
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
