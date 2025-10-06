# Bivariate Splits in Classification Trees: Implementation and Performance Analysis

## 📌 Overview

This project implements and evaluates **circular bivariate splits** in classification trees, comparing their performance against traditional univariate splits. The goal is to explore whether considering two attributes simultaneously during splitting can lead to more flexible decision boundaries and more compact trees, while maintaining or improving classification accuracy.

---

## 🧠 Introduction

Traditional decision trees use univariate splits, which are highly interpretable but may fail to capture complex relationships between attributes. This project investigates **bivariate splitting**, where splits are based on two attributes at once, using a **circular split rule** defined by a center point and radius.

Key contributions:
- Implementation of circular bivariate splits in Python
- Optimization using feature selection to reduce computational cost
- Comprehensive evaluation on 16 datasets using WEKA's Experimenter

---

## 🛠 Method

### Circular Bivariate Splits

Each split is defined by a circle in the 2D space of an attribute pair:
- **Center**: an instance's coordinates in the two attributes
- **Radius**: half the distance between adjacent sorted distances from the center
- **Left branch**: instances outside the circle
- **Right branch**: instances inside the circle

The split is chosen to maximize **information gain**:

<img src="https://latex.codecogs.com/svg.latex?IG(S,A)=H(S)-\sum_{v\in\text{Values}(A)}\frac{|S_v|}{|S|}H(S_v)" alt="Information Gain Formula" />

Where:
- $H(S)$ is the entropy of set $S$
- $S_v$ represents the subset of instances for value $v$ of attribute $A$
- $|S|$ is the total number of instances
- The sum is over all possible values of attribute $A$

where the sum is over all values v of attribute A.

### Feature Selection Optimization

To reduce the O(n²) complexity of evaluating all attribute pairs, we:
1. Rank attributes by their best univariate information gain
2. Select the top-k attributes
3. Only consider bivariate splits among these k attributes

This reduces the search space to O(k²), making the method scalable.

### Implementation Details
- Uses **Numba** for JIT compilation to speed up split evaluation
- Maintains class count arrays for efficient entropy calculation
- Integrates with WEKA for cross-validation and statistical testing

---

## 📊 Experimental Results

### Classification Accuracy

| Dataset | Univariate | Bivariate (All) | Bivariate (Top-k) |
|------|------------|-----------------|-------------------|
| balance-scale.arff | 77.30 | **89.07** ✓ | **88.86** ✓ |
| ecoli.arff | **81.94** | 78.10 | 78.02 |
| glass.arff | 67.18 | 68.69 | **69.29** |
| ionosphere.arff | 88.44 | 89.46 | **90.06** |
| iris.arff | 93.27 | **95.33** | 94.87 |
| wine.arff | 89.82 | **93.75** | 92.75 |
| ...  | | | |

- **✓**: statistically significant improvement over baseline (p < 0.05)
- Bivariate splits often match or exceed univariate performance

### Tree Size Comparison

| Dataset | Univariate | Bivariate (All) | Bivariate (Top-k) |
|------|------------|-----------------|-------------------|
| balance-scale.arff | 259 | 113 | 113 |
| iris.arff | 39 | 11 | 11 |
| heart-statlog.arff | 127 | 43 | 43 |
| yeast.arff | 1129 | 571 | 567 |
| ...  | | | |

- Bivariate splits consistently produce **smaller trees** (50–80% fewer nodes)

### Computational Efficiency
- Feature selection reduces time complexity from O(n²) to O(k²)
- Makes bivariate splits feasible for high-dimensional datasets

---

## ✅ Conclusions

- ✅ Bivariate splits produce **more compact trees** across all datasets
- ✅ Accuracy is **competitive or better** on many datasets
- ✅ Feature selection makes the method **computationally practical**
- ⚠️ Not universally better — best suited for datasets with complex feature interactions

Bivariate splits are a **specialized tool** for scenarios where model compactness is important and data exhibits multi-attribute interactions.

---

## 📚 References

1. Arai, S., Shirakawa, S., & Nagao, T. (2024). *Binn-DT: Towards Better Interpretability of Multidimensional Decision Rules via Bivariate Non-Linear Node Decision Trees*. IEEE SMC.
2. Witten, I. H., Frank, E., & Hall, M. A. (2011). *Data Mining: Practical Machine Learning Tools and Techniques*. Morgan Kaufmann.

---

## 📁 Repository Structure

```
├── src/                    # Source code
├── data/                   # Datasets (ARFF format)
├── results/                # Experimental results
├── README.md               # This file
└── requirements.txt        # Python dependencies
```

---

## 🚀 Getting Started

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Experiments
```bash
./weka.ps1
```


---

> 🔍 *This project was implemented and evaluated as part of a machine learning assignment focusing on advanced decision tree splitting strategies.*
