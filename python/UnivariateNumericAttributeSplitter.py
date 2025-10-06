from Splitter import Splitter

from numba import jit
import numpy as np

@jit
def information_gain(left_counts, right_counts):
    total = left_counts + right_counts
    sum_total = np.sum(total)
    if sum_total == 0:
        return 0.0
    sum_left = np.sum(left_counts)
    if sum_left == 0:
        return 0.0
    sum_right = np.sum(right_counts)
    if sum_right == 0:
        return 0.0
    log2 = np.log(2)
    entropy_total = -np.nansum(total * np.log(total))
    entropy_left = -np.nansum(left_counts * np.log(left_counts))
    entropy_right = -np.nansum(right_counts * np.log(right_counts))
    return (entropy_total + sum_total * np.log(sum_total) -
            (entropy_left + sum_left * np.log(sum_left) +
             entropy_right + sum_right * np.log(sum_right))) / (sum_total * log2)

@jit
def find_best_split_point(attr_values, y, attr_idx, initial_counts):
    sorted_indices = np.argsort(attr_values)
    attr_values, y_sorted = attr_values[sorted_indices], y[sorted_indices]
    counts_left = initial_counts.copy()
    counts_right = np.zeros_like(counts_left)
    previous_value, split_quality, split_point, attribute_index = attr_values[0], 0, 0, -1
    for i in range(1, len(attr_values)):
        label = y_sorted[i]
        if attr_values[i] > previous_value:
            current_quality = information_gain(counts_left, counts_right)
            if current_quality > split_quality:
                split_quality, split_point, attribute_index = current_quality, (attr_values[i] + previous_value) / 2.0, attr_idx
            previous_value = attr_values[i]
        counts_left[label] -= 1
        counts_right[label] += 1
    return split_quality, split_point, attribute_index

class UnivariateNumericAttributeSplitter(Splitter):
    def __init__(self, args):
        self.attribute_index = None
        self.split_point = None
        self.split_quality = 0.0
        self.num_classes = args["num_classes"]
        self.attribute_names = args.get("attributes")

    def find_split(self, X, y):
        initial_counts = np.bincount(y, minlength=self.num_classes)
        for attr_idx in range(X.shape[1]):
            qual, point, att = find_best_split_point(X[:, attr_idx], y, attr_idx, initial_counts)
            if qual > self.split_quality:
                self.split_quality = qual
                self.split_point = point
                self.attribute_index = att

    def first_subset(self, x):
        return x[self.attribute_index] < self.split_point

    def split_quality(self):
        return self.split_quality

    def __str__(self, left_branch, decimal_places):
        if self.attribute_names is not None:
            attr_name = self.attribute_names[self.attribute_index]
        else:
            attr_name = f"x[{self.attribute_index}]"
        op = "<" if left_branch else ">="
        return f"{attr_name} {op} {self.split_point:.{decimal_places}f}"
