from UnivariateNumericAttributeSplitter import UnivariateNumericAttributeSplitter
from BivariateNumericAttributeSplitter import BivariateNumericAttributeSplitter

from sklearn.base import BaseEstimator, ClassifierMixin
import numpy as np

class ClassificationTree(BaseEstimator, ClassifierMixin):
    class LeafNode:
        def __init__(self, class_probs):
            self.class_probs = class_probs

    class InternalNode:
        def __init__(self, splitter, left, right):
            self.splitter = splitter
            self.left = left
            self.right = right

    def __init__(self, args = {}):
        self.root = None
        self.args = args

    def fit(self, X_train, y_train):
        y_train = np.round(y_train).astype(int)
        self.tree_size = 0
        info_gain_threshold = self.args.get("info_gain_threshold")
        info_gain_threshold = 1e-6 if info_gain_threshold is None else info_gain_threshold
        self.root = self._build_tree(X_train, y_train, info_gain_threshold)

    def _build_tree(self, X, y, info_gain_threshold):
        self.tree_size += 1
        if self.args.get("bivariate_split") is True:
            splitter = BivariateNumericAttributeSplitter(self.args)
        else:
            splitter = UnivariateNumericAttributeSplitter(self.args)
        splitter.find_split(X, y)

        if splitter.split_quality < info_gain_threshold:
            counts = np.bincount(y, minlength=self.args["num_classes"])
            probs = counts / np.sum(counts)
            return self.LeafNode(probs)
        else:
            mask = splitter.first_subset(np.transpose(X))
            left_X, left_y = X[mask], y[mask]
            right_X, right_y = X[~mask], y[~mask]
            return self.InternalNode(
                splitter,
                self._build_tree(left_X, left_y, info_gain_threshold),
                self._build_tree(right_X, right_y, info_gain_threshold)
            )

    def predict_proba(self, X):
        return np.array([self._predict_instance_proba(self.root, x) for x in X])

    def predict(self, X):
        proba = self.predict_proba(X)
        return np.argmax(proba, axis=1)

    def _predict_instance_proba(self, node, x):
        if isinstance(node, self.LeafNode):
            return node.class_probs
        elif node.splitter.first_subset(x):
            return self._predict_instance_proba(node.left, x)
        else:
            return self._predict_instance_proba(node.right, x)

    def __str__(self):
        if self.root is None:
            return "No model has been built yet."
        lines = []
        self._tree_to_str(self.root, lines, depth=0)
        lines.append(f"\n\nSize of the tree : {self.tree_size}")
        return "".join(lines)

    def _tree_to_str(self, node, lines, depth):
        indent = "|   " * depth
        if isinstance(node, self.LeafNode):
            probs_str = ", ".join(f"{p:.2f}" for p in node.class_probs)
            lines.append(f": {probs_str}")
        else:
            lines.append("\n" + indent + node.splitter.__str__(True, 2))
            self._tree_to_str(node.left, lines, depth + 1)
            lines.append("\n" + indent + node.splitter.__str__(False, 2))
            self._tree_to_str(node.right, lines, depth + 1)
