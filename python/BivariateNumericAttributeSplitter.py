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
def find_best_split_for_solution1(attr_values, y, initial_counts):
    best_gain = -1.0
    best_x1, best_x2, best_r = 0.0, 0.0, 0.0
    num_classes = initial_counts.shape[0]
    n = attr_values.shape[0]

    for i in range(n):
        for j in range(i + 1, n):  # pick two points to define a circle
            x1_i, x2_i = attr_values[i, 0], attr_values[i, 1]
            x1_j, x2_j = attr_values[j, 0], attr_values[j, 1]
            # center = midpoint
            center_x = (x1_i + x1_j) / 2
            center_y = (x2_i + x2_j) / 2
            # radius = distance to one of the points
            radius = np.sqrt((x1_i - center_x) ** 2 + (x2_i - center_y) ** 2)

            left_counts = np.zeros(num_classes)
            right_counts = np.copy(initial_counts)

            for k in range(n):
                x1_k, x2_k = attr_values[k, 0], attr_values[k, 1]
                dist = (x1_k - center_x) ** 2 + (x2_k - center_y) ** 2
                if dist <= radius ** 2:
                    cls = y[k]
                    left_counts[cls] += 1
                    right_counts[cls] -= 1

            gain = information_gain(left_counts, right_counts)
            if gain > best_gain:
                best_gain = gain
                best_x1, best_x2, best_r = center_x, center_y, radius

    return best_gain, best_x1, best_x2, best_r


@jit
def find_best_split_for_solution2(attr_values, y, initial_counts, num_radius_steps):
    if num_radius_steps is None:
        num_radius_steps = 100

    best_gain = -1.0
    best_x1, best_x2, best_r = 0.0, 0.0, 0.0
    num_classes = len(initial_counts)
    n = attr_values.shape[0]

    for center_idx in range(n):
        center_x, center_y = attr_values[center_idx]

        # Calculate the distance from all points to the center of the circle
        distances = np.zeros(n)
        for i in range(n):
            dx = attr_values[i, 0] - center_x
            dy = attr_values[i, 1] - center_y
            distances[i] = np.sqrt(dx * dx + dy * dy)

        # Sort the distance to construct a series of radii
        sorted_radii = np.sort(distances)
        step_size = max(1, n // num_radius_steps)
        for step in range(1, n, step_size):
            r = sorted_radii[step]

            left_counts = np.zeros(num_classes)
            right_counts = np.zeros(num_classes)

            for i in range(n):
                cls = y[i]
                if distances[i] <= r:
                    left_counts[cls] += 1
                else:
                    right_counts[cls] += 1

            gain = information_gain(left_counts, right_counts)
            if gain > best_gain:
                best_gain = gain
                best_x1, best_x2, best_r = center_x, center_y, r

    return best_gain, best_x1, best_x2, best_r


@jit
def find_best_split_for_solution3(attr_values, y, initial_counts, num_radius_steps, max_extra_centers):
    if num_radius_steps is None:
        num_radius_steps = 500

    if max_extra_centers is None:
        max_extra_centers = 1000

    best_gain = -1.0
    best_x1, best_x2, best_r = 0.0, 0.0, 0.0
    num_classes = initial_counts.shape[0]
    n = attr_values.shape[0]

    # All samples are used as circle centers.
    centers = list(attr_values)

    # Additionally we add some midpoints between samples of different classes.
    count = 0
    for i in range(n):
        for j in range(i + 1, n):
            if y[i] != y[j]:
                midpoint = (attr_values[i] + attr_values[j]) / 2
                centers.append(midpoint)
                count += 1
                if count >= max_extra_centers:
                    break
        if count >= max_extra_centers:
            break

    # Enumerate each circle center and sample over the radius
    for center_x, center_y in centers:
        distances = np.sqrt((attr_values[:, 0] - center_x) ** 2 +
                            (attr_values[:, 1] - center_y) ** 2)
        sorted_radii = np.sort(distances)
        step_size = max(1, n // num_radius_steps)

        for step in range(1, n, step_size):
            r = sorted_radii[step]
            left_counts = np.zeros(num_classes)
            right_counts = np.zeros(num_classes)

            for i in range(n):
                cls = y[i]
                if distances[i] <= r:
                    left_counts[cls] += 1
                else:
                    right_counts[cls] += 1

            gain = information_gain(left_counts, right_counts)
            if gain > best_gain:
                best_gain = gain
                best_x1, best_x2, best_r = center_x, center_y, r

    return best_gain, best_x1, best_x2, best_r

@jit
def find_best_split_for_solution4(attr_values, y, initial_counts, num_radius_steps):
    if num_radius_steps is None:
        num_radius_steps = 45

    best_gain = -1.0
    best_x1, best_x2, best_r = 0.0, 0.0, 0.0
    num_classes = initial_counts.shape[0]
    n = attr_values.shape[0]

    # All samples are used as circle centers.
    centers = list(attr_values)

    # Enumerate each circle center and sample over the radius
    for center_x, center_y in centers:
        distances = np.sqrt((attr_values[:, 0] - center_x) ** 2 +
                            (attr_values[:, 1] - center_y) ** 2)
        min_r = 0.0
        max_r = np.max(distances)  # Get the maximum distance from all sample points to the current circle center.

        radii = np.linspace(min_r, max_r, num_radius_steps + 2)[1:-1]  # Remove the endpoints (0 and the maximum value)

        for r in radii:
            left_counts = np.zeros(num_classes)
            right_counts = np.zeros(num_classes)

            for i in range(n):
                cls = y[i]
                if distances[i] <= r:
                    left_counts[cls] += 1
                else:
                    right_counts[cls] += 1

            gain = information_gain(left_counts, right_counts)
            if gain > best_gain:
                best_gain = gain
                best_x1, best_x2, best_r = center_x, center_y, r

    return best_gain, best_x1, best_x2, best_r


@jit
def evaluate_single_feature(X_col, y, num_classes):
    if len(np.unique(X_col)) <= 1:
        return 0.0

    sorted_indices = np.argsort(X_col)
    sorted_feature = X_col[sorted_indices]
    sorted_labels = y[sorted_indices]

    left_counts = np.zeros(num_classes)
    right_counts = np.bincount(sorted_labels, minlength=num_classes)

    best_gain = 0.0

    for i in range(len(X_col) - 1):
        label = sorted_labels[i]
        right_counts[label] -= 1
        left_counts[label] += 1

        if sorted_feature[i] == sorted_feature[i + 1]:
            continue

        gain = information_gain(left_counts, right_counts)
        if gain > best_gain:
            best_gain = gain

    return best_gain


def select_top_features(X, y, num_classes, top_k=5):
    n_features = X.shape[1]
    feature_scores = np.zeros(n_features)

    for i in range(n_features):
        feature_scores[i] = evaluate_single_feature(X[:, i], y, num_classes)

    top_indices = np.argsort(feature_scores)[::-1][:top_k]
    return top_indices, feature_scores[top_indices]

@jit
def find_best_split(attr_values, y, initial_counts):
    best_gain = -1.0
    best_x1, best_x2, best_r = 0.0, 0.0, 0.0
    num_classes = len(initial_counts)
    n = attr_values.shape[0]

    # Iterate over each point to use as the circle center
    for center_idx in range(n):
        center = attr_values[center_idx]

        # Compute distances from all points to the current center
        distances = np.sqrt(np.sum((attr_values - center) ** 2, axis=1))

        # Get sorted indices by distance and retrieve corresponding distances and labels
        sorted_indices = np.argsort(distances)
        sorted_distances = distances[sorted_indices]
        sorted_labels = y[sorted_indices]

        # Initialize class counts: all points are initially inside the circle
        left_counts = np.zeros(num_classes)  # points outside the circle

        # points inside the circle
        right_counts = np.bincount(sorted_labels, minlength=num_classes)

        # Gradually increase the radius by moving one point at a time to the outside
        for i in range(n - 1):
            label = sorted_labels[i]
            right_counts[label] -= 1
            left_counts[label] += 1

            # Skip if the next point has the same distance: same split, redundant
            if sorted_distances[i] == sorted_distances[i + 1]:
                continue

            # Compute the midpoint radius between two adjacent points
            rmin = sorted_distances[i]
            rmax = sorted_distances[i + 1]
            r = (rmin + rmax) / 2

            # Compute information gain for this split
            gain = information_gain(left_counts, right_counts)

            # Update best split if this one has higher gain
            if gain > best_gain:
                best_gain = gain
                best_x1, best_x2 = center[0], center[1]
                best_r = r

    return best_gain, best_x1, best_x2, best_r


class BivariateNumericAttributeSplitter(Splitter):
    def __init__(self, args):
        self.attribute1_index = None
        self.attribute2_index = None
        self.x1 = None
        self.x2 = None
        self.r = None
        self.split_point = None
        self.split_quality = 0.0
        self.num_classes = args["num_classes"]
        self.attribute_names = args.get("attributes")
        self.solution_number = args.get("solution_number")
        self.max_extra_centers = args.get("max_extra_centers")
        self.num_radius_steps = args.get("num_radius_steps")
        self.enable_evaluate_importance_of_single_attribute = args.get("enable_evaluate_importance_of_single_attribute")
        self.top_k_features = args.get("top_k_features")

    def find_split(self, X, y):
        n_features = X.shape[1]
        best_gain = -1.0

        if self.enable_evaluate_importance_of_single_attribute is True:
            # Evaluate importance of every single attribute
            top_features, feature_scores = select_top_features(X, y, self.num_classes, self.top_k_features)
            for i_idx, i in enumerate(top_features):
                for j in top_features[i_idx + 1:]:
                    best_gain = self._evaluate_feature_pair(X, y, i, j, best_gain)
        else:
            for i in range(n_features):
                for j in range(i + 1, n_features):
                    best_gain = self._evaluate_feature_pair(X, y, i, j, best_gain)

    def _evaluate_feature_pair(self, X, y, feature_idx1, feature_idx2, current_best_gain):
        attr_pair = X[:, [feature_idx1, feature_idx2]]
        counts = np.zeros(self.num_classes)
        for label in y:
            counts[label] += 1

        if self.solution_number == 1:
            gain, x1, x2, r = find_best_split_for_solution1(attr_pair, y, counts)
        elif self.solution_number == 2:
            gain, x1, x2, r = find_best_split_for_solution2(attr_pair, y, counts,
                                                            num_radius_steps=self.num_radius_steps)
        elif self.solution_number == 3:
            gain, x1, x2, r = find_best_split_for_solution3(attr_pair, y, counts,
                                                            num_radius_steps=self.num_radius_steps,
                                                            max_extra_centers=self.max_extra_centers)
        elif self.solution_number == 4:
            gain, x1, x2, r = find_best_split_for_solution4(attr_pair, y, counts,
                                                            num_radius_steps=self.num_radius_steps)
        else:
            gain, x1, x2, r = find_best_split(attr_pair, y, counts)

        if gain > current_best_gain:
            self.attribute1_index = feature_idx1
            self.attribute2_index = feature_idx2
            self.x1 = x1
            self.x2 = x2
            self.r = r
            self.split_quality = gain
            return gain

        return current_best_gain

    def first_subset(self, x):
        val1 = x[self.attribute1_index]
        val2 = x[self.attribute2_index]
        dist = (val1 - self.x1) ** 2 + (val2 - self.x2) ** 2
        return dist > self.r ** 2

    def split_quality(self):
        return self.split_quality

    def __str__(self, left_branch, decimal_places):
        if self.attribute_names is not None:
            attr1_name = self.attribute_names[self.attribute1_index]
            attr2_name = self.attribute_names[self.attribute2_index]
        else:
            attr1_name = f"x[{self.attribute1_index}]"
            attr2_name = f"x[{self.attribute2_index}]"
        op = "inside" if left_branch else "outside"
        return "Attributes: " + attr1_name + "," + attr2_name + \
            op + "circle with center (" + \
            f"{attr1_name} {op} {self.x1:.{decimal_places}f}" + "," + \
            f"{attr2_name} {op} {self.x2:.{decimal_places}f}" + ") and radius " + \
            f"{self.r:.{decimal_places}f}"
