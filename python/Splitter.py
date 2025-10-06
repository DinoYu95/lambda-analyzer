from abc import ABC, abstractmethod

class Splitter(ABC):
    """
    Abstract base class for a data splitter.
    """

    @abstractmethod
    def find_split(self, X, y, args):
        """
        Finds the best split given the training data.
        Parameters:
            X (np.ndarray): Feature matrix of shape (n_samples, n_features)
            y (np.ndarray): Label vector of shape (n_samples,)
            args: Dictionary with possible arguments
        """
        pass

    @abstractmethod
    def first_subset(self, x):
        """
        Determines if a given instance x belongs to the left (first) subset.
        Parameters:
            x (np.ndarray): Feature vector of shape (n_features,)
        Returns:
            bool: True if instance belongs to left branch, False otherwise
        """
        pass

    @abstractmethod
    def split_quality(self):
        """
        Returns a numeric score for the quality of the current split.
        Returns:
            float
        """
        pass

    @abstractmethod
    def __str__(self, left_branch, decimal_places):
        """
        Returns a string representation of the split condition.
        """
        pass
