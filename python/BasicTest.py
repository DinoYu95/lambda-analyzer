from sklearn.datasets import load_iris
from ClassificationTree import ClassificationTree

data = load_iris()
X = data.data
y = data.target

tree = ClassificationTree({"num_classes" : 3})
tree.fit(X,y)
print(tree)
