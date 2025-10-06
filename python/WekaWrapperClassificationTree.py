from ClassificationTree import ClassificationTree

from wekapyscript import ArffToArgs, uses

def train(args):
    X_train = args["X_train"]
    y_train = args["y_train"].flatten()
    classifier = ClassificationTree(args)
    classifier.fit(X_train, y_train)
    return classifier

def describe(args, model):
    return str(model)

def test(args, model):
    X_test = args["X_test"]
    return model.predict_proba(X_test).tolist()

if __name__ == '__main__':
    x = ArffToArgs()
    x.set_input("iris.arff")
    x.set_class_index("last")
    args = x.get_args()
    args["info_gain_threshold"] = 0.1
    args["bivariate_split"] = True
    classifier = train(args)
    print(describe(args, classifier))
    x.close()
