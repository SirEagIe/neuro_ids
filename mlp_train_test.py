from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
import time, sys
import pickle

X_train, Y_train = [], []
X_test, Y_test = [], []

filename1 = sys.argv[1]
filename2 = sys.argv[2]

with open(filename1, 'r') as f:
    for line in f.readlines():
        line = line.replace('Infinity', '-1').replace('NaN', '-1')
        if 'DDoS' in line.split(',')[-1]:
            X_train.append(list(map(float, line.split(',')[:-1])))
            Y_train.append('DDoS')
        elif 'PortScan' in line.split(',')[-1]:
            X_train.append(list(map(float, line.split(',')[:-1])))
            Y_train.append('PortScan')
        elif 'BENIGN' in line.split(',')[-1]:
            X_train.append(list(map(float, line.split(',')[:-1])))
            Y_train.append('BENIGN')
        elif 'DoSHulk' in line.split(',')[-1]:
            X_train.append(list(map(float, line.split(',')[:-1])))
            Y_train.append('DoSHulk')

with open(filename2, 'r') as f:
    for line in f.readlines():
        line = line.replace('Infinity', '-1').replace('NaN', '-1')
        if 'DDoS' in line.split(',')[-1]:
            X_test.append(list(map(float, line.split(',')[:-1])))
            Y_test.append('DDoS')
        elif 'PortScan' in line.split(',')[-1]:
            X_test.append(list(map(float, line.split(',')[:-1])))
            Y_test.append('PortScan')
        elif 'BENIGN' in line.split(',')[-1]:
            X_test.append(list(map(float, line.split(',')[:-1])))
            Y_test.append('BENIGN')
        elif 'DoSHulk' in line.split(',')[-1]:
            X_test.append(list(map(float, line.split(',')[:-1])))
            Y_test.append('DoSHulk')


clf = MLPClassifier(hidden_layer_sizes=(25,), learning_rate_init=0.001, learning_rate='adaptive', max_iter=200, n_iter_no_change=10, tol=0.0001, verbose=True)
# clf = MLPClassifier(hidden_layer_sizes=(25,))
# clf = DecisionTreeClassifier()

start_train = time.time()
clf.fit(X_train, Y_train)
end_train = time.time()

predict = clf.predict(X_test)
end_test = time.time()

# print('train:', end_train - start_train, '\ntest:', end_test - end_train)
print(f'{end_train - start_train}', end=' ')
print(f'{end_test - end_train}', end=' ')

from sklearn.metrics import classification_report
print("\n{}".format(classification_report(Y_test, predict)))
print(clf.loss_curve_)

with open('model.pkl', 'wb') as f:
    pickle.dump(clf, f)
