from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier


# clf = RandomForestClassifier(
# 	bootstrap=True, class_weight=None, criterion='gini',
# 	max_depth=17, max_features=10, max_leaf_nodes=None,
# 	min_impurity_decrease=0.0, 
# 	min_samples_leaf=3, min_samples_split=2,
# 	min_weight_fraction_leaf=0.0, n_estimators=50,
# 	n_jobs=None, oob_score=False, random_state=1, verbose=0,
# 	warm_start=False)

clf = RandomForestClassifier(n_estimators=50)

with open('train.csv', 'r') as file:
    lines_x = []
    lines_y = []
    headers = file.readline()
    for i in range(112872):
        r = file.readline().split(',')
        lines_x.append([float(r[i]) if r[i] != 'Infinity' and r[i] != 'NaN' else -1 for i in range(len(r)) if i not in [0, 1, 3, 6, 84]])
        lines_y.append(0 if 'BENIGN' in r[-1] else 1)
        
print('ok2')

clf.fit(lines_x, lines_y)

print('ok2')

with open('test.csv', 'r') as file:
    headers = file.readline()
    predict = []
    check = []
    lines = []
    for i in range(100):
        r = file.readline().split(',')
        check.append(r[-1][:-1])
        lines.append([float(r[i]) if r[i] != 'Infinity' and r[i] != 'NaN' else -1 for i in range(len(r)) if i not in [0, 1, 3, 6, 84]])

print('Реальный результат:', check)
print('Предположение НС:', clf.predict(lines))

with open('ddos.csv', 'r') as file:
    headers = file.readline()
    predict = []
    check = []
    lines = []
    for i in range(100):
        r = file.readline().split(',')
        check.append(r[-1][:-1])
        lines.append([float(r[i]) if r[i] != 'Infinity' and r[i] != 'NaN' else -1 for i in range(len(r)) if i not in [0, 1, 3, 6, 84]])

print('Реальный результат:', check)
print('Предположение НС:', clf.predict(lines))
