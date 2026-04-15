import socket
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn_extensions.extreme_learning_machines.elm import GenELMClassifier
from sklearn_extensions.extreme_learning_machines.random_layer import RBFRandomLayer, MLPRandomLayer
import numpy as np
import pandas as pd


def prediction(X_test, cls):
    y_pred = cls.predict(X_test)
    for i in range(len(X_test)):
        print('')
    # print("X=%s, Predicted=%s" % (X_test[i], y_pred[i]))
    return y_pred


# Function to calculate accuracy
def cal_accuracy(y_test, y_pred, details):
    output = ''
    cm = confusion_matrix(y_test, y_pred)
    accuracy = accuracy_score(y_test, y_pred) * 100
    output += details + "\n"
    output += "Accuracy : " + str(accuracy) + "\n\n"
    output += "Report : " + str(classification_report(y_test, y_pred)) + "\n"
    output += "Confusion Matrix : " + str(cm) + "\n\n\n"
    return output


balance_data = pd.read_csv("clean.txt")
X = balance_data.values[:, 0:37]
Y = balance_data.values[:, 38]
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=0)
srhl_tanh = MLPRandomLayer(n_hidden=8, activation_func='tanh')
cls = GenELMClassifier(hidden_layer=srhl_tanh)
cls.fit(X_train, y_train)
prediction_data = prediction(X_test, cls)
output = cal_accuracy(y_test, prediction_data,
                      'Extreme Machine Learning Algorithm Accuracy, Classification Report & Confusion Matrix')

s = socket.socket()
port = 4444
s.bind(('', port))
s.listen(5)
print("Distributed Server Started")
while True:
    conn, address = s.accept()
    data = conn.recv(1024).decode()
    if not data:
        break
    print("from connected user: " + str(data))
    conn.send(output.encode())  # send data to the client

    # conn.close()  # close the connection
