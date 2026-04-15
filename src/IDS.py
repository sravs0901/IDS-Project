
from tkinter import *
import tkinter
from tkinter.filedialog import askopenfilename
import numpy as np
import pandas as pd
from tkinter import simpledialog
from tkinter import filedialog
from sklearn.model_selection import train_test_split
from tkinter import messagebox
from sklearn import *
from imutils import paths
import matplotlib.pyplot as plt

from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from keras.models import Sequential
from keras.layers import Dense
from sklearn_extensions.extreme_learning_machines.elm import GenELMClassifier
from sklearn_extensions.extreme_learning_machines.random_layer import RBFRandomLayer, MLPRandomLayer
from sklearn.feature_selection import SelectFromModel
from sklearn.linear_model import Lasso
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
import socket
import time


main = tkinter.Tk()
main.title("intrusion Detection")
main.geometry("1300x1200")
global filename
global labels
global columns
global balance_data
global data
global X, Y, X_train, X_test, y_train, y_test
global svm_acc, random_acc, dnn_acc, elm_acc
global normal_time
global parallel_time
def isfloat(value):
    try:
        float(value)
        return True
    except ValueError:
        return False
def importdata():
    global balance_data
    balance_data = pd.read_csv("clean.txt")
    return balance_data


def splitdataset(balance_data):
    X = balance_data.values[:, 0:37]
    Y = balance_data.values[:, 38]
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=0)
    return X, Y, X_train, X_test, y_train, y_test
def upload():
    global filename
    text.delete('1.0', END)
    filename = askopenfilename(initialdir="dataset")
    pathlabel.config(text=filename)
    text.insert(END, "Dataset loaded\n\n")
def preprocess():
    global labels
    global columns
    global filename

    text.delete('1.0', END)
    columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment",
               "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted",
               "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
               "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
               "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
               "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
               "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
               "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

    labels = {"normal": 0, "neptune": 1, "warezclient": 2, "ipsweep": 3, "portsweep": 4, "teardrop": 5, "nmap": 6,
              "satan": 7, "smurf": 8, "pod": 9, "back": 10, "guess_passwd": 11, "ftp_write": 12, "multihop": 13,
              "rootkit": 14, "buffer_overflow": 15, "imap": 16, "warezmaster": 17, "phf": 18, "land": 19,
              "loadmodule": 20, "spy": 21, "perl": 22, "saint": 23, "mscan": 24, "apache2": 25, "snmpgetattack": 26,
              "processtable": 27, "httptunnel": 28, "ps": 29, "snmpguess": 30, "mailbomb": 31, "named": 32,
              "sendmail": 33, "xterm": 34, "worm": 35, "xlock": 36, "xsnoop": 37, "sqlattack": 38, "udpstorm": 39}
    balance_data = pd.read_csv(filename)
    dataset = ''
    index = 0
    cols = ''
    for index, row in balance_data.iterrows():
        for i in range(0, 42):
            if (isfloat(row[i])):
                dataset += str(row[i]) + ','
                if index == 0:
                    cols += columns[i] + ','
        dataset += str(labels.get(row[41]))
        if index == 0:
            cols += 'Label'
        dataset += '\n'
        index = 1;

    f = open("clean.txt", "w")
    f.write(cols + "\n" + dataset)
    f.close()

    text.insert(END, "Removed non numeric characters from dataset and saved inside clean.txt file\n\n")
    text.insert(END, "Dataset Information\n\n")
    text.insert(END, dataset + "\n\n")

def generateModel():
    global data
    global X, Y, X_train, X_test, y_train, y_test
    data = importdata()
    X, Y, X_train, X_test, y_train, y_test = splitdataset(data)
    text.delete('1.0', END)
    text.insert(END, "Training model generated\n\n")


def prediction(X_test, cls):
    y_pred = cls.predict(X_test)
    for i in range(len(X_test)):
        print("X=%s, Predicted=%s" % (X_test[i], y_pred[i]))
    return y_pred


# Function to calculate accuracy
def cal_accuracy(y_test, y_pred, details):

    accuracy = accuracy_score(y_test, y_pred) * 100
    text.insert(END, details + "\n\n")

    text.insert(END, "Accuracy : " + str(accuracy) + "\n\n")



    return accuracy


def runSVM():
    global svm_acc
    global X, Y, X_train, X_test, y_train, y_test
    text.delete('1.0', END)
    cls = svm.SVC(C=2.0, gamma='scale', kernel='rbf', random_state=2)
    cls.fit(X_train, y_train)
    text.insert(END, "Prediction Results\n\n")
    prediction_data = prediction(X_test, cls)
    svm_acc = cal_accuracy(y_test, prediction_data, 'SVM Accuracy')


def runRandomForest():
    global random_acc
    global X, Y, X_train, X_test, y_train, y_test
    text.delete('1.0', END)
    cls = RandomForestClassifier(n_estimators=10, max_depth=0.9, random_state=None)
    cls.fit(X_train, y_train)
    text.insert(END, "Prediction Results\n\n")
    prediction_data = prediction(X_test, cls)
    random_acc = cal_accuracy(y_test, prediction_data,
                              'Random Forest Algorithm Accuracy')


def runDNN():
    global dnn_acc
    text.delete('1.0', END)
    model = Sequential()
    model.add(Dense(12, input_dim=37, activation='relu'))
    model.add(Dense(37, activation='relu'))
    model.add(Dense(1, activation='softmax'))
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(X_train, y_train, epochs=100, batch_size=64)
    _, dnn_acc = model.evaluate(X_train, y_train)
    dnn_acc = dnn_acc * 100
    text.insert(END, "Prediction Results\n")

    text.insert(END, "DNN Accuracy : " + str(dnn_acc) + "\n\n")

def runELM():
    start_time = time.time()
    global elm_acc
    global normal_time
    global X, Y, X_train, X_test, y_train, y_test
    text.delete('1.0', END)
    srhl_tanh = MLPRandomLayer(n_hidden=8, activation_func='tanh')
    cls = GenELMClassifier(hidden_layer=srhl_tanh)
    cls.fit(X_train, y_train)
    text.insert(END, "Prediction Results\n")
    prediction_data = prediction(X_test, cls)
    elm_acc = cal_accuracy(y_test, prediction_data,
                           'Extreme Machine Learning Algorithm Accuracy')
    end_time = time.time()
    normal_time = end_time - start_time
    text.insert(END, 'Normal Execution Time : ' + str(normal_time) + "\n\n\n\n\n\n\n\n\n\n")
def parallel():
    global parallel_time
    text.delete('1.0', END)
    start_time = time.time()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 4444))
    client.send('request'.encode())  # send message
    data = client.recv(1024).decode()  # receive response
    text.insert(END, 'Output From Parallel Processor\n')
    text.insert(END, str(data))
    end_time = time.time()
    parallel_time = end_time - start_time
    text.insert(END, '\nParallel Execution Time : ' + str(parallel_time) + "\n\n\n\n\n\n\n\n\n\n")
def graph():
    height = [svm_acc, random_acc, dnn_acc, elm_acc]
    bars = ('SVM Acc', 'Random Forest Acc', 'DNN Acc', 'ELM Acc')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()


def parallelChart():
    height = [normal_time, parallel_time]
    bars = ('Normal Processing Time', 'Parallel Processing Time')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()


font = ('times', 18, 'bold')
title = Label(main, text='DL-IDF Deep learning based intrusion Detection Frame work in industrial internet of things')
title.config(bg='purple', fg='white')
title.config(font=font)
title.config(height=3, width=120)
title.place(x=0, y=3)

pathlabel = Label(main)
pathlabel.config(bg='brown', fg='white')
pathlabel.config(font=font)
pathlabel.place(x=600,y=150)


font1 = ('times', 14, 'bold')
upload = Button(main, text="Upload NSL KDD Dataset", command=upload)
upload.place(x=50, y=100)
upload.config(bg='black', fg='white')
upload.config(font=font1)

preprocess = Button(main, text="Preprocess Dataset", command=preprocess)
preprocess.place(x=50, y=150)
preprocess.config(bg='black', fg='white')
preprocess.config(font=font1)

model = Button(main, text="Generate Training Model", command=generateModel)
model.place(x=50, y=200)
model.config(bg='black', fg='white')
model.config(font=font1)

runsvm = Button(main, text="Run SVM Algorithm", command=runSVM)
runsvm.place(x=50, y=250)
runsvm.config(bg='black', fg='white')
runsvm.config(font=font1)

runrandomforest = Button(main, text="Run Random Forest Algorithm", command=runRandomForest)
runrandomforest.place(x=50, y=300)
runrandomforest.config(bg='black', fg='white')
runrandomforest.config(font=font1)

rundnn = Button(main, text="Run DNN Algorithm", command=runDNN)
rundnn.place(x=50, y=350)
rundnn.config(bg='black', fg='white')
rundnn.config(font=font1)

runeml = Button(main, text="Run Extreme  Learning Machine", command=runELM)
runeml.place(x=50, y=400)
runeml.config(bg='black', fg='white')
runeml.config(font=font1)


graph = Button(main, text="Accuracy Graph", command=graph)
graph.place(x=50, y=450)
graph.config(bg='black', fg='white')
graph.config(font=font1)

runparallel = Button(main, text="Run Parallel Processing", command=parallel)
runparallel.place(x=50,y=500)
runparallel.config(bg='black', fg='white')
runparallel.config(font=font1)


parallelgraph = Button(main, text="Parallel Time Graph", command=parallelChart)
parallelgraph.place(x=50, y=550)
parallelgraph.config(bg='black', fg='white')
parallelgraph.config(font=font1)

font1 = ('times', 14, 'bold')
text = Text(main, height=40, width=150)
scroll = Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.config(bg='black', fg='white')
text.place(x=350, y=100)
text.config(font=font1)

main.config(bg='gray')
main.mainloop()
