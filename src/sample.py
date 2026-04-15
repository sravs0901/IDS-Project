def importdata():
    global balance_data
    balance_data = pd.read_csv("Users\HOME\Desktop\code\extension\IDS\clean.csv")
    # Printing the dataset shape
    print ("Dataset Lenght: ", len(balance_data))
    print ("Dataset Shape: ", balance_data.shape)
    # Printing the dataset obseravtions
    print ("Dataset: ",balance_data.head())
    return balance_data