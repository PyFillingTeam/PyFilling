#!/usr/bin/python

import pandas as pd
import numpy as np
from statsmodels.tsa.arima_model import ARIMA
from sklearn.metrics import mean_squared_error
import warnings
warnings.simplefilter("ignore")

def get_data(start):
    #iterate through protocols
    protocols = ['dns', 'http', 'https', 'icmp', 'ntp', 'pop']

    max = 0
    for protocol in protocols:
        try:
            data = pd.read_csv('packets_' + protocol + '.csv', names=['Time','Size','Buckets'])
            data = data.astype(int)
            #count the number of packets in each second
            data = data['Time'].value_counts()
            #sort by seconds
            data = data.sort_index()
            #fill missing seconds
            data = data.reindex(pd.RangeIndex(data.index.max() + 1)).fillna(0)
            
            a = []
            a = np.array(a, int)
            index = 1
            sum = 0
            
            #aggregate seconds into minutes
            for i in data:
                if index%60 == 0:
                    a = np.append(a, sum)
                    index = 1
                    sum = 0
                else:
                    index += 1
                    sum += i
                    
            #add the remaining seconds into a last minute
            a = np.append(a, sum)
            
            #switch protocols if new sum is higher, indicating more activity
            all_sum = a[start:start+180].sum()
            if all_sum > max:
                max = all_sum
                seconds, minutes = data, a
                proto = protocol
                print(protocol)
        except:
            continue
    
    return seconds, minutes, proto
    
def optimum(current_time):
    
    
    """ sample code for generating graphs
    >>> model = ARIMA(monday, order=(7,0,1))
    >>> model_fit = model.fit(disp=0)
    >>> forecast = model_fit.predict(start=0, end=1440)

    forecast = ARIMA(hour, order=(7,0,1)).fit(disp=0).predict(start=0,end=60)

    forecast = ARIMA(halfh, order=(7,0,1)).fit(disp=0).predict(start=0,end=60)

    """
    
    #convert time to minutes and generate the first window to end 5 minutes from current time
    start = int((current_time + 300)/60) + 1
    seconds, minutes, protocol = get_data(start)
    left = start - 29
    right = start + 1
    t_forecast =[]
    
    #generate rolling ARIMA
    for k in range(36):
        print(k)
        window = minutes[left+k*5:right+k*5]
        windows = pd.Series(window)
        p = 1
        max = windows.autocorr(p)
        #find optimum p value
        for i in range(2, 10):
            ar = windows.autocorr(i)
            if ar > max:
                max = ar
                p = i
        
        q = 0
        model = ARIMA(window, order=(p,0,q))
        try:
            model_fit = model.fit(disp=0)
        except:
            t_forecast = np.append(t_forecast, np.array([0,0,0,0,0]))
            continue
            
        prediction = model_fit.predict(start=0,end=29)
        error = mean_squared_error(window,prediction)
        #find optimum q value
        for i in range(1,5):
            try:
                model = ARIMA(window, order=(p,0,i))
                model_fit = model.fit(disp=0)
                prediction = model_fit.predict(start=0,end=29)
                e = mean_squared_error(window,prediction)
                if e < error:
                    q = i
            except:
                break
        
        #generate forecast for next 5 minutes
        forecast = ARIMA(window, order=(p,0,q)).fit(disp=0).predict(start=30,end=34)
        #append forecast
        t_forecast = np.append(t_forecast, forecast)

        print(forecast)
    
    t_forecast[t_forecast < 0] = 0
    
    max = 0
    optimal = 0
    #find optimal minute
    for index in range(t_forecast.size):
        if t_forecast[index] > max:
            max = t_forecast[index]
            optimal = index
    
    return ((start+optimal)*60), protocol