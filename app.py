from flask import Flask, request, render_template
import pandas as pd
import numpy as np
import pickle

from feature import FeatureExtraction
import warnings
warnings.filterwarnings('ignore')

# declare constants
HOST = '0.0.0.0'
PORT = 8081

# initialize flask application
app = Flask(__name__)
model = pickle.load(open('model/modelRF.pkl','rb'))


@app.route("/", methods=["GET", "POST"])
def predict():
    
    if request.method == "POST":

        input_url = request.form["vurl"]
        obj = FeatureExtraction(input_url)
        url = np.array(obj.getFeaturesList()).reshape((1, -1)) 

        pred = model.predict(url)[0]

        if (pred) == 0:
            res="It's SAFE"
            prob = model.predict_proba(url)[0,0]
            prob_t = "{0:.2f} % ".format(prob*100)
            return render_template("index.html", prediction_text = res)

        elif (pred) == 1:
            res="Defacement"
            prob = model.predict_proba(url)[0,1]
            prob_t = "{0:.2f} % ".format(prob*100)
            return render_template("index.html", percentage = prob_t, prediction_text = res)


        elif (pred) == 2:
            res="Malware"
            prob = model.predict_proba(url)[0,2]
            prob_t = "{0:.2f} % ".format(prob*100)
            return render_template("index.html", percentage = prob_t, prediction_text = res)
            
        elif (pred) == 3:
            res="Phishing"
            prob = model.predict_proba(url)[0,3]
            prob_t = "{0:.2f} % ".format(prob*100)
            return render_template("index.html", percentage = prob_t, prediction_text = res)


        #return render_template("index.html", prediction_text = res , percentage = prob_t)
    
    return render_template("index.html")


if __name__ == '__main__':
    # run web server
    app.run(host=HOST,
            debug=True,  # automatic reloading enabled
            port=PORT)


