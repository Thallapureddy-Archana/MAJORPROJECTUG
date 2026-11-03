from flask import Flask, render_template, request
import numpy as np
#from tensorflow.python.eager import load_model
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
from flask import jsonify
# import keras
app = Flask(__name__)
# Load the trained model
model = load_model('my_model.h5')

# Initialize the MinMaxScaler
scaler = MinMaxScaler()

# List of feature names to ensure consistent order
feature_names = [
    'duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'is_host_login', 'is_guest_login', 'num_compromised', 'root_shell',
    'su_attempted', 'num_file_creations', 'num_shell', 'num_access_files',
    'num_outbound_cmds', 'count', 'srv_count', 'serror_rate', 'rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate'
]

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/submit', methods=['GET'])
def submit():
        data = {
            "duration": int(request.args.get('duration', 0)),
            "protocol_type": int(request.args.get('protocol_type', 0)),
            "flag": int(request.args.get('flag', 0)),
            "src_bytes": int(request.args.get('src_bytes', 0)),
            "dst_bytes": int(request.args.get('dst_bytes', 0)),
            "land": int(request.args.get('land', 0)),
            "wrong_fragment": int(request.args.get('wrong_fragment', 0)),
            "urgent": int(request.args.get('urgent', 0)),
            "hot": float(request.args.get('hot', 0)),
            "num_failed_logins": int(request.args.get('num_failed_logins', 0)),
            "logged_in": int(request.args.get('logged_in', 0)),
            "is_host_login": int(request.args.get('is_host_login', 0)),
            "is_guest_login": int(request.args.get('is_guest_login', 0)),
            "num_compromised": int(request.args.get('num_compromised', 0)),
            "root_shell": int(request.args.get('root_shell', 0)),
            "su_attempted": int(request.args.get('su_attempted', 0)),
            "num_file_creations": int(request.args.get('num_file_creations', 0)),
            "num_shell": int(request.args.get('num_shell', 0)),
            "num_access_files": int(request.args.get('num_access_files', 0)),
            "num_outbound_cmds": int(request.args.get('num_outbound_cmds', 0)),
            "count": int(request.args.get('count', 0)),
            "srv_count": int(request.args.get('srv_count', 0)),
            "serror_rate": float(request.args.get('serror_rate', 0)),
            "rerror_rate": float(request.args.get('rerror_rate', 0)),
            "same_srv_rate": float(request.args.get('same_srv_rate', 0)),
            "diff_srv_rate": float(request.args.get('diff_srv_rate', 0)),
            "srv_diff_host_rate": float(request.args.get('srv_diff_host_rate', 0)),
            "dst_host_count": int(request.args.get('dst_host_count', 0)),
            "dst_host_srv_count": int(request.args.get('dst_host_srv_count', 0)),
            "dst_host_diff_srv_rate": float(request.args.get('dst_host_diff_srv_rate', 0)),
            "dst_host_same_src_port_rate": float(request.args.get('dst_host_same_src_port_rate', 0)),
            "dst_host_srv_diff_host_rate": float(request.args.get('dst_host_srv_diff_host_rate', 0))
        }

        #return jsonify(data)
        # Convert the data to a NumPy array
        input_data = np.array([[
            float(data[name]) if data[name] is not None else 0 for name in feature_names
        ]])

        # Scale the data
        scaled_data = scaler.fit_transform(input_data)

        # Make prediction
        prediction = model.predict(scaled_data)

        # Convert prediction to a more readable format if needed
        prediction_result = prediction[0]  # Assuming it's a single prediction
        if (np.argmax(prediction[0])==0):  
            return render_template("dos.html")
        elif (np.argmax(prediction[0])==1):
            return render_template("normal.html")
        elif(np.argmax(prediction[0])==2):
            return render_template("probe.html" )  
        elif (np.argmax(prediction[0])==3):
            return render_template("remotelocal.html")
        elif (np.argmax(prediction[0])==4):
            return render_template("u2r.html")


if __name__ == '__main__':
    app.run(debug=True)
