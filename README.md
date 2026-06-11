# AI-based Intelligent Network Monitoring System

This project is an AI-powered system designed to monitor network traffic and detect potential security threats in real-time. It leverages machine learning algorithms to analyze network packets and identify anomalies.

## Key Features
- Threat Detection: Uses Random Forest and Isolation Forest algorithms.
- Efficiency: Achieved an 8.3ms response time for automated security responses.
- Dataset: Trained and validated using the CIC-IDS2017 dataset.

## How it Works
The system monitors incoming network traffic in real-time. It analyzes packets using the Random Forest and Isolation Forest algorithms to distinguish between normal traffic and potential threats. The system provides automated security responses with an optimized response time of 8.3ms.

## Dataset
The project relies on the CIC-IDS2017 dataset. Due to its large size, it is not included in this repository. 
To run the project, please download the dataset from [Official CIC-IDS2017 Website](https://www.unb.ca/cic/datasets/ids-2017.html) and place the files inside the data/ folder in the project directory.

## Project Dashboard
![Project Dashboard](dashboard.png)

## Prerequisites
- Python 3.12
- Libraries: numpy, pandas, scikit-learn

## How to Run
1. Clone the repository:
   git clone [https://github.com/Hala-saud/AI-Network-Monitoring] 
2. Create a virtual environment and install dependencies:
   pip install -r requirements.txt
3. Run the main script:
   python main.py
