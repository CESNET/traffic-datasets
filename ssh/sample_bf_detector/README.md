# Processing tool
The tool was created to evaluate between novelty ML-based ssh bruteforce detector and traditional flow based NEMEA detector. The input is in csv format. The output are IP addresses with their label and malicious confidence obtained from abuse IPDB. 


### Usage
```
python detection_service.py "$ML-BASED-detector-output.csv" "$NEMEA-BF-detector-output.csv"
```

