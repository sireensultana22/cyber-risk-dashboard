import requests

AI_SERVICE_URL = "http://localhost:5000/analyze"

def get_ai_analysis(scan_result):

    response = requests.post(
        AI_SERVICE_URL,
        json={
            "scan_data": scan_result
        }
    )

    return response.json()