import requests

def get_public_info(service_name):
    """
    Fetches information from a public API. 
    This is for research purposes to understand the service.
    """
    url = f"https://api.example.com/search?query={service_name}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
        return {"error": "No data found"}
    except Exception as e:
        return {"error": str(e)}