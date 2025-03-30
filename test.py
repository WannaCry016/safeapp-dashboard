import requests

url = "http://127.0.0.1:8000/auth/login"  # Update path

data = {
    "username": "user1",
    "password": "user1_password123"
}

response = requests.post(url, json=data)

print("Status Code:", response.status_code)
print("Response:", response.json())  # Should return access_token if successful
