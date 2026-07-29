import urllib.request

try:
    r = urllib.request.urlopen("http://localhost:5000/api/health", timeout=5)
    print("Health check:", r.getcode())
except Exception as e:
    print("Health check failed:", e)
