import requests

dm_client=requests.get("https://www.googleapis.com/deploymentmanager/v2/projects/cparkar-project/global/deployments/cparkar-deployment")

print(requests.deployment)
