Token Generator API

This API provides two endpoints for generating authentication tokens for the Free Fire game:





/guest: Authenticates using UID and password, then generates a token by trying multiple platform types.





URL: https://{name}.vercel.app/guest?uid={uid}&password={password}



Response: {"server": "region", "uid": "uid", "token": "token"}



/main: Generates a token using an access token by trying multiple platform types.





URL: https://{name}.vercel.app/main?access_token={access_token}



Response: {"server": "region", "uid": "uid", "token": "token"}

Platform Types

The API tries the following platform types to generate a valid token:





Apple (10)



Facebook (3)



Google (8)



Guest (4)



VK (5)



Huawei (7)



X (11)

Setup





Install dependencies: pip install -r requirements.txt



Deploy to Vercel or run locally: python main.py

Dependencies





Flask==2.3.3



requests==2.31.0



pycryptodome==3.20.0



protobuf==4.25.1



PyJWT==2.8.0

Deployment

To deploy on Vercel:





Create a new Vercel project and link it to your repository.



Push all files to the repository.



Vercel will automatically deploy the application based on the vercel.json configuration.