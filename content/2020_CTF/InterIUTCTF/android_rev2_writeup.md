## InterIUT CTF: reverse me 2 [android]
> description to be added later

## Firebase
#### This was a pretty fun challenge to learn about and solved. From the decompiled java code below, we can see that the application uses a firebase as the database for the application. 
![](rev2_jadx.png)

## What is firebase?
#### The Firebase Realtime Database is a cloud-hosted database. Data is stored as JSON and synchronized in realtime to every connected client. That being said, non-secure applications have a tendency to expose their firebase endpoints such as this app. 
#### We can simply retrieve the resources of the app using apktool and search for the firebase url in the strings.xml resource:
```
    <string name="default_web_client_id">203460543242-pshurnn90vb0kogc8u4n60af9msj15l6.apps.googleusercontent.com</string>
    <string name="ensibs_text">"ENSIBS' shareflag app"</string>
    <string name="firebase_database_url">https://reverse-me-2.firebaseio.com</string>
    <string name="gcm_defaultSenderId">203460543242</string>
    <string name="google_api_key">AIzaSyDOV5tbZVMIMo-WAZ5Y3rLJWFk-poBgKec</string>
    <string name="google_app_id">1:203460543242:android:a9df09f63861648defb0f3</string>
    <string name="google_crash_reporting_api_key">AIzaSyDOV5tbZVMIMo-WAZ5Y3rLJWFk-poBgKec</string>
    <string name="google_storage_bucket">reverse-me-2.appspot.com</string>
```
#### Next step is to navigate to the provided url, get the .json entry and read the flag. (The server is down as of this time of preparing the writeup, I will upload a screenshot of how the page looks when the servers are back up later this week. meanwhile here's a python script I used)

```python
import requests

firebase_url = 'https://reverse-me-2.firebaseio.com/.json'
r = requests.get(firebase_url)
print(r.text)
#: flag: H2G2{f1r3basE_iS_v3ry_s3cure}

#: References
#: https://book.hacktricks.xyz/pentesting/pentesting-web/buckets/firebase-database
#: https://stackoverflow.com/questions/42825567/how-to-get-google-service-json-file-in-decompile-apk/42826400
```