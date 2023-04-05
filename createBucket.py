import datetime
import hashlib
import hmac
import base64
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

compartmentId="<your compartmentid>"
#OCID of the tenancy calls are being made in to
tenancy_ocid="<your tenancy_ocid>"
# OCID of the user making the rest call
user_ocid = "<your user_ocid>"
ossnamespace = "<your OSS NAMESPACE>"
# path to the private PEM format key for this user
private_key_path = "/home/opc/.oci/privatekey.pem"

# fingerprint of the private key for this user
fingerprint = "<YOUR key fingerprint>"

# The REST api you want to call, with any required parameters.
rest_api = f"/n/{ossnamespace}/b"

# The host you want to make the call against
host = "objectstorage.ap-seoul-1.oraclecloud.com"


date11 = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
date_header = f"date: {date11}"
host_header = f"host: {host}"
request_target = f"(request-target): post {rest_api}"
# note the order of items. The order in the signing_string matches the order in the headers
headers = "(request-target) date host"


with open('./createBucketPayload', 'rb') as fp:
    payload = fp.read()
print(payload)

'''
payload=f'{\
  \"compartmentId\": \"{compartmentId}\",\
  \"namespace\": \"ansh8lvru1zp\",\
  \"objectEventsEnabled\": true,\
  \"name\": \"my-test-1\",\
  \"freeformTags\": {\"Department\": \"Finance\"},\
  \"definedTags\":\
  {\
    \"MyTags\":\
    {\
      \"CostCenter\": \"42\",\
      \"Project\": \"Stealth\",\
      \"CreatedBy\": \"BillSmith\",\
      \"CreatedDate\": \"9/21/2017T14:00\"\
    },\
    \"Audit\":\
    {\
      \"DataSensitivity\": \"PII\",\
      \"CageSecurity\": \"High\",\
      \"Simplicity\": \"complex\"\
    }\
  }\
}'
'''
with open(private_key_path, 'rb') as fr:pem_pri=fr.read()
new_key = serialization.load_pem_private_key(pem_pri, password=None, backend=default_backend())

h256obj = hashlib.sha256(payload)
content_sha256_binary= h256obj.digest()
content_sha256 = base64.b64encode(content_sha256_binary).decode()
content_sha256_header = 'x-content-sha256: ' + content_sha256
content_length_str=str(len(payload))
content_length_header = 'content-length: ' + content_length_str
'''
headers = {
    content_sha256_header,
    content_length_header
}
'''
headers=headers + " x-content-sha256 content-type content-length"
content_type_header="content-type: application/json"

signing_string = f"{request_target}\n{date_header}\n{host_header}"

signing_string = signing_string + f"\n{content_sha256_header}\n{content_type_header}\n{content_length_header}"
print("=====================================================================================================")
print(f"signing string is {signing_string}\n")

dat = new_key.sign(bytes(signing_string,'utf-8'), padding.PKCS1v15(), hashes.SHA256())
#print(dat)
signature = base64.b64encode(dat).decode().replace('\n', '').replace('\r', '')

#signature = base64.b64encode(hmac.new(private_key, signing_string.encode(), hashlib.sha256).digest()).decode()

print(f"Signed Request is\n{signature}\n")
print("=====================================================================================================")

headers_dict = {
    "date": date11,
    "x-content-sha256": content_sha256,
    "content-type": "application/json",
    "content-length": content_length_str,
    "Authorization": f'Signature version="1",keyId="{tenancy_ocid}/{user_ocid}/{fingerprint}",algorithm="rsa-sha256",headers="{headers}",signature="{signature}"'
}
print(f"Headers ==={headers_dict}\n")
response = requests.post(f"https://{host}{rest_api}",data=payload, headers=headers_dict)

print(response.text)
