import datetime
import hashlib
import hmac
import base64
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


#OCID of the tenancy calls are being made in to
tenancy_ocid="ocid1.tenancy.oc1..aaaaaaaafqp2t7fvy54rxpxig544zvwl6jcsfktqzbt4zhrq7yhofyeua6yq"
# OCID of the user making the rest call
user_ocid = "ocid1.user.oc1..aaaaaaaao752rxe6xdrepbzankblrmxnixlmbryejucidav4txgbpeua3ysa"

# path to the private PEM format key for this user
private_key_path = "/home/opc/.oci/privatekey.pem"

# fingerprint of the private key for this user
fingerprint = "e1:7e:d9:fe:a8:2b:7e:b2:0b:48:8e:ab:a2:1a:2e:fc"

# The REST api you want to call, with any required parameters.
rest_api = "/n/cnan8fmjdahe/b/test2/p?compartmentId=ocid1.compartment.oc1..aaaaaaaavjpnolu7cz64pajvagwwnrxcqnzqzg7ywmyaeivgl2c24qufzehq"

# The host you want to make the call against
host = "objectstorage.ap-seoul-1.oraclecloud.com"


date11 = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
date_header = f"date: {date11}"
host_header = f"host: {host}"
request_target = f"(request-target): get {rest_api}"
# note the order of items. The order in the signing_string matches the order in the headers
signing_string = f"{request_target}\n{date_header}\n{host_header}"
headers = "(request-target) date host"

print("=====================================================================================================")
print(f"signing string is {signing_string}\n")

with open(private_key_path, 'rb') as fr:pem_pri=fr.read()
new_key = serialization.load_pem_private_key(pem_pri, password=None, backend=default_backend())

dat = new_key.sign(bytes(signing_string,'utf-8'), padding.PKCS1v15(), hashes.SHA256())
#print(dat)
signature = base64.b64encode(dat).decode().replace('\n', '').replace('\r', '')

#signature = base64.b64encode(hmac.new(private_key, signing_string.encode(), hashlib.sha256).digest()).decode()

print(f"Signed Request is\n{signature}\n")
print("=====================================================================================================")

headers_dict = {
    "date": date11,
    "Authorization": f'Signature version="1",keyId="{tenancy_ocid}/{user_ocid}/{fingerprint}",algorithm="rsa-sha256",headers="{headers}",signature="{signature}"'
}

response = requests.get(f"https://{host}{rest_api}", headers=headers_dict)

print(response.text)
