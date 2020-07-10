# Cpp4Openssl


# install required library:
sudo apt install build-essential libssl-dev -y

# 1, generate private key and save into file rsa_private_key.pem
openssl genrsa -out rsa_private_key.pem 1024

# 2, generate public key from private key file and save into file
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

# NOTE: how to convert .pem to .der:
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

