apple-push-notify
=================

sample for apple push notify with openssl

develop.des3 is the develop pem encrypt with des3

encrypt:
openssl des3 -salt -in develop.pem -out develop.des3

decrypt:
openssl des3 -d -salt -in develop.des3 -out develop.pem

