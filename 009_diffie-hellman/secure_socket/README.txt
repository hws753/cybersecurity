1. copiare il codice sia su server, sia su client

2. generare certificati su server col comando: python3 script.py gen_certs

3. copiare sul client i files: ca_cert.pem, client_cert.pem e client key.pem

4. avviare il server col comando: python3 script.py server <ip del server>

5 avviare il client col comando: python3 script.py client <ip del server>
