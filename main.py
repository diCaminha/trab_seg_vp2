import random

from OpenSSL import crypto, SSL

from db import get_db, save_cert


def cert_gen(
        email="email",
        name="name",
        countryName="NT",
        stateName="stateOrProvinceName",
        organizationName="organizationName",
        validityStartInSeconds=0,
        validityEndInSeconds=10 * 365 * 24 * 60 * 60,
        KEY_FILE="private.key",
        CERT_FILE="selfsigned.crt"):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateName
    cert.get_subject().O = organizationName
    cert.get_subject().CN = name
    cert.get_subject().emailAddress = email
    serial_number = random.randint(1, (159 << 1) - 1)
    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
    key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8")

    save_cert(cert, key, serial_number)

    return certificate, key