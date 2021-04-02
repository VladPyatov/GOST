import argparse
from utils.sha256 import SHA256
from utils.gost3410 import *
from utils.utils import hexenc
from os import urandom

ap = argparse.ArgumentParser()
ap.add_argument("-i", type=str, help="Input file path")
ap.add_argument("-o", type=str, help="Output file path")
ap.add_argument("-k", type=str, default='', help="Public key output path")
ap.add_argument("-r", type=str, default='', help="Private key output path")
ap.add_argument("-d", type=str, default='0', help="Private key")
ap.add_argument("-p", type=int, default=57896044618658097711785492504343953926634992332820282019728792003956564821041,
                help="Characteristic of the underlying prime field")
ap.add_argument("-q", type=int, default=57896044618658097711785492504343953927082934583725450622380973592137631069619,
                help="Elliptic curve subgroup order")
ap.add_argument("-a", type=int, default=7, help="Coefficient a of the equation of the elliptic curve in the canonical form")
ap.add_argument("-b", type=int, default=43308876546767276905765904595650931995942111794451039583252968842033849580414,
                help="Coefficient b of the equation of the elliptic curve in the canonical form")
ap.add_argument("-x", type=int, default=2, help="x coordinate of the point P (generator of the subgroup of order q) "
                                                "of the elliptic curve in the canonical form")
ap.add_argument("-y", type=int, default=4018974056539037503335449422937059775635739389905545080690979365213431566280,
                help="y coordinate of the point P (generator of the subgroup of order q) of the elliptic curve"
                     " in the canonical form")

args = vars(ap.parse_args())

if args["d"] == '0':
    # generate private key
    private_key_raw = urandom(64)
    prv_key_hex = hexenc(private_key_raw)
    print(f"Private key is: {prv_key_hex}")
    # write private key to the output file
    if args["r"] != '':
        with open(args["r"], "w") as pk:
            pk.write(prv_key_hex)
    args["d"] = prv_unmarshal(private_key_raw)
else:
    args["d"] = prv_unmarshal(hexdec(args["d"]))

# initialize curve and sha256 objects
curve = Curve(p=args["p"], q=args["q"], a=args["a"], b=args["b"], x=args["x"], y=args["y"])
sha = SHA256()

# generate public key
pub = public_key(curve, args["d"])
pub_key_hex = hexenc(pub_marshal(pub))
print(f"Public key is: {pub_key_hex}")

# write public key to the output file
if args["k"] != '':
    with open(args["k"], "w") as pk:
        pk.write(pub_key_hex)

# generate hash
with open(args["i"], "rb") as file:
    sha.update(file.read())

# sign input file
signature = sign(curve, args["d"], sha.digest())

# siave signature
with open(args["o"], "w") as signature_file:
    signature_file.write(hexenc(signature))


