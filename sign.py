import argparse
from utils.sha256 import SHA256
from utils.gost3410 import *
from utils.utils import hexenc
from os import urandom

ap = argparse.ArgumentParser()
ap.add_argument("-i", type=str, help="Input file path")
ap.add_argument("-o", type=str, help="Output file path")
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
                help="x coordinate of the point P (generator of the subgroup of order q) of the elliptic curve"
                     " in the canonical form")
ap.add_argument("-d", type=str, default='0', help="Private key")

args = vars(ap.parse_args())

if args["d"] == '0':
    private_key_raw = urandom(64)
    print(f"Private key is: {hexenc(private_key_raw)}")
    args["d"] = prv_unmarshal(private_key_raw)
else:
    args["d"] = prv_unmarshal(hexdec(args["d"]))

curve = Curve(p=args["p"], q=args["q"], a=args["a"], b=args["b"], x=args["x"], y=args["y"])
sha = SHA256()

pub = public_key(curve, args["d"])
print(f"Public key is: {hexenc(pub_marshal(pub))}")

with open(args["i"], "rb") as file:
    sha.update(file.read())

signature = sign(curve, args["d"], sha.digest())

with open(args["o"], "w") as signature_file:
    signature_file.write(hexenc(signature))


