import argparse
from utils.sha256 import SHA256
from utils.gost3410 import *
from utils.utils import hexenc
from os import urandom

ap = argparse.ArgumentParser()
ap.add_argument("-i", type=str, help="Input file path")
ap.add_argument("-s", type=str, help="Input signature file path")
ap.add_argument("-d", type=str, help="Public key")
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

# initialize sha256 and curve objects
sha = SHA256()
curve = Curve(p=args["p"], q=args["q"], a=args["a"], b=args["b"], x=args["x"], y=args["y"])

# compute hash of the input file
with open(args["i"], "rb") as file:
    sha.update(file.read())

# read signature
with open(args["s"], "r") as s:
    signature = hexdec(s.read())
    
# perform verification
if verify(curve, pub_unmarshal(hexdec(args["d"])), sha.digest(), signature):
    print("Signature verified!")
else:
    print("Tough luck...")

