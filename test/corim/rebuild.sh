#!/usr/bin/bash
set -euo pipefail

corims=(
	cca-ref-plat
	cca-ref-realm
	cca-ta
)

for name in "${corims[@]}"; do
	echo "Rebuilding signed-corim-${name}.cbor..."
	corim-tool compile "corim-${name}.json" -o "signed-corim-${name}.cbor" --kid key.pub.pem --key key.priv.pem -f
done
echo "Done."
