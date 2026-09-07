#!/usr/bin/bash
set -euo pipefail

corims=(
	cca-plat-rv
	cca-plat-ta
	cca-realm-rv
	cca-plat-expired-validity
	cca-plat-unsupported-profile
)

for name in "${corims[@]}"; do
	echo "Rebuilding signed-corim-${name}.cbor..."
	# echo "compile corim-${name}.json -o signed-corim-${name}.cbor --kid key.pub.pem --key key.priv.pem -f"
	corim-tool compile "corim-${name}.json" -o "signed-corim-${name}.cbor" --kid key.pub.pem --key key.priv.pem -f
done
echo "Done."
