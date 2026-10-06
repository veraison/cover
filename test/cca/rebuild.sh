rm -rf deps
mkdir deps

pushd deps

git clone https://github.com/veraison/evcli.git --depth 1 ./evcli.dir

pushd evcli.dir
go build -o ../evcli main.go
popd

popd

./deps/evcli cca create \
    --claims=cca-claims-03.json \
    --iak=keys/iak-ec256.priv.json \
    --rak=keys/rak-ec384.priv.json \
    --token=cca-token-03.cbor