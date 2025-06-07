#!/bin/sh

izname=./sample.d/56f87f00.zip

namedjson2asn1(){
	gznames=$1
	gzjsonl=$2
	outasn1=$3

	sznames=$( cat "${gznames}" | wc -c )
	szjsonl=$( cat "${gzjsonl}" | wc -c )

	printf '%x' $sznames | xxd -r -ps > ./sample.d/.tmp.names.sz.dat
	printf '%x' $szjsonl | xxd -r -ps > ./sample.d/.tmp.jsonl.sz.dat

	printf '\x04' |
		cat \
			/dev/stdin \
			./sample.d/.tmp.names.sz.dat \
			"${gznames}" \
		> ./sample.d/.tmp.names.asn1.der.dat

	printf '\x04\x81' |
		cat \
			/dev/stdin \
			./sample.d/.tmp.jsonl.sz.dat \
			"${gzjsonl}" \
		> ./sample.d/.tmp.jsonl.asn1.der.dat

	osz=$( cat ./sample.d/.tmp.*.asn1.der.dat | wc -c )
	printf '%x' ${osz} | xxd -r -ps > ./sample.d/.tmp.sz.dat

	printf '\x30\x81' |
		cat \
			/dev/stdin \
			./sample.d/.tmp.sz.dat \
			./sample.d/.tmp.names.asn1.der.dat \
			./sample.d/.tmp.jsonl.asn1.der.dat \
		> "${outasn1}"
}

geninput0zi0(){
	jq -c -n '{
		order: 333,
		user: 634,
		timestamp: 1748917370.491,
		items: [
			{product: 599,  quantity: 4, price: 1.01325},
			{product: 3776, quantity: 2, price: 42.195}
		]
	}' > ./sample.d/z0i0j0.json

	jq -c -n '{
		order: 334,
		user: 635,
		timestamp: 1748917371.491,
		items: [
			{product: 600,  quantity: 5, price: 2.01325},
			{product: 3777, quantity: 3, price: 43.195}
		]
	}' > ./sample.d/z0i0j1.json

	cat ./sample.d/z0i0j[01].json |
		gzip --fast \
		> ./sample.d/z0i0jsonl.raw.gz

	printf '%s\n' namez0i0j0 namez0i0j1 |
		gzip --fast \
		> ./sample.d/z0i0names.raw.gz

	namedjson2asn1 \
		./sample.d/z0i0names.raw.gz \
		./sample.d/z0i0jsonl.raw.gz \
		./sample.d/56f87f70
}

geninput0zi1(){
	jq -c -n '{
		order: 433,
		user: 734,
		timestamp: 1848917370.491,
		items: [
			{product: 699,  quantity: 5, price: 2.01325},
			{product: 4776, quantity: 3, price: 52.195}
		]
	}' > ./sample.d/z0i1j0.json

	jq -c -n '{
		order: 434,
		user: 735,
		timestamp: 1848917371.491,
		items: [
			{product: 700,  quantity: 6, price: 3.01325},
			{product: 4777, quantity: 4, price: 53.195}
		]
	}' > ./sample.d/z0i1j1.json

	cat ./sample.d/z0i1j[01].json |
		gzip --fast \
		> ./sample.d/z0i1jsonl.raw.gz

	printf '%s\n' namez0i1j0 namez0i1j1 |
		gzip --fast \
		> ./sample.d/z0i1names.raw.gz

	namedjson2asn1 \
		./sample.d/z0i1names.raw.gz \
		./sample.d/z0i1jsonl.raw.gz \
		./sample.d/56f87f80
}

geninput(){
	echo creating input zip files...

	mkdir -p ./sample.d

	geninput0zi0
	geninput0zi1

	echo '
		cd ./sample.d
		ls 56f87f[78]0 |
			zip \
				-@ \
				-T \
				-v \
				-o \
				./56f87f00.zip
	' | sh
}

test -f "${izname}" || geninput

key=order
key=user

unzip -lv ./sample.d/56f87f00.zip

echo
echo creating bloom bytes...
ls "${izname}" |
	cut -d/ -f3- |
	sed 's,^,/guest-i.d/,' |
	wazero \
		run \
		-env ENV_BLOOM_TARGET_KEY="${key}" \
		-mount "${PWD}/sample.d:/guest-i.d:ro" \
		./basic.wasm |
		xxd
