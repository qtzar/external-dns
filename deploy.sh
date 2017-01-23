#!/bin/bash
./scripts/build
cd bin/
tar cf ../packaging/external-dns.tar external-dns
gzip -f9 ../packaging/external-dns.tar
docker build -t qtzar/external-dns ../packaging
docker push qtzar/external-dns
