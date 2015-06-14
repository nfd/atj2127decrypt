#!/bin/sh

test_one() {
	#echo $1 >> test/compare
	rm -Rf out
	./decrypt ../$1
	ls out/* | xargs sha1sum | sed "s/^/$1 /" - >> test/compare
}

make
rm -f test/compare

test_one upgrade-clip-jam-1.03.hex
test_one upgrade-1.22.hex 
test_one Muse4_Cpu_Cap_v1.20A.upg
test_one upgrade-1.15.hex
test_one upgrade-1.17.hex
test_one upgrade-1.18.hex
test_one upgrade-sweetpea.hex

diff -u test/reference test/compare

