#!/bin/bash
pushd `pwd`
WORK=`pwd`  # aflgo/tests
NAME=binutils
CVE=$1		# first argv, e.g. 2016-4487

DOWNLOAD_DIR=$WORK/$NAME
if [ ! -d $DOWNLOAD_DIR ]; then
    mkdir $DOWNLOAD_DIR
fi
cd $DOWNLOAD_DIR

CVE_TARGET=$WORK/CVEtargetline/${CVE}.txt
CVE_PATCH=$WORK/CVEpatch/${CVE}.patch

if [ "$2" == "origin" ] ; then
    WHICH_AFLGO="origin"
else
    WHICH_AFLGO="good"
fi
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-${WHICH_AFLGO}-patched
OBJ_1=$DOWNLOAD_DIR/obj-1-${WHICH_AFLGO}
OBJ_2=$DOWNLOAD_DIR/obj-2-${WHICH_AFLGO}/${CVE}
OBJ_FIXED=$DOWNLOAD_DIR/obj-3-${WHICH_AFLGO}/${CVE}
TMP_DIR=$DOWNLOAD_DIR/temp-${WHICH_AFLGO}/${CVE}-temp
DIR_OUT=$DOWNLOAD_DIR/out-${WHICH_AFLGO}/${CVE}-out

if [ ! -e $DOWNLOAD_DIR/obj-2-${WHICH_AFLGO} ]; then
	mkdir $DOWNLOAD_DIR/obj-2-${WHICH_AFLGO}
fi
if [ ! -e $DOWNLOAD_DIR/temp-${WHICH_AFLGO} ]; then
	mkdir $DOWNLOAD_DIR/temp-${WHICH_AFLGO}
fi
if [ ! -e $DOWNLOAD_DIR/out-${WHICH_AFLGO} ]; then
	mkdir $DOWNLOAD_DIR/out-${WHICH_AFLGO}
fi
if [ ! -e $DOWNLOAD_DIR/obj-3-${WHICH_AFLGO} ]; then
	mkdir $DOWNLOAD_DIR/obj-3-${WHICH_AFLGO}
fi
if [ ! -e $TMP_DIR ]; then
	mkdir $TMP_DIR
fi
if [ -e $TMP_DIR/state ]; then
  echo "1" >$TMP_DIR/state
fi

case $CVE in
    "2016-4487")
        #### valgrind binutils/cxxfilt _Q10-__9cafebabe.
	#echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1203\ncplus-dem.c:1490\ncplus-dem.c:2594\ncplus-dem.c:4319" >$TMP_DIR/BBtargets.txt
	echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1203\ncplus-dem.c:1490\ncplus-dem.c:2599\ncplus-dem.c:4325" >$TMP_DIR/BBtargets.txt 
	echo -e "main\ndemangle_it\ncplus_demangle\ninternal_cplus_demangle\ndemangle_signature\ndemangle_class\nregister_Btype" >$TMP_DIR/Ftargets.txt
        ;;
    "2016-4488")
        #### valgrind binutils/cxxfilt _Q10-__9cafebabe.
	#echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1203\ncplus-dem.c:1490\ncplus-dem.c:2617\ncplus-dem.c:4292" >$TMP_DIR/BBtargets.txt
	echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1203\ncplus-dem.c:1490\ncplus-dem.c:2625\ncplus-dem.c:4298" >$TMP_DIR/BBtargets.txt
	echo -e "main\ndemangle_it\ncplus_demangle\ninternal_cplus_demangle\ndemangle_signature\ndemangle_class\nremember_Ktype\n" >$TMP_DIR/Ftargets.txt
        ;;
    "2016-4489")
        #### valgrind c++filt __vt_90000000000cafebabe
	#echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1190\ncplus-dem.c:3007\ncplus-dem.c:4839" >$TMP_DIR/BBtargets.txt
	echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1190\ncplus-dem.c:3012\ncplus-dem.c:4845" >$TMP_DIR/BBtargets.txt
	echo -e "main\ndemangle_it\ncplus_demangle\ninternal_cplus_demangle\ngnu_special\nstring_appendn" >$TMP_DIR/Ftargets.txt
        ;;
    "2016-4490")
        #### valgrind c++filt _Z80800000000000000000000
	echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:864\ncp-demangle.c:6102\ncp-demangle.c:5945\ncp-demangle.c:5894\ncp-demangle.c:1172\ncp-demangle.c:1257\ncp-demangle.c:1399\ncp-demangle.c:1596\n" >$TMP_DIR/BBtargets.txt
	echo -e "main\ndemangle_it\ncplus_demangle_v3\nd_demangle\nd_demangle_callback\ncplus_demangle_mangled_name\nd_encoding\nd_name\nd_unqualified_name\n" >$TMP_DIR/Ftargets.txt
        ;;
    "2016-4491")
	#### valgind c++filt _Z1MA_aMMMMA_MMA_MMMMMMMMSt1MS_o11T0000000000t2M0oooozoooo
	echo -e "cp-demangle.c:5394\ncp-demangle.c:4320" > $TMP_DIR/BBtargets.txt
	echo -e "d_print_comp\nd_print_comp_inner" > $TMP_DIR/Ftargets.txt
        ;;
    "2016-4492")
        #### valgind c++filt 0__Ot2m02R5T0000500000
	#echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1203\ncplus-dem.c:1642\ncplus-dem.c:4514\ncplus-dem.c:4231\ncplus-dem.c:3671\ncplus-dem.c:2169" >$TMP_DIR/BBtargets.txt
	echo -e "cxxfilt.c:227\ncxxfilt.c:62\ncplus-dem.c:886\ncplus-dem.c:1203\ncplus-dem.c:1645\ncplus-dem.c:4520\ncplus-dem.c:4237\ncplus-dem.c:3676\ncplus-dem.c:2174" >$TMP_DIR/BBtargets.txt
	echo -e "main\ndemangle_it\ncplus_demangle\ninternal_cplus_demangle\ndemangle_signature\ndemangle_args\ndo_arg\ndo_type\ndemangle_template\n" >$TMP_DIR/Ftargets.txt
        ;;
    "2016-6131")
	#### valgrind cxxfilt __10%0__S4_0T0T0
        #echo -e "cplus-dem.c:3811\ncplus-dem.c:4018\ncplus-dem.c:2543\ncplus-dem.c:2489\n" >$TMP_DIR/BBtargets.txt
	echo -e "cplus-dem.c:3817\ncplus-dem.c:4024\ncplus-dem.c:2548\ncplus-dem.c:2494\n" >$TMP_DIR/BBtargets.txt
	echo -e "do_type\ndemangle_fund_type\ndemangle_class_name\ndemangle_arm_hp_template" >$TMP_DIR/Ftargets.txt
        ;;
    *)
        echo "Unrecorgnized CVE id. Please select CVE id from:2016-4487,2016-4488,2016-4489,2016-4490,2016-4491,2016-4492,2016-6131."
esac

## echo core | sudo tee /proc/sys/kernel/core_pattern
## wget http://ftp.gnu.org/gnu/binutils/binutils-2.26.tar.gz
## tar xvf binutils-2.26.tar.gz
## cp -R binutils-2.26 BUILD

cd $DOWNLOAD_DIR

export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++

TMP_DIR_COMMOM=$DOWNLOAD_DIR/temp-${WHICH_AFLGO}/temp-common
if [ ! -d $TMP_DIR_COMMOM ];then
	mkdir $TMP_DIR_COMMOM
	echo "First Compile."
	ADDITIONAL="-targets=$TMP_DIR_COMMOM/BBtargets.txt -outdir=$TMP_DIR_COMMOM -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
	export CFLAGS="-g3 $ADDITIONAL"
	export CXXFLAGS="-g3  $ADDITIONAL"
	export LDFLAGS="-ldl -lutil" 
	rm -rf $OBJ_1
	mkdir $OBJ_1; cd $OBJ_1;
	$DOWNLOAD_DIR/BUILD/configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld
	make 
	echo "First Compile done."
fi

ln -s $TMP_DIR_COMMOM/dot-files $TMP_DIR/dot-files
cp $TMP_DIR_COMMOM/BBcalls.txt $TMP_DIR/BBcalls.txt
cp $TMP_DIR_COMMOM/BBnames.txt $TMP_DIR/BBnames.txt
#BBtargets.txt already set up before
cp $TMP_DIR_COMMOM/Fnames.txt $TMP_DIR/Fnames.txt
#Ftargets.txt already set up before

#### Clean up
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

#### Generate distance
if [ ! -e distance.cfg.txt ];then
	PROGRAM_NAME=cxxfilt
	PROGRAM_DIR=$OBJ_1/binutils/
	$AFLGO/scripts/genDistance.sh $PROGRAM_DIR $TMP_DIR $PROGRAM_NAME
fi
echo "Distance values:"
head -n5 $TMP_DIR/distance.cfg.txt
echo "..."
tail -n5 $TMP_DIR/distance.cfg.txt
exit
export CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error -distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
export CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

echo "Second compile."
rm -rf $OBJ_2
mkdir $OBJ_2; cd $OBJ_2; 
$DOWNLOAD_DIR/BUILD/configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld
if [ -d $TMP_DIR/rid_bbname_pairs.txt ];then
	rm $TMP_DIR/rid_bbname_pairs.txt
fi
make 
echo "Second compile done."


if [ ! -e $OBJ_FIXED ]; then
	echo "Compile patched version."
	cd $DOWNLOAD_DIR/BUILD
	patch -p0 < $CVE_PATCH
	mkdir $OBJ_FIXED; cd $OBJ_FIXED
	export CC=clang
	export CXX=clang++
	export CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fno-omit-frame-pointer -g -Wno-error"
	$DOWNLOAD_DIR/BUILD/configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim --disable-ld
	make
	cd $DOWNLOAD_DIR/BUILD
	patch -Rp0 < $CVE_PATCH
	echo "Compile patched version done."
fi

if [ "$WHICH_AFLGO" == "good" ] ; then
    $AFLGO/scripts/index_all_cfg_edges.py -d $TMP_DIR/dot-files
    #$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files
fi

cd $DOWNLOAD_DIR 
TARGET=$OBJ_2/binutils/cxxfilt
TIME=1m
echo "" > $DOWNLOAD_DIR/in/seeds
DIR_IN=$DOWNLOAD_DIR/in

ITER=0
for((i=1;i<=$((ITER));i++));
do
	if [ -d $DIR_OUT ]; then
		rm -rf $DIR_OUT
	fi
	if [ "$WHICH_AFLGO" == "good" ];then
		$AFLGO/afl-fuzz -S target_result -z exp -c $TIME -E $TMP_DIR -i $DIR_IN -o $DIR_OUT $TARGET
		#gdb --args $AFLGO/afl-fuzz -S target_result -z exp -c $TIME -E $TMP_DIR -i $DIR_IN -o $DIR_OUT -P $DOWNLOAD_DIR/CVElists $TARGET
	else
		$AFLGO/afl-fuzz -S target_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $TARGET
		#gdb --args $AFLGO/afl-fuzz -S target_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -P $DOWNLOAD_DIR/CVElists $TARGET
        fi
	#### valgrind ./BUILD/obj-${CVE}-2/binutils/cxxfilt < ./crashfile
done

popd
