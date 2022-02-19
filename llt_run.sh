#!/bin/bash

CURRENT_DIR="$(cd "$(dirname "$0")"; pwd)"
readonly DOWNLOAD_PKG_PATH="/opt/distribute_block/develop/"
readonly down_load_script="${CURRENT_DIR}/../../../product/sftp.sh"
readonly depends_pkg="infrastructure,infrastructure-obs,edsctrl,oam-u,ftds,persistence,fdsa,xnet"
readonly down_load_binary="${CURRENT_DIR}/../../../product/down_binary.sh"
LIBSTORAGE_SDK_RPM_PATH=/opt/distribute_block/develop/spdk

readonly AGENT_INSTALL_DIR="/opt/fusionstorage"
TOP_DIR=$(cd $CURRENT_DIR/../../..;pwd)
AGENT_3RD_DIR="${TOP_DIR}/agent/open_source"
AGENT_ROOT_DIR="${TOP_DIR}/agent"
THIRD_PARTY_DIR="${AGENT_ROOT_DIR}/open_source"
SDK_PACKAGE_DIR="/opt/distribute_block/develop"

branch_name="master_811_unknown"
mode="normal"
BUILD_ARCH=x86_64
while getopts "b:m:" arg
do
    case $arg in
        b)
            branch_name=$OPTARG
            ;;
        m)
            mode=${OPTARG}
            ;;
        ?)
           echo "only support -b branc_name -m mode(normal,debug)"
           exit 1
        ;;
    esac
done

echo "mode is $mode"
if [ $mode != "normal" -a $mode != "debug" ]; then
    echo "mode is invalid"
    exit 1
fi

# 安装mock
cd "${CURRENT_DIR}/../mockcpp"
cmake CMakeLists.txt
make
make install

cd "${CURRENT_DIR}/../../../CI/script"
# download 3td package
function download_package_start()
{
    local test_type=$1
    local branch=$(git branch | grep "\*" | sed "s/\* //")
    rm -rf /opt/cmc/Local_Agent/.cache.json /opt/cmc/Local_Agent/.index.json
    bash ${down_load_binary} ${BUILD_ARCH}
    bash ${down_load_script} -s ${depends_pkg} -r ${test_type} -a ${BUILD_ARCH} -b ${branch_name} -d ${DOWNLOAD_PKG_PATH}
    return
}

function download_datanet_so()
{
    cd ${DOWNLOAD_PKG_PATH}
    [[ ${BUILD_ARCH} == 'x86_64' ]] && artifactId="Datanet" || artifactId="datanet"
	rm -rf ${artifactId}*.tar.gz
	#down load datanet so
	if [[ $BUILD_ARCH != 'x86_64' ]];then
		DATANET_PATH=http://wlg1.artifactory.cd-cloud-artifact.tools.huawei.com/artifactory/Product-FusionStorage-Object-snapshot/com/huawei/fusionstorage-object/arm/Infrastructure/datanet/
	else
		DATANET_PATH=http://wlg1.artifactory.cd-cloud-artifact.tools.huawei.com/artifactory/product-dfv/com/huawei/dfv/infrastructure/Datanet
	fi
	
	DATANET_VERSION=maven-metadata.xml

	#get latest dir
	wget ${DATANET_PATH}/${DATANET_VERSION}
	if [ $? -ne 0 ];then
	   echo "Download DATANET version file failed!"
	   exit 1
	fi
	datanet_file_dir=`cat ${DATANET_VERSION} | grep latest | awk -F '[<>]' '{print $3}' | head -1`
	rm -f ${DATANET_VERSION}

	wget ${DATANET_PATH}/${datanet_file_dir}/${DATANET_VERSION}
	if [ $? -ne 0 ];then
	   echo "Download DATANET version file failed!"
	   exit 1
	fi

	datanet_version=`cat ${DATANET_VERSION} | grep value | awk -F '[<>]' '{print $3}' | head -1`
	rm -f ${DATANET_VERSION}

	wget ${DATANET_PATH}/${datanet_file_dir}/${artifactId}-${datanet_version}.tar.gz
	if [ $? -ne 0 ];then
	   echo "Download DATANET failed!"
	   exit 1
	fi
	if [  ! -f ${artifactId}-${datanet_version}.tar.gz  ];then
	   echo "DATANET package not exist!"
	   exit 1
	fi

	rm -rf dfv_datanet Datanet
	tar -xvzf ${artifactId}-${datanet_version}.tar.gz
	if [[ -d ./Datanet/dfv_datanet ]]; then
	    mv -f ./Datanet/dfv_datanet/ .
	    rm -rf Datanet
	fi
	cd -
}

function build_fsa_grpc() {
    echo "build fsa_grpc"
    if [ ! -d ${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc ]; then
        tar -xvzf ${CURRENT_DIR}/../../3rd/grpc/*.tar.gz -C ${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/ > /dev/null
    else
        if [ "`ls -A ${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc`" = "" ]; then
            rm -rf ${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc
            tar -xvzf ${CURRENT_DIR}/../../3rd/grpc/*.tar.gz -C ${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/ > /dev/null
        fi
    fi
    LD_LIBRARY_PATH_OLD=`echo "${LD_LIBRARY_PATH}"`
    export LD_LIBRARY_PATH=${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc/lib:${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc/lib64:${LD_LIBRARY_PATH}
    chmod 500 ${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc/protoc
    chmod 500 ${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc/grpc_cpp_plugin
    rm -rf ${AGENT_ROOT_DIR}/src/grpc_adapter/build
    mkdir -p ${AGENT_ROOT_DIR}/src/grpc_adapter/build
    cd ${AGENT_ROOT_DIR}/src/grpc_adapter/build
    cmake .. -Dgencov=yes
    make
    cd -
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH_OLD
}

function build_net_subhealth() {
    echo "build_net_subhealth"
    rm -rf ${AGENT_ROOT_DIR}/src/net_module/net_subhealth_frame/build
    mkdir -p ${AGENT_ROOT_DIR}/src/net_module/net_subhealth_frame/build
    cd ${AGENT_ROOT_DIR}/src/net_module/net_subhealth_frame/build
    cmake .. -Dgencov=yes
    make clean;make
    cd -
}

download_package_start debug
download_datanet_so

# copy depandent sdk library
function copyDepandentSdkLibrary()
{
  #拷贝eds和oam-u的库（注意要使用shell原生命令，不要使用alias，达到强制覆盖的目的）
  while read line || [[ -n ${line} ]]
  do
    \cp -rf ${SDK_PACKAGE_DIR}$line ${AGENT_INSTALL_DIR}/agent/lib
    if [ $? -ne 0 ]; then
      echo "cp ${SDK_PACKAGE_DIR}$line to ${AGENT_INSTALL_DIR}/agent/lib failed."
      return 1
    fi
  done < ${CURRENT_DIR}/../../build/dependent_sdk_package_library.txt
  local platform="X86"
  if [ "${BUILD_ARCH}" == "aarch64" ]; then
    platform="ARM"
  fi

  cp -rf ${AGENT_ROOT_DIR}/external_lib/${platform}/* ${AGENT_INSTALL_DIR}/agent/lib
  if [ $? -ne 0 ]; then
    echo "cp ${AGENT_ROOT_DIR}/external_lib/${platform}/* to ${AGENT_INSTALL_DIR}/agent/lib failed."
    return 1
  fi
  return 0
}


if [ $mode == "normal" ]; then
    #build KMC
    echo "start build KMC"
    cd ${CURRENT_DIR}/../../../agent/platform/KMC
    chmod 500 build_kmc.sh
    ./build_kmc.sh __AGENT__ ${BUILD_ARCH}
    echo "end build KMC"

    cd ${CURRENT_DIR}
    make clean || { echo "make clean failed."; exit 1; }
    build_fsa_grpc
    build_net_subhealth
    make gencov=yes asan=yes dtfuzz=no || { echo "make failed"; exit 1;  }
fi

# clean env
rm -rf /var/log/oma  > /dev/null 2>&1
rm -rf /opt/fusionstorage > /dev/null 2>&1
rm -rf /opt/dsware/agent > /dev/null 2>&1

# prepare runtime env
mkdir -p /var/log/oma/fsa
mkdir -p /opt/fusionstorage/agent/conf
mkdir -p /opt/dsware/agent/conf/

echo "AGENT_ROOT_DIR=$AGENT_ROOT_DIR"

mkdir -p $AGENT_INSTALL_DIR
mkdir -p $AGENT_INSTALL_DIR/conf
mkdir -p $AGENT_INSTALL_DIR/agent
mkdir -p $AGENT_INSTALL_DIR/agent/conf
mkdir -p $AGENT_INSTALL_DIR/agent/certificate
mkdir -p $AGENT_INSTALL_DIR/agent/lib
mkdir -p $AGENT_INSTALL_DIR/agent/bin
mkdir -p $AGENT_INSTALL_DIR/agent/script
mkdir -p $AGENT_INSTALL_DIR/agent/tool
mkdir -p $AGENT_INSTALL_DIR/agent/fifo
mkdir -p $AGENT_INSTALL_DIR/agent/start_sign
mkdir -p $AGENT_INSTALL_DIR/agent/tmp
mkdir -p $AGENT_INSTALL_DIR/agent/version
mkdir -p $AGENT_INSTALL_DIR/agent_safe/script

cp $AGENT_ROOT_DIR/common/conf/* ${AGENT_INSTALL_DIR}/conf  > /dev/null 2>&1
cp $AGENT_ROOT_DIR/common/install/* ${AGENT_INSTALL_DIR}/agent/script/ > /dev/null 2>&1
cp $AGENT_ROOT_DIR/common/conf/node_config.xml ${AGENT_INSTALL_DIR}/agent/bin > /dev/null 2>&1
cp $AGENT_ROOT_DIR/build/dsware_agent ${AGENT_INSTALL_DIR}/agent/bin > /dev/null 2>&1
cp $AGENT_ROOT_DIR/build/dsware_agent_tool_binary ${AGENT_INSTALL_DIR}/agent/tool > /dev/null 2>&1
cp $AGENT_ROOT_DIR/script/dsware_agent_tool ${AGENT_INSTALL_DIR}/agent/tool > /dev/null 2>&1
cp -rf $AGENT_ROOT_DIR/script/* ${AGENT_INSTALL_DIR}/agent/script/ > /dev/null 2>&1
cp -rf $AGENT_ROOT_DIR/script/rootScript ${AGENT_INSTALL_DIR}/agent_safe/script/ > /dev/null 2>&1
cp  $AGENT_ROOT_DIR/common/install ${AGENT_INSTALL_DIR}/agent/script/ > /dev/null 2>&1
mv ${AGENT_INSTALL_DIR}/agent/script/dsware_insight ${AGENT_INSTALL_DIR}/agent/tool > /dev/null 2>&1
cp -f $AGENT_ROOT_DIR/src/tool/*.sh ${AGENT_INSTALL_DIR}/agent/tool/ > /dev/null 2>&1
cp -rf $AGENT_ROOT_DIR/interface/agent/* ${AGENT_INSTALL_DIR}/agent/conf > /dev/null 2>&1
cp -rf $AGENT_ROOT_DIR/certificate/* ${AGENT_INSTALL_DIR}/agent/certificate/ > /dev/null 2>&1
cp -rf $THIRD_PARTY_DIR/cJSON/lib/* ${AGENT_INSTALL_DIR}/agent/lib > /dev/null 2>&1
cp $AGENT_ROOT_DIR/conf/install_dir.cfg ${AGENT_INSTALL_DIR}/agent > /dev/null 2>&1
cp $CURRENT_DIR/test_data/omm_sudo_user_info ${AGENT_INSTALL_DIR}/agent/conf > /dev/null 2>&1
cp -rf $AGENT_ROOT_DIR/../healthcheck $AGENT_INSTALL_DIR/agent/script/ > /dev/null 2>&1

#将配置文件格式转换为unix
dos2unix ${AGENT_INSTALL_DIR}/conf/* > /dev/null 2>&1
dos2unix ${AGENT_INSTALL_DIR}/agent/script/*.sh > /dev/null 2>&1
dos2unix ${AGENT_INSTALL_DIR}/agent/conf/* > /dev/null 2>&1
dos2unix ${AGENT_INSTALL_DIR}/agent/conf/componentConfig/* > /dev/null 2>&1

#拷贝eds和oam-u的库（注意要使用shell原生命令，不要使用alias，达到强制覆盖的目的）
copyDepandentSdkLibrary
if [ $? -ne 0 ]; then
  echo "copy depandent sdk library failed."
  return 1
fi
find ${AGENT_INSTALL_DIR}/agent/lib  -name "*.a" -type f -print -exec rm -rf {} > /dev/null 2>&1 \;

mkdir -p ${AGENT_INSTALL_DIR}/agent/conf/kmc/conf > /dev/null 2>&1
mkdir -p ${AGENT_INSTALL_DIR}/agent/conf/kmc/bkp > /dev/null 2>&1
cp -rf $AGENT_ROOT_DIR/interface/common/keystore/primary_ks.key ${AGENT_INSTALL_DIR}/agent/conf/kmc/conf > /dev/null 2>&1
cp -rf $AGENT_ROOT_DIR/interface/common/keystore/standby_ks.key ${AGENT_INSTALL_DIR}/agent/conf/kmc/bkp > /dev/null 2>&1
cp -rf /opt/fusionstorage/agent/conf/kmc/ /opt/dsware/agent/conf/ > /dev/null 2>&1
cp -rf /opt/fusionstorage/agent/conf/ssl/ /opt/dsware/agent/conf/ > /dev/null 2>&1

echo "nodeVersion=${REAL_VERSION}" > ${AGENT_INSTALL_DIR}/DSwareAgentNodeVersion
echo "buildDate=`date +%Y-%m-%d`" >> ${AGENT_INSTALL_DIR}/DSwareAgentNodeVersion
echo "buildTime=`date +%H:%M:%S`" >> ${AGENT_INSTALL_DIR}/DSwareAgentNodeVersion
chmod 700 ${AGENT_INSTALL_DIR}/DSwareAgentNodeVersion

mkdir -p /var/log/oam/fsa/run
mkdir -p /var/log/oam/fsa/script
mkdir -p /opt/dsware/vbs/conf

mkdir -p  /opt/fusionstorage/persistence_layer/mdc/conf/
touch /opt/fusionstorage/persistence_layer/mdc/conf/mdc_conf.cfg

$CURRENT_DIR/output/bin/dsware_agent_tool_test --gtest_output=xml
LD_LIBRARY_PATH=${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc/lib:${DOWNLOAD_PKG_PATH}/infrastructure/lib/open_source/grpc/lib64:${LD_LIBRARY_PATH} $CURRENT_DIR/output/bin/dsware_agent_test --gtest_output=xml
