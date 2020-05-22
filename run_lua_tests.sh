# sh /docker/pull-changes.sh

OPENRESTY="/usr/local/openresty"
RESTY="${OPENRESTY}/bin/resty"
WD="${OPENRESTY}/nginx"
BASE_DIR="/usr/src"
TEST_DIR="${BASE_DIR}/test"

STATS_FILE="luacov.stats.out"
STATS_SRC="${TEST_DIR}/${STATS_FILE}"
REPORT_FILE="luacov.report.out"
REPORT_SRC="${TEST_DIR}/${REPORT_FILE}"

EXIT_CODE=0

################################################################################

OPT_PROCESS_STATS=0
OPT_EARLY_EXIT=1

while getopts "s" opt; do
    case $opt in
        s) OPT_PROCESS_STATS=1;;
        \?) echo "invalid argument";;
    esac
done

################################################################################

function exit_script {
    echo ""
    echo "END TESTS"
    echo ""
    echo "coverage stats file: ${STATS_SRC}"
    end_tests
    echo $1
    exit $1
}

function end_tests {
  echo "done"
    # if [ $OPT_PROCESS_STATS -eq 1 ]; then
    #     cd $TEST_DIR
    #     (luacov)
    #     echo "coverage report file: ${REPORT_SRC}"
    # fi
}

 ################################################################################

echo ""
echo "BEGIN TESTS"
echo ""

cd $TEST_DIR
PREV=$(pwd)

files=$(find . -name '*.test.lua')

while read line; do
    echo " -- TEST FILE: ${line}"
    DIR=$(dirname "${line}")
    FILE=$(basename "${line}")

    onlytag=""
    grep '#only' "${line}" && onlytag="--tags='only'"

    bash -c "$RESTY $line --exclude-tags='skip' ${onlytag}"
    RES=$?

    if [ $RES -ne 0 ]; then
        EXIT_CODE=$RES
        if [ $OPT_EARLY_EXIT -eq 1 ]; then break; fi
    fi

    cd "$PREV"
    echo ""
done <<< "$files"

exit_script $EXIT_CODE
