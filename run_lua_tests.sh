
if [ "$LUACOV_REPORT" = "1" ]; then
    busted --coverage-config-file ./.luacov --coverage ./test >&2
    cat ./luacov.report.html
else
    busted ./test
fi