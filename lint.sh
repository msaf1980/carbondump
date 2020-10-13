#!/usr/bin/env bash

SRC="src"
INCLUDE="include"


RET="0"

sources() {
    [ -z "${SOURCES}" ] && SOURCES=$( find ${SRC} -name '*.c' -o -name '*.cpp' )
}

lint_cppcheck() {
    cppcheck --enable=all -i ${INCLUDE} --template="{file}:{line}:\ [{severity}][{id}]\ {message}" ${SRC}
    [ "$?" -eq "0" ] || RET="1"
}

lint_clang_tidy() {
    sources
    clang-tidy -p /home/msv/git/graphite/carbondump/build -checks='*,-clang-analyzer-alpha.*' ${SOURCES}
    [ "$?" -eq "0" ] || RET="1"
}

cd $( dirname $0 )

ARGS=($@)
if [ "${#ARGS[@]}" -eq "0" ]; then
    ARGS=("cppcheck" "clang-tidy")
fi

for ((i = 0; i < ${#ARGS[@]}; i++)); do
    case "${ARGS[${i}]}" in
        "cppcheck")
            lint_cppcheck
            ;;
        "clang-tidy")
            lint_clang_tidy
            ;;
        *)
            echo "Unknown linter: ${ARGS[${i}]}" >&2
            ;;
    esac
done

exit ${RET}
