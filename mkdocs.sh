#!/bin/sh
########################################################################
# Use markdown_helper gem to generate docs. It's much nicer than using 
# vscode's broken TOC generator plugin.
########################################################################
CAT="/bin/cat"
LF="./docs/LICENSE.txt"

gen_license_file()
{
    echo "# License is MIT" > $LF
    echo "" >> $LF
    echo '```' >> $LF
    ${CAT} ./LICENSE.txt >>$LF
    echo "" >> $LF
    echo '```' >> $LF
}

run_markdown_toc() {
    local -r prog='markdown-toc-go'
    local -r gfile='./docs/glossary.txt'
    local -r m='./docs/README.md'
    local -r r='./README.md'
    ${prog} \
        -i ${m} -o ${r} \
        --glossary ${gfile} \
        -f
    ${prog} \
        -i ./docs/ChangeLog.md -o ./ChangeLog.md \
        --glossary ${gfile} \
        -no-credit \
        -f

}
#-----------------------------------------

#gen_license_file
run_markdown_toc
