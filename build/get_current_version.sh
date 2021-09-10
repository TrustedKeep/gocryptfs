#! /bin/bash

# takes a variable passed to get_current_branch and assigns it the
# current git branch you are in.

get_current_branch() {
    if  git symbolic-ref HEAD > /dev/null 2>&1
    then
	local __result=$1
        local branch_result=`git symbolic-ref HEAD | cut -d "/" -f3`
        eval $__result="'$branch_result'"
    else
	local __result=$1
        local tag_result=`git branch |grep \* | cut -d " " -f4| cut -d ")" -f1`
        eval $__result="'$tag_result'"
    fi
}

get_current_branch current_version
echo ${current_version}
