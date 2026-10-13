#!/usr/bin/env bash
# git-checkout.sh [-j JOBS] REMOTE BRANCH
#
# Resets the repository to REMOTE/BRANCH (the local BRANCH tracks it) and every submodule
# (recursively, in parallel) to the commit pinned there, fetching only missing commits.
# Local changes and untracked files are discarded everywhere; ignored files (build/, .gradle/,
# local.properties) are kept. Submodule URLs follow .gitmodules, update = none is honored only
# when .gitmodules sets it.
#   -j JOBS  submodules processed in parallel (default: 16)

# refuse versions older than the ones this script was tested with: bash 5.3.9, git 2.55.0
if (( BASH_VERSINFO[0] * 10000 + BASH_VERSINFO[1] * 100 + BASH_VERSINFO[2] < 50309 )); then
  echo "${0##*/}: needs bash 5.3.9 or newer, this is $BASH_VERSION" >&2; exit 1
fi
v=$(git version 2>/dev/null); v=${v#git version }
IFS=. read -r v1 v2 v3 <<< "$v"; v3=${v3%%[!0-9]*}
if (( v1 * 10000 + v2 * 100 + ${v3:-0} < 25500 )); then
  echo "${0##*/}: needs git 2.55.0 or newer, this is ${v:-none}" >&2; exit 1
fi
set -euo pipefail
shopt -s inherit_errexit

# settings for every git command below, including the ones git itself runs
n=${GIT_CONFIG_COUNT:-0}
for kv in advice.detachedHead=false checkout.workers=0 submodule.recurse=false fetch.recurseSubmodules=false; do
  export "GIT_CONFIG_KEY_$n=${kv%%=*}" "GIT_CONFIG_VALUE_$n=${kv#*=}"
  n=$(( n + 1 ))
done
export GIT_CONFIG_COUNT=$n

JOBS=16 TOP=''
TMP=$(mktemp -d "${TMPDIR:-/tmp}/git-checkout.XXXXXX")
cleanup() {
  local -a pids
  mapfile -t pids < <(jobs -p)
  if (( ${#pids[@]} )); then   # workers lead process groups with their git processes
    kill -- "${pids[@]/#/-}" 2>/dev/null || true
    kill "${pids[@]}" 2>/dev/null || true
  fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

die() { echo "${0##*/}: $*" >&2; exit 1; }

# REPO: queue REPO's submodules, registering new ones and URL changes from .gitmodules
# (what git submodule init and sync would do)
walk_queue() {
  local repo=$1 kv key name path rec rest val relative=0
  local -a stale=()
  local -A name_of=() gm_url=() url_of=() none_of=()
  if [[ ! -f $repo/.gitmodules ]]; then return 0; fi
  while IFS= read -r -d '' kv; do   # .gitmodules
    key=${kv%%$'\n'*} name=${key#submodule.} val=${kv#*$'\n'}
    case $key in
      *.path) name_of[$val]=${name%.path} ;;
      *.url) gm_url[${name%.url}]=$val; if [[ $val == ./* || $val == ../* ]]; then relative=1; fi ;;
      *.update) if [[ $val == none ]]; then none_of[${name%.update}]=1; fi ;;
    esac
  done < <(git -C "$repo" config -z -f .gitmodules --get-regexp '^submodule\..*\.(path|url|update)$' || true)
  if (( ! ${#name_of[@]} )); then return 0; fi
  if (( relative )); then   # URLs relative to the remote: let git resolve them
    git -C "$repo" submodule --quiet sync
    git -C "$repo" submodule --quiet init
  fi
  while IFS= read -r -d '' kv; do   # local config
    key=${kv%%$'\n'*} name=${key#submodule.} val=${kv#*$'\n'}
    case $key in
      *.url) url_of[${name%.url}]=$val ;;
      *.update) name=${name%.update}; if [[ $val == none && -z ${none_of[$name]-} ]]; then stale+=("$name"); fi ;;
    esac
  done < <(git -C "$repo" config -z --local --get-regexp '^submodule\..*\.(url|update)$' || true)
  for name in "${stale[@]}"; do git -C "$repo" config unset "submodule.$name.update"; done   # set only locally
  if (( ! relative )); then
    for name in "${!gm_url[@]}"; do
      if [[ ${url_of[$name]-} == "${gm_url[$name]}" ]]; then continue; fi
      if [[ -z ${url_of[$name]-} ]]; then git -C "$repo" config set "submodule.$name.active" true; fi
      git -C "$repo" config set "submodule.$name.url" "${gm_url[$name]}"
      url_of[$name]=${gm_url[$name]}
    done
  fi
  while IFS= read -r -d '' rec; do
    if [[ $rec != 160000\ * ]]; then continue; fi
    path=${rec#*$'\t'} rest=${rec#* }
    name=${name_of[$path]-}
    if [[ -z $name || -z ${url_of[$name]-} || -n ${none_of[$name]-} ]]; then continue; fi
    t_repo+=("$repo") t_path+=("$path") t_sha+=("${rest%% *}") t_name+=("$name") t_url+=("${url_of[$name]}")
  done < <(git -C "$repo" --literal-pathspecs ls-files -s -z -- "${!name_of[@]}")
}

# walk TOP: runs sub_sync in the background for every submodule of TOP (recursively, JOBS at a
# time; a repository's submodules are queued once it is synced). Sets WALK_DONE, WALK_FAILED,
# WALK_NEW (repositories were cloned).
walk() {
  local pid res label
  local -i idx qh=0 rc ndone=0 nfail=0 el
  local -a t_repo=() t_path=() t_sha=() t_name=() t_url=()
  local -A running=() started=()
  WALK_NEW=0
  walk_queue "$1"
  while (( ${#t_repo[@]} > qh || ${#running[@]} )); do
    while (( ${#t_repo[@]} > qh && ${#running[@]} < JOBS )); do
      idx=$qh qh+=1
      set -m   # a process group of its own, so that an abort stops the git processes too
      ( export GIT_TERMINAL_PROMPT=0
        sub_sync "${t_repo[idx]}" "${t_path[idx]}" "${t_sha[idx]}" "${t_name[idx]}" "${t_url[idx]}"
      ) </dev/null >"$TMP/$idx.log" 2>&1 3>"$TMP/$idx.res" &
      set +m
      running[$!]=$idx started[$!]=${EPOCHREALTIME/[.,]/}
    done
    pid='' rc=0
    wait -n -p pid || rc=$?
    if [[ -z $pid || -z ${running[$pid]-} ]]; then continue; fi   # not a worker: a process substitution
    idx=${running[$pid]}
    unset "running[$pid]"
    el=$(( (${EPOCHREALTIME/[.,]/} - ${started[$pid]}) / 100000 ))
    res=''; read -r res < "$TMP/$idx.res" || true
    label=${t_repo[idx]#"$TOP"}/${t_path[idx]} label=${label#/}
    if (( rc )); then
      nfail+=1
      echo "$label: FAILED" >&2
      sed 's/^/    /' "$TMP/$idx.log" | tail -n 20 >&2
    else
      ndone+=1
      if [[ $res == cloned ]]; then WALK_NEW=1; fi
      walk_queue "${t_repo[idx]}/${t_path[idx]}"
      if [[ -n $res ]]; then printf '%s: %s (%d.%ds)\n' "$label" "$res" $(( el / 10 )) $(( el % 10 )) >&2; fi
    fi
  done
  WALK_DONE=$ndone WALK_FAILED=$nfail
}

# REPO SHA: fetch that commit (one commit deep in a shallow repository)
fetch_commit() {
  local err
  local -a depth=()
  if [[ $(git -C "$1" rev-parse --is-shallow-repository) == true ]]; then depth=(--depth 1); fi
  if ! err=$(git -C "$1" fetch -q --no-tags "${depth[@]}" origin "$2" 2>&1); then
    if [[ $err != *unadvertised* ]]; then printf '%s\n' "$err" >&2; return 1; fi
    # an old server that refuses fetching by commit id: fetch the branches
    git -C "$1" fetch -q --no-tags origin '+refs/heads/*:refs/remotes/origin/*'
  fi
}

# Worker: make submodule PATH of REPO a clean checkout of exactly SHA from URL
sub_sync() {
  local repo=$1 path=$2 sha=$3 name=$4 url=$5 sub=$1/$2 head origin err
  if [[ ! -e $sub/.git && -d $(git -C "$repo" rev-parse --path-format=absolute --git-path "modules/$name") ]]; then
    # deinitialized or deleted earlier: reattach the repository that is still there
    git -C "$repo" submodule --quiet update --init --no-fetch -- "$path" 2>/dev/null || true
  fi
  if [[ ! -e $sub/.git ]]; then
    if ! err=$(git clone -q --no-tags --depth 1 --revision="$sha" -- "$url" "$sub" 2>&1); then
      if [[ $err != *unadvertised* ]]; then printf '%s\n' "$err" >&2; return 1; fi
      git clone -q --no-tags --no-checkout -- "$url" "$sub"   # server refuses fetching by commit id
      git -C "$sub" checkout -q --detach "$sha"
    fi
    echo cloned >&3
    return 0
  fi
  origin=$(git -C "$sub" config get remote.origin.url) || origin=''
  if [[ $origin != "$url" ]]; then git -C "$sub" config set remote.origin.url "$url"; fi
  # HEAD and whether SHA is here, in one call
  if head=$(GIT_NO_LAZY_FETCH=1 git -C "$sub" rev-parse HEAD "$sha^{commit}" 2>/dev/null); then
    head=${head%%$'\n'*}
  else
    head=''
    fetch_commit "$sub" "$sha"
  fi
  git -C "$sub" checkout -q -f --detach "$sha"
  git -C "$sub" clean -ffdq
  if [[ $head != "$sha" ]]; then echo "updated to ${sha:0:7}" >&3; fi
}

# REMOTE BRANCH: fetch BRANCH and reset the local BRANCH (tracking REMOTE/BRANCH) to it
checkout_top() {
  local remote=$1 branch=$2 spec s covered=0
  local -a specs
  spec=refs/heads/$branch:refs/remotes/$remote/$branch
  mapfile -t specs < <(git -C "$TOP" config get --all "remote.$remote.fetch" || true)
  for s in "${specs[@]}"; do
    if [[ ${s#+} == "refs/heads/*:refs/remotes/$remote/*" || ${s#+} == "$spec" ]]; then covered=1; fi
  done
  git -C "$TOP" fetch -q --no-tags "$remote" "+$spec"
  if (( ! covered )); then git -C "$TOP" config --add "remote.$remote.fetch" "+$spec"; fi   # for --track
  git -C "$TOP" checkout -q -f -B "$branch" --track "$remote/$branch"
  git -C "$TOP" clean -ffdq
}

main() {
  local out commit failed=''
  local -i t0=${EPOCHREALTIME/[.,]/} el
  while (( $# )); do
    case $1 in
      -j) JOBS=$2; shift 2 ;;
      -h|--help) sed -n '2,9s/^# \{0,1\}//p' "$0"; exit 0 ;;
      -*) die "unknown option $1" ;;
      *) break ;;
    esac
  done
  if (( $# != 2 )); then die "usage: ${0##*/} [-j JOBS] REMOTE BRANCH"; fi
  if [[ ! $JOBS =~ ^[1-9][0-9]*$ ]]; then die "-j needs a positive number"; fi
  TOP=$(git rev-parse --show-toplevel)
  checkout_top "$1" "$2"
  walk "$TOP"
  if (( WALK_NEW )) && ! out=$(git -C "$TOP" submodule --quiet absorbgitdirs 2>&1); then
    printf '%s\n' "$out" >&2; exit 1
  fi
  el=$(( (${EPOCHREALTIME/[.,]/} - t0) / 100000 ))
  if (( WALK_FAILED )); then failed=", $WALK_FAILED FAILED"; fi
  printf '%s: %d submodules%s in %d.%ds\n' "${0##*/}" "$WALK_DONE" "$failed" $(( el / 10 )) $(( el % 10 )) >&2
  commit=$(git -C "$TOP" log -1 --format='%h %s')
  echo "Using commit ${commit%% *} ($2): ${commit#* }"
  (( ! WALK_FAILED ))
}

main "$@"
