#!/usr/bin/env bash
# Build kernelsu.ko for the Pico 4 Ultra (sparrow) vendor kernel in CI.
#
# A DDK/GKI module has the wrong vermagic and task_struct offsets, so build
# against the exact kernel the device runs, using headers carved from the OTA.
set -euo pipefail

KERNEL_COMMIT="${KERNEL_COMMIT:-9db823a19d2674d9e551c061386863a3936b4331}"
KERNEL_TAG="${KERNEL_TAG:-android12-5.10.198_r00}"
LOCALVERSION_EXTRA="${LOCALVERSION_EXTRA:--gaaf872b28b70-ab117}"
EXPECTED_VERMAGIC="${EXPECTED_VERMAGIC:-5.10.198-perf-gaaf872b28b70-ab117}"
# Served by Pico; only ~16 MiB of it is fetched (range requests).
OTA_URL="${OTA_URL:-https://lf-stone-iot-my.dlpicovr.com/obj/stone-iot-my/5.15.7-202608080609-RELEASE-user-sparrow-b9111-b2059d5f17.zip}"

SRC="${SRC:-$PWD/kernel}"
WORK="${WORK:-$PWD/.lkm-work}"
KDIR="$WORK/kernel"
OUT="${OUT:-$PWD/dist}"
# -ffile-prefix-map rewrites this to "." so the build does not embed it.
PREFIX_MAP="${PREFIX_MAP:-$PWD}"

log() { printf '[lkm] %s\n' "$*"; }

mkdir -p "$WORK" "$OUT"

# kheaders/config are not committed; carve them out of the OTA.  OTA_ZIP
# overrides the URL for offline builds.
KHDR="$WORK/kheaders"
OTA_INPUT="${OTA_ZIP:-$OTA_URL}"
if [ ! -f "$KHDR/sparrow-kheaders.tar.xz" ] || [ ! -f "$KHDR/sparrow.config" ]; then
    log "extracting kheaders from OTA"
    python3 "$SRC/tools/ota-kheaders.py" "$OTA_INPUT" --outdir "$KHDR" \
        --symbols "$WORK/kallsyms.tsv"
fi

if [ ! -d "$KDIR/.git" ]; then
    log "cloning $KERNEL_TAG"
    git init -q "$KDIR"
    git -C "$KDIR" remote add origin https://android.googlesource.com/kernel/common
    git -C "$KDIR" fetch -q --depth 1 origin "$KERNEL_TAG"
    git -C "$KDIR" checkout -q FETCH_HEAD
fi

ACTUAL_COMMIT=$(git -C "$KDIR" rev-parse HEAD)
if [ "$ACTUAL_COMMIT" != "$KERNEL_COMMIT" ]; then
    log "ERROR: kernel commit $ACTUAL_COMMIT != expected $KERNEL_COMMIT"
    exit 1
fi

log "applying device kheaders"
tar -C "$KDIR" -xJf "$KHDR/sparrow-kheaders.tar.xz"
cp "$KHDR/sparrow.config" "$KDIR/.config"

# setlocalversion checks .scmversion first, which pins the vendor release
# string without having to patch the device config.
printf '%s' "$LOCALVERSION_EXTRA" > "$KDIR/.scmversion"

# LLVM_IAS=1 is required: without it HAS_LTO_CLANG is false and kconfig
# silently rewrites the LTO choice to LTO_NONE.
log "syncconfig"
make -C "$KDIR" -s syncconfig </dev/null

for want in CONFIG_MODULES=y CONFIG_LTO_CLANG_FULL=y CONFIG_CFI_CLANG=y CONFIG_CFI_CLANG_SHADOW=y; do
    grep -qx "$want" "$KDIR/include/config/auto.conf" || {
        log "ERROR: $want not set in auto.conf"
        exit 1
    }
done

log "prepare"
make -C "$KDIR" -s prepare </dev/null
make -C "$KDIR" -s modules_prepare </dev/null

# Not a dependency of prepare, but the module build needs flask.h.
make -C "$KDIR" -s scripts </dev/null
"$KDIR/scripts/selinux/genheaders/genheaders" \
    "$KDIR/security/selinux/flask.h" \
    "$KDIR/security/selinux/av_permissions.h"

# prepare regenerates these from our toolchain, yielding TSK_STACK_CANARY 1544
# instead of the device's 1744 and re-enabling CONFIG_STACKPROTECTOR_PER_TASK,
# which makes the module use the wrong task_struct offsets.  Restore the
# device copies afterwards.
log "restoring device-generated headers"
# The device archive stores members with a "./" prefix, so re-extract the
# whole archive; this restores include/generated/ regardless of prefix.
tar -C "$KDIR" -xJf "$KHDR/sparrow-kheaders.tar.xz"

CANARY=$(awk '{if ($2 == "TSK_STACK_CANARY") print $3;}' "$KDIR/include/generated/asm-offsets.h")
if [ "$CANARY" != "1744" ]; then
    log "ERROR: TSK_STACK_CANARY is $CANARY, expected 1744"
    exit 1
fi
if grep -q CONFIG_STACKPROTECTOR_PER_TASK "$KDIR/include/generated/autoconf.h"; then
    log "ERROR: device autoconf.h should not define CONFIG_STACKPROTECTOR_PER_TASK"
    exit 1
fi

log "building kernelsu.ko"
# -ffile-prefix-map keeps __FILE__ out of the output, so the same source builds
# to the same bytes regardless of where it is checked out.
make -C "$KDIR" M="$SRC" src="$SRC" modules \
    CONFIG_KSU=m \
    CONFIG_KSU_MULTI_MANAGER_SUPPORT=y \
    CONFIG_KSU_TRACEPOINT_HOOK=y \
    KCFLAGS="-ffile-prefix-map=$PREFIX_MAP=."

KO="$SRC/kernelsu.ko"
[ -f "$KO" ] || { log "ERROR: $KO missing"; exit 1; }

ACTUAL_VERMAGIC=$(modinfo -F vermagic "$KO" | awk '{print $1}')
if [ "$ACTUAL_VERMAGIC" != "$EXPECTED_VERMAGIC" ]; then
    log "ERROR: vermagic $ACTUAL_VERMAGIC != $EXPECTED_VERMAGIC"
    exit 1
fi

# No vendor vmlinux exists, so synthesise a symtab from the kallsyms table
# recovered from the OTA kernel (done by the extraction step above).
KALLSYMS="$WORK/kallsyms.tsv"
if [ -f "$KALLSYMS" ]; then
    python3 "$SRC/tools/mkvmlinux.py" "$KALLSYMS" -o "$WORK/vmlinux.sym"
    cc "$SRC/tools/check_symbol.c" -o "$WORK/check_symbol"
    "$WORK/check_symbol" "$KO" "$WORK/vmlinux.sym"
    log "symbol check passed"
else
    log "WARNING: no kallsyms dump, skipping symbol check"
fi

install -m 0644 "$KO" "$OUT/kernelsu.ko"
log "wrote $OUT/kernelsu.ko"