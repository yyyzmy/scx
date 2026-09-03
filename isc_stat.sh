#!/bin/bash
# ============================================================================
# isc_stat.sh — SYNPA ISC 栈采集器
# 对指定程序进行独立运行(ST)与组合运行(SMT)的 perf 停顿统计
#
# 采集事件: cpu_cycles, stall_frontend, stall_backend, inst_spec
# 计算三变量:
#   FEstalls = stall_frontend / cpu_cycles          前端停顿占比
#   BEstalls = stall_backend  / cpu_cycles          后端停顿占比
#   DIcycles = inst_spec / (W * cpu_cycles)         满带宽分发等效周期占比
#
# 用法:
#   ./isc_stat.sh -m topo -c 10                          # 查看 SMT 拓扑
#   ./isc_stat.sh -m st   -c 10 ./front ./back           # 各程序单独运行
#   ./isc_stat.sh -m pair -c 10 ./front ./back           # 两程序共跑同一物理核
#   ./isc_stat.sh -m pair -c 10,74 ./front ./back        # 显式指定两个硬件线程
#   ./isc_stat.sh -m all  -c 10 ./front ./back ./bench3  # ST + 两两全组合 + 数据集
#
# 选项:
#   -m <mode>   topo | st | pair | all
#   -c <cpu>    锚定 CPU；pair/all 模式自动使用其 SMT sibling；也可 "cpuA,cpuB"
#   -w <width>  dispatch 宽度，默认 6 (Neoverse V1/V2)；ThunderX2 用 4；N2 用 5
#   -r <times>  每个配置重复次数，默认 1；>1 时汇总取中位数
#   -o <file>   all 模式训练数据集输出文件，默认 isc_dataset.csv
#
# 注意:
#   - 需要 root（perf 计数器权限）
#   - ST 模式假设 sibling 硬件线程无负载（建议 offline: echo 0 > online）
#   - 程序命令串内不要包含逗号（CSV 输出）
#   - 若从 Windows 拷贝后报语法错误, 先执行: dos2unix isc_stat.sh
# ============================================================================

set -u

EVENTS="cpu_cycles,stall_frontend,stall_backend,inst_spec"
WIDTH=6
REPEAT=1
MODE=""
ANCHOR=""
OUTCSV="isc_dataset.csv"
TMPDIR=$(mktemp -d)

trap 'rm -rf "$TMPDIR"' EXIT

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------
# 环境检查
# ---------------------------------------------------------------------------
check_env() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[警告] 非 root 运行, perf 可能无权限读取 PMU (perf_event_paranoid)"
    fi
    if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
        echo "[错误] 需要 bash 4+ (关联数组), 当前: $BASH_VERSION"
        exit 1
    fi
    command -v perf >/dev/null 2>&1 || { echo "[错误] 未找到 perf"; exit 1; }
    command -v taskset >/dev/null 2>&1 || { echo "[错误] 未找到 taskset"; exit 1; }
    command -v awk >/dev/null 2>&1 || { echo "[错误] 未找到 awk"; exit 1; }

    # 事件可用性预检
    local out
    out=$(perf stat -x, -e "$EVENTS" true 2>&1)
    if echo "$out" | grep -qiE "not supported|not counted|failed"; then
        echo "[错误] 部分事件不可用, 请用 'perf list | grep -i stall' 确认事件名"
        echo "$out" | grep -iE "not supported|not counted|failed"
        exit 1
    fi
}

# 获取 cpu 的 SMT sibling（无 SMT 返回空）
get_sibling() {
    local cpu=$1
    local f="/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list"
    [ -r "$f" ] || { echo ""; return; }
    local sib
    sib=$(cat "$f" | tr -d ' ')
    case "$sib" in
        *-*) # 形如 "10-11"
            local lo=${sib%-*} hi=${sib#*-}
            if [ "$cpu" -eq "$lo" ] 2>/dev/null; then echo "$hi"; else echo "$lo"; fi
            ;;
        *,*) # 形如 "10,74" (含多段则取第一个非自身)
            local other
            other=$(echo "$sib" | tr ',' '\n' | grep -vx "$cpu" | head -n1)
            echo "$other"
            ;;
        *)   # 单 CPU, 无 SMT
            echo ""
            ;;
    esac
}

# 解析 perf CSV 输出 → 全局变量 C_CYC C_FE C_BE C_SPEC
parse_perf() {
    local f=$1
    C_CYC=$(awk -F, -v e='cpu_cycles'    'tolower($3)==e{print $1; exit}' "$f" | tr -d ' <>')
    C_FE=$(awk  -F, -v e='stall_frontend' 'tolower($3)==e{print $1; exit}' "$f" | tr -d ' <>')
    C_BE=$(awk  -F, -v e='stall_backend'  'tolower($3)==e{print $1; exit}' "$f" | tr -d ' <>')
    C_SPEC=$(awk -F, -v e='inst_spec'     'tolower($3)==e{print $1; exit}' "$f" | tr -d ' <>')
    local bad=0
    for v in "$C_CYC" "$C_FE" "$C_BE" "$C_SPEC"; do
        case "$v" in ''|*[!0-9]*) bad=1 ;; esac
    done
    if [ $bad -eq 1 ]; then
        echo "[错误] perf 输出解析失败 ($f):"
        cat "$f" >&2
        exit 1
    fi
}

# 计算三变量 → 全局变量 V_FE V_BE V_DI V_TOT（0~1 浮点）
calc_isc() {
    read -r V_FE V_BE V_DI V_TOT <<EOF
$(awk -v fe="$C_FE" -v be="$C_BE" -v sp="$C_SPEC" -v cy="$C_CYC" -v w="$WIDTH" 'BEGIN{
    if (cy+0 <= 0) { print -1,-1,-1,-1 }
    else {
        f = fe/cy; b = be/cy; d = sp/(w*cy)
        printf "%.4f %.4f %.4f %.4f", f, b, d, f+b+d
    }
}')
EOF
    if [ "$V_FE" = "-1" ]; then
        echo "[错误] cpu_cycles 为 0, 无法计算"; exit 1
    fi
}

# 打印一次采集结果
print_result() {
    local tag=$1 cpu=$2 el=$3
    printf "  %-28s @ cpu%-3s | %7ss\n" "$tag" "$cpu" "$el"
    printf "    cycles=%s fe=%s be=%s spec=%s\n" "$C_CYC" "$C_FE" "$C_BE" "$C_SPEC"
    printf "    FEstalls=%5.2f%%  BEstalls=%6.2f%%  DIcycles=%5.2f%%  (W=%s)  Total=%6.2f%%\n" \
        "$(awk -v x=$V_FE 'BEGIN{print x*100}')" \
        "$(awk -v x=$V_BE 'BEGIN{print x*100}')" \
        "$(awk -v x=$V_DI 'BEGIN{print x*100}')" \
        "$WIDTH" \
        "$(awk -v x=$V_TOT 'BEGIN{print x*100}')"
}

# 取文件中数值的中位数（每行一个数）
median() {
    sort -n "$1" | awk '
        { a[NR]=$1 }
        END {
            if (NR==0) { print 0; exit }
            if (NR%2==1) print a[(NR+1)/2]
            else printf "%.6f", (a[NR/2]+a[NR/2+1])/2
        }'
}

# ---------------------------------------------------------------------------
# ST: 单程序运行（结果存入关联数组 ST_*）
# ---------------------------------------------------------------------------
declare -A ST_FE ST_BE ST_DI ST_TOT ST_EL

run_st_one() {
    local cpu=$1 cmd=$2 tag=$3
    local ffe=$TMPDIR/fe.txt fbe=$TMPDIR/be.txt fdi=$TMPDIR/di.txt ftot=$TMPDIR/tot.txt fel=$TMPDIR/el.txt
    : > "$ffe"; : > "$fbe"; : > "$fdi"; : > "$ftot"; : > "$fel"

    local rep
    for rep in $(seq 1 "$REPEAT"); do
        local t0 t1
        t0=$(date +%s%N)
        perf stat -x, -e "$EVENTS" taskset -c "$cpu" $cmd >/dev/null 2>"$TMPDIR/run.perf"
        t1=$(date +%s%N)
        parse_perf "$TMPDIR/run.perf"
        calc_isc
        awk -v x="$V_FE"  'BEGIN{print x}' >> "$ffe"
        awk -v x="$V_BE"  'BEGIN{print x}' >> "$fbe"
        awk -v x="$V_DI"  'BEGIN{print x}' >> "$fdi"
        awk -v x="$V_TOT" 'BEGIN{print x}' >> "$ftot"
        awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f\n", (b-a)/1e9}' >> "$fel"
        if [ "$REPEAT" -gt 1 ]; then
            printf "  [rep %d] " "$rep"; print_result "$tag" "$cpu" \
                "$(tail -n1 "$fel")"
        fi
    done

    ST_FE[$tag]=$(median "$ffe")
    ST_BE[$tag]=$(median "$fbe")
    ST_DI[$tag]=$(median "$fdi")
    ST_TOT[$tag]=$(median "$ftot")
    ST_EL[$tag]=$(median "$fel")
    printf "[ST ] "; print_result "$tag" "$cpu" "${ST_EL[$tag]}"
}

# ---------------------------------------------------------------------------
# SMT: 两程序经 fifo 屏障同步启动, 分别绑 sibling 运行
# 结果存入全局 PAIR_* 数组, key = "cmdA|cmdB"
# ---------------------------------------------------------------------------
run_smt_pair() {
    local cpuA=$1 cpuB=$2 cmdA=$3 cmdB=$4
    local pfe=$TMPDIR/pfe.txt pbe=$TMPDIR/pbe.txt pdi=$TMPDIR/pdi.txt \
           ptot=$TMPDIR/ptot.txt pel=$TMPDIR/pel.txt
    local qfe=$TMPDIR/qfe.txt qbe=$TMPDIR/qbe.txt qdi=$TMPDIR/qdi.txt \
           qtot=$TMPDIR/ptot2.txt qel=$TMPDIR/qel.txt
    : > "$pfe"; : > "$pbe"; : > "$pdi"; : > "$ptot"; : > "$pel"
    : > "$qfe"; : > "$qbe"; : > "$qdi"; : > "$qtot"; : > "$qel"

    local rep
    for rep in $(seq 1 "$REPEAT"); do
        rm -f "$TMPDIR/go"
        mkfifo "$TMPDIR/go"

        # 采集线程 A
        (
            exec 3< "$TMPDIR/go"; IFS= read -r _ <&3
            t0=$(date +%s%N)
            perf stat -x, -e "$EVENTS" taskset -c "$cpuA" $cmdA >/dev/null 2>"$TMPDIR/a.perf"
            t1=$(date +%s%N)
            echo "$t0 $t1" > "$TMPDIR/a.time"
        ) &
        local pidA=$!
        # 采集线程 B
        (
            exec 3< "$TMPDIR/go"; IFS= read -r _ <&3
            t0=$(date +%s%N)
            perf stat -x, -e "$EVENTS" taskset -c "$cpuB" $cmdB >/dev/null 2>"$TMPDIR/b.perf"
            t1=$(date +%s%N)
            echo "$t0 $t1" > "$TMPDIR/b.time"
        ) &
        local pidB=$!

        # 双双就绪后同时放行
        exec 4> "$TMPDIR/go"
        printf 'go\ngo\n' >&4
        wait "$pidA" "$pidB"
        exec 4>&-

        # 解析 A / B
        parse_perf "$TMPDIR/a.perf"; calc_isc
        local Afe=$V_FE Abe=$V_BE Adi=$V_DI Atot=$V_TOT
        local Ael=$(awk '{printf "%.3f", ($2-$1)/1e9}' "$TMPDIR/a.time")
        parse_perf "$TMPDIR/b.perf"; calc_isc
        local Bfe=$V_FE Bbe=$V_BE Bdi=$V_DI Btot=$V_TOT
        local Bel=$(awk '{printf "%.3f", ($2-$1)/1e9}' "$TMPDIR/b.time")

        echo "$Afe" >> "$pfe"; echo "$Abe" >> "$pbe"; echo "$Adi" >> "$pdi"; echo "$Atot" >> "$ptot"; echo "$Ael" >> "$pel"
        echo "$Bfe" >> "$qfe"; echo "$Bbe" >> "$qbe"; echo "$Bdi" >> "$qdi"; echo "$Btot" >> "$qtot"; echo "$Bel" >> "$qel"

        if [ "$REPEAT" -gt 1 ]; then
            printf "  [rep %d]\n" "$rep"
            printf "    A: "; print_result "$cmdA" "$cpuA" "$Ael"
            printf "    B: "; print_result "$cmdB" "$cpuB" "$Bel"
        fi
    done

    local key="${cmdA}|${cmdB}"
    PAIR_FE[$key]=$(median "$pfe"); PAIR_BE[$key]=$(median "$pbe")
    PAIR_DI[$key]=$(median "$pdi"); PAIR_TOT[$key]=$(median "$ptot")
    PAIR_EL[$key]=$(median "$pel")
    local key2="${cmdB}|${cmdA}"
    PAIR_FE[$key2]=$(median "$qfe"); PAIR_BE[$key2]=$(median "$qbe")
    PAIR_DI[$key2]=$(median "$qdi"); PAIR_TOT[$key2]=$(median "$qtot")
    PAIR_EL[$key2]=$(median "$qel")

    printf "[SMT] %-24s @ cpu%-3s | %7ss   <->   %-24s @ cpu%-3s | %7ss\n" \
        "$cmdA" "$cpuA" "${PAIR_EL[$key]}" "$cmdB" "$cpuB" "${PAIR_EL[$key2]}"
    printf "    %-24s FEstalls=%5.2f%%  BEstalls=%6.2f%%  DIcycles=%5.2f%%  Total=%6.2f%%\n" \
        "$cmdA" \
        "$(awk -v x=${PAIR_FE[$key]} 'BEGIN{print x*100}')" \
        "$(awk -v x=${PAIR_BE[$key]} 'BEGIN{print x*100}')" \
        "$(awk -v x=${PAIR_DI[$key]} 'BEGIN{print x*100}')" \
        "$(awk -v x=${PAIR_TOT[$key]} 'BEGIN{print x*100}')"
    printf "    %-24s FEstalls=%5.2f%%  BEstalls=%6.2f%%  DIcycles=%5.2f%%  Total=%6.2f%%\n" \
        "$cmdB" \
        "$(awk -v x=${PAIR_FE[$key2]} 'BEGIN{print x*100}')" \
        "$(awk -v x=${PAIR_BE[$key2]} 'BEGIN{print x*100}')" \
        "$(awk -v x=${PAIR_DI[$key2]} 'BEGIN{print x*100}')" \
        "$(awk -v x=${PAIR_TOT[$key2]} 'BEGIN{print x*100}')"
}

declare -A PAIR_FE PAIR_BE PAIR_DI PAIR_TOT PAIR_EL

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
main() {
    # 参数检查
    [ -n "$MODE" ] || { usage; echo "[错误] 缺少 -m 模式"; exit 1; }
    [ -n "$ANCHOR" ] || { usage; echo "[错误] 缺少 -c CPU"; exit 1; }
    [ "$REPEAT" -ge 1 ] 2>/dev/null || { echo "[错误] -r 需 >= 1"; exit 1; }
    [ "$WIDTH" -ge 1 ] 2>/dev/null || { echo "[错误] -w 需 >= 1"; exit 1; }

    check_env

    # 解析 -c: "10" 或 "10,74"
    local CPU_A CPU_B
    if [[ "$ANCHOR" == *,* ]]; then
        CPU_A=${ANCHOR%,*}
        CPU_B=${ANCHOR#*,}
    else
        CPU_A=$ANCHOR
        CPU_B=$(get_sibling "$ANCHOR")
    fi

    case "$MODE" in
    topo)
        local sib coreid
        coreid=$(cat "/sys/devices/system/cpu/cpu$CPU_A/topology/core_id" 2>/dev/null)
        if [ -z "$CPU_B" ]; then
            echo "cpu$CPU_A: 无 SMT sibling (core_id=$coreid)"
        else
            echo "cpu$CPU_A <-> cpu$CPU_B  (同一物理核, core_id=$coreid)"
            echo "SMT 共跑:  ./isc_stat.sh -m pair -c $CPU_A,$CPU_B ./prog1 ./prog2"
        fi
        ;;

    st)
        [ ${#CMDS[@]} -ge 1 ] || { echo "[错误] st 模式至少 1 个程序"; exit 1; }
        echo "=== ST 模式 (独立运行, W=$WIDTH, repeat=$REPEAT) ==="
        if [ -n "$CPU_B" ]; then
            echo "[提示] ST 模式要求 cpu$CPU_B (sibling) 无负载, 否则结果受污染"
        fi
        local c
        for c in "${CMDS[@]}"; do
            run_st_one "$CPU_A" "$c" "$c"
        done
        ;;

    pair)
        [ ${#CMDS[@]} -eq 2 ] || { echo "[错误] pair 模式需要恰好 2 个程序"; exit 1; }
        [ -n "$CPU_B" ] || { echo "[错误] cpu$CPU_A 无 SMT sibling, 无法共跑"; exit 1; }
        echo "=== SMT 模式 (组合运行, W=$WIDTH, repeat=$REPEAT) ==="
        run_smt_pair "$CPU_A" "$CPU_B" "${CMDS[0]}" "${CMDS[1]}"
        ;;

    all)
        [ ${#CMDS[@]} -ge 1 ] || { echo "[错误] all 模式至少 1 个程序"; exit 1; }
        if [ ${#CMDS[@]} -ge 2 ]; then
            [ -n "$CPU_B" ] || { echo "[错误] cpu$CPU_A 无 SMT sibling, 无法组合运行"; exit 1; }
        fi
        echo "=== ALL 模式: ST + 两两全组合 (W=$WIDTH, repeat=$REPEAT) ==="

        # 1. ST
        local c
        for c in "${CMDS[@]}"; do
            run_st_one "$CPU_A" "$c" "$c"
        done

        # 2. 全组合
        local i j n=${#CMDS[@]}
        if [ "$n" -ge 2 ]; then
            echo ""
            echo "--- 两两组合 ---"
            for ((i=0; i<n; i++)); do
                for ((j=i+1; j<n; j++)); do
                    run_smt_pair "$CPU_A" "$CPU_B" "${CMDS[i]}" "${CMDS[j]}"
                    echo ""
                done
            done

            # 3. slowdown 矩阵
            echo "--- slowdown 矩阵 (行=程序, 列=共跑者, 值=共跑耗时/单独耗时) ---"
            printf "%-24s" ""
            for j in "${CMDS[@]}"; do
                printf "%-12s" "${j:0:11}"
            done
            echo ""
            for i in "${CMDS[@]}"; do
                printf "%-24s" "$i"
                for j in "${CMDS[@]}"; do
                    if [ "$i" = "$j" ]; then
                        printf "%-12s" "1.00"
                    else
                        printf "%-12s" "$(awk -v a="${PAIR_EL[$i|$j]}" -v b="${ST_EL[$i]}" \
                            'BEGIN{if (b+0>0) printf "%.2f", a/b; else print "N/A"}')"
                    fi
                done
                echo ""
            done
        fi

        # 4. 训练数据集 CSV
        {
            echo "mode,app,co_runner,FEstalls,BEstalls,DIcycles,total,elapsed_s"
            for c in "${CMDS[@]}"; do
                local cn=${c//,/,}
                cn=${cn//,/+}
                echo "st,${cn},,${ST_FE[$c]},${ST_BE[$c]},${ST_DI[$c]},${ST_TOT[$c]},${ST_EL[$c]}"
            done
            for ((i=0; i<n; i++)); do
                for ((j=i+1; j<n; j++)); do
                    local a=${CMDS[i]} b=${CMDS[j]}
                    a=${a//,/+}; b=${b//,/+}
                    local k1="${CMDS[i]}|${CMDS[j]}" k2="${CMDS[j]}|${CMDS[i]}"
                    echo "smt,${a},${b},${PAIR_FE[$k1]},${PAIR_BE[$k1]},${PAIR_DI[$k1]},${PAIR_TOT[$k1]},${PAIR_EL[$k1]}"
                    echo "smt,${b},${a},${PAIR_FE[$k2]},${PAIR_BE[$k2]},${PAIR_DI[$k2]},${PAIR_TOT[$k2]},${PAIR_EL[$k2]}"
                done
            done
        } > "$OUTCSV"
        echo ""
        echo "训练数据集已写入: $OUTCSV"
        echo "用法: ST 行提供 C_st 特征, smt 行提供 C_smt 目标值, 可直接拟合"
        echo "      C_smt(i,j) = a + b*C_st(i) + g*C_st(j) + r*C_st(i)*C_st(j)"
        ;;

    *)
        usage; echo "[错误] 未知模式: $MODE"; exit 1
        ;;
    esac
}

# 参数解析
while getopts "m:c:w:r:o:h" opt; do
    case $opt in
        m) MODE=$OPTARG ;;
        c) ANCHOR=$OPTARG ;;
        w) WIDTH=$OPTARG ;;
        r) REPEAT=$OPTARG ;;
        o) OUTCSV=$OPTARG ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND-1))
CMDS=("$@")

main
