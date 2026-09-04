#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# isc_pair.py — SYNPA 配对决策器
# 基于拟合系数, 输入两个程序的 ST 特征, 预测共跑干扰并判断是否适合配对
#
# 用法:
#   # 1. 直接输入数值
#   python3 isc_pair.py 0.0026 0.7711 0.2146  0.01 0.15 0.40
#                    (FE_A  BE_A   DI_A)   (FE_B  BE_B DI_B)
#
#   # 2. 从数据集 CSV 查已测程序
#   python3 isc_pair.py --csv isc_dataset_v1.csv "500.perlbench_r" "502.gcc_r"
#
#   # 3. 交互模式: 逐个输入程序特征
#   python3 isc_pair.py -i
#
#   # 4. 批量评估: 从 CSV 读全部程序, 输出最优配对方案
#   python3 isc_pair.py --csv isc_dataset_v1.csv --best
# ============================================================================

import sys
import re
import argparse

# ---- 拟合系数 (从 isc_fit.py 输出复制) ----
COEF = {
    "FE": (-0.001879, +0.358142, +0.114884, -0.210373),
    "BE": (+0.023460, +0.100824, +0.107437, +0.631714),
    "DI": (-0.087226, +0.849124, +0.137791, -0.338685),
}
CATS = ("FE", "BE", "DI")
CAT_NAMES = {"FE": "FEstalls", "BE": "BEstalls", "DI": "DIcycles"}


def predict(cat, ci, cj):
    a, b, g, r = COEF[cat]
    return a + b * ci + g * cj + r * ci * cj


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


# ---------------------------------------------------------------------------
# 短名提取: 从长命令串里取 benchmark 编号, 否则截断
# ---------------------------------------------------------------------------
SPEC_RE = re.compile(r'(\d{3}\.[\w_]+(?:_[\w_]+)?)')


def short_name(full):
    """从 runcpu 命令串里提取 benchmark 名 (如 500.perlbench_r)"""
    m = SPEC_RE.search(full)
    if m:
        return m.group(1)
    return full if len(full) <= 40 else full[:37] + "..."


# ---------------------------------------------------------------------------
# 核心评估
# ---------------------------------------------------------------------------
def evaluate(st_A, st_B, name_A="A", name_B="B"):
    """输入两组 ST 特征, 返回评估结果字典"""
    smt_A = {c: clamp(predict(c, st_A[c], st_B[c])) for c in CATS}
    smt_B = {c: clamp(predict(c, st_B[c], st_A[c])) for c in CATS}

    di_A_st = st_A["DI"]
    di_B_st = st_B["DI"]
    di_A_smt = smt_A["DI"]
    di_B_smt = smt_B["DI"]

    slow_A = di_A_st / di_A_smt if di_A_smt > 0.001 else 99.0
    slow_B = di_B_st / di_B_smt if di_B_smt > 0.001 else 99.0

    gain = (1.0 / slow_A + 1.0 / slow_B)

    inter = {}
    for c in CATS:
        _, _, _, r = COEF[c]
        inter[c] = r * st_A[c] * st_B[c]

    return {
        "smt_A": smt_A, "smt_B": smt_B,
        "slow_A": slow_A, "slow_B": slow_B,
        "gain": gain,
        "inter": inter,
    }


def verdict(gain):
    if gain >= 1.5:
        return "优秀配对", "SMT 增益显著, 强烈推荐共跑"
    elif gain >= 1.2:
        return "良好配对", "SMT 有正收益, 推荐共跑"
    elif gain >= 1.0:
        return "中性配对", "SMT 略有收益, 可共跑但非最优"
    else:
        return "不良配对", "SMT 反效果, 建议拆开跑"


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def print_report(st_A, st_B, name_A, name_B):
    r = evaluate(st_A, st_B, name_A, name_B)
    tag, desc = verdict(r["gain"])

    sA = short_name(name_A)
    sB = short_name(name_B)

    w = 66
    print("=" * w)
    print("配对评估:  %s  +  %s" % (sA, sB))
    print("=" * w)

    print("\n【输入 ST 特征】")
    print("  %-20s %8s %8s %8s %8s" % ("程序", "FEstall", "BEstall", "DIcyc", "Total"))
    print("  %-20s %8.4f %8.4f %8.4f %8.4f" % (sA, st_A["FE"], st_A["BE"], st_A["DI"],
          st_A["FE"] + st_A["BE"] + st_A["DI"]))
    print("  %-20s %8.4f %8.4f %8.4f %8.4f" % (sB, st_B["FE"], st_B["BE"], st_B["DI"],
          st_B["FE"] + st_B["BE"] + st_B["DI"]))

    print("\n【预测 SMT 栈】")
    print("  %-20s %8s %8s %8s %8s" % ("程序(共跑后)", "FEstall", "BEstall", "DIcyc", "Total"))
    s = r["smt_A"]
    print("  %-20s %8.4f %8.4f %8.4f %8.4f" % ("%s|%s" % (sA, sB),
          s["FE"], s["BE"], s["DI"], s["FE"] + s["BE"] + s["DI"]))
    s = r["smt_B"]
    print("  %-20s %8.4f %8.4f %8.4f %8.4f" % ("%s|%s" % (sB, sA),
          s["FE"], s["BE"], s["DI"], s["FE"] + s["BE"] + s["DI"]))

    print("\n【干扰分解】 r×Ci×Cj 项 (正=竞争放大, 负=互补填补)")
    for c in CATS:
        v = r["inter"][c]
        bar = "+" * int(abs(v) * 200) if v > 0 else "-" * int(abs(v) * 200)
        sign = "竞争" if v > 0 else "互补" if v < 0 else "中性"
        print("  %-9s %+8.4f  %s %s" % (CAT_NAMES[c], v, bar, sign))

    print("\n【性能预测】")
    print("  %-20s  slowdown = %5.2fx  (DI: %.4f -> %.4f)" %
          (sA, r["slow_A"], st_A["DI"], r["smt_A"]["DI"]))
    print("  %-20s  slowdown = %5.2fx  (DI: %.4f -> %.4f)" %
          (sB, r["slow_B"], st_B["DI"], r["smt_B"]["DI"]))
    print("  SMT 聚合吞吐增益 = %.2fx  (1.0=无增益, 2.0=理想)" % r["gain"])

    print("\n【结论】 %s — %s" % (tag, desc))
    print("=" * w)

    return r


# ---------------------------------------------------------------------------
# 从 CSV 读取 ST 特征
# ---------------------------------------------------------------------------
def load_st_from_csv(path):
    import csv
    st = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if (row.get("mode") or "").strip() != "st":
                continue
            app = (row.get("app") or "").strip()
            if not app:
                continue
            try:
                st[app] = {
                    "FE": float(row["FEstalls"]),
                    "BE": float(row["BEstalls"]),
                    "DI": float(row["DIcycles"]),
                }
            except (KeyError, ValueError):
                pass
    return st


def fuzzy_match(key, keys):
    """模糊匹配程序名"""
    if key in keys:
        return key
    key_l = key.lower()
    for k in keys:
        if key_l in k.lower():
            return k
    # 尝试数字匹配 (如 "500" 匹配 "500.perlbench_r")
    for k in keys:
        parts = k.split(".")
        if parts and parts[0] == key:
            return k
    return None


# ---------------------------------------------------------------------------
# 最优配对 (贪心, 非Blossom但够用)
# ---------------------------------------------------------------------------
def best_pairing(st):
    apps = list(st.keys())
    n = len(apps)
    if n < 2:
        print("至少需要 2 个程序")
        return

    # 计算所有对的增益
    pairs = []
    for i in range(n):
        for j in range(i + 1, n):
            r = evaluate(st[apps[i]], st[apps[j]])
            pairs.append((r["gain"], apps[i], apps[j], r))
    pairs.sort(key=lambda x: -x[0])

    # 贪心: 每次选剩余中增益最高的对
    used = set()
    result = []
    for gain, a, b, r in pairs:
        if a in used or b in used:
            continue
        used.add(a)
        used.add(b)
        result.append((a, b, gain, r))
    leftover = [a for a in apps if a not in used]

    # 自适应列宽: 按短名算最长
    short_names = {a: short_name(a) for a in st}
    # 参与配对的程序
    paired = []
    for a, b, _, _ in result:
        paired.append(short_names[a])
        paired.append(short_names[b])
    w = max((len(s) for s in paired), default=10)
    w = min(w, 40)  # 上限 40

    print("=" * 66)
    print("最优配对方案 (贪心, 按增益排序)")
    print("=" * 66)
    for a, b, gain, r in result:
        tag, _ = verdict(gain)
        print("  %-*s + %-*s  gain=%.2fx  %s" %
              (w, short_names[a], w, short_names[b], gain, tag))
    if leftover:
        print("  未配对(奇数): %s" % ", ".join(short_names[a] for a in leftover))

    avg = sum(p[2] for p in result) / len(result) if result else 0
    print("\n  平均增益: %.2fx  (%d 对)" % (avg, len(result)))
    print("=" * 66)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="SYNPA 配对决策器")
    ap.add_argument("fe_a", nargs="?", type=float, help="程序A FEstalls")
    ap.add_argument("be_a", nargs="?", type=float, help="程序A BEstalls")
    ap.add_argument("di_a", nargs="?", type=float, help="程序A DIcycles")
    ap.add_argument("fe_b", nargs="?", type=float, help="程序B FEstalls")
    ap.add_argument("be_b", nargs="?", type=float, help="程序B BEstalls")
    ap.add_argument("di_b", nargs="?", type=float, help="程序B DIcycles")
    ap.add_argument("--csv", help="从数据集 CSV 读取 ST 特征")
    ap.add_argument("--best", action="store_true", help="批量: 输出最优配对方案")
    ap.add_argument("-i", "--interactive", action="store_true", help="交互模式")
    args = ap.parse_args()

    # 无参数: 打印帮助和系数
    if not any([args.fe_a, args.csv, args.best, args.interactive]):
        ap.print_help()
        print("\n当前嵌入系数:")
        for c in CATS:
            a, b, g, r = COEF[c]
            print("  %-9s  a=%+.6f b=%+.6f g=%+.6f r=%+.6f" % (CAT_NAMES[c], a, b, g, r))
        return

    st_db = {}
    if args.csv:
        st_db = load_st_from_csv(args.csv)
        if not st_db:
            sys.exit("[错误] CSV 中未找到 ST 行")

    # 模式 3: 批量最优配对
    if args.best:
        if not st_db:
            sys.exit("[错误] --best 需要 --csv")
        best_pairing(st_db)
        return

    # 模式 2: 从 CSV 查两个程序
    if args.csv and len(sys.argv) >= 4:
        name_A = sys.argv[-2]
        name_B = sys.argv[-1]
        ka = fuzzy_match(name_A, st_db)
        kb = fuzzy_match(name_B, st_db)
        if not ka:
            sys.exit("[错误] 未找到程序: %s\n可用: %s" % (name_A, ", ".join(st_db)))
        if not kb:
            sys.exit("[错误] 未找到程序: %s\n可用: %s" % (name_B, ", ".join(st_db)))
        print_report(st_db[ka], st_db[kb], ka, kb)
        return

    # 模式 1: 直接输入数值
    if all(v is not None for v in [args.fe_a, args.be_a, args.di_a,
                                    args.fe_b, args.be_b, args.di_b]):
        st_A = {"FE": args.fe_a, "BE": args.be_a, "DI": args.di_a}
        st_B = {"FE": args.fe_b, "BE": args.be_b, "DI": args.di_b}
        print_report(st_A, st_B, "Program_A", "Program_B")
        return

    # 模式 4: 交互
    if args.interactive:
        if st_db:
            print("已知程序:")
            for full, s in sorted(st_db.items(), key=lambda x: short_name(x[0])):
                print("  %s  (FE=%.4f BE=%.4f DI=%.4f)" % (short_name(full), st_db[full]["FE"],
                      st_db[full]["BE"], st_db[full]["DI"]))
        print("\n输入格式: 名称 FE BE DI (空行结束)\n")
        progs = {}
        while True:
            line = input("程序 %d: " % (len(progs) + 1)).strip()
            if not line:
                break
            parts = line.split()
            if len(parts) != 4:
                print("  格式: 名称 FE BE DI")
                continue
            name = parts[0]
            try:
                progs[name] = {"FE": float(parts[1]), "BE": float(parts[2]), "DI": float(parts[3])}
            except ValueError:
                print("  数值格式错误")
        if len(progs) < 2:
            return
        names = list(progs.keys())
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                print_report(progs[names[i]], progs[names[j]], names[i], names[j])
                print()
        return

    ap.print_help()


if __name__ == "__main__":
    main()
